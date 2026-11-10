"""Orchestration du pipeline complet."""

import csv
import json
import os
import time
from collections import defaultdict
from typing import Iterator, TextIO

from logengine import audit
from logengine.aggregation import Aggregator
from logengine.bruteforce import BruteForceDetector
from logengine.config import (
    ALERT_COOLDOWN,
    BATCH_SIZE,
    FAST_THRESHOLD,
    FAST_WINDOW,
    REFRESH_SECONDS,
    SLOW_THRESHOLD,
    SLOW_WINDOW,
)
from logengine.display import LineDisplay, print_raw_lines, trace_stream
from logengine.evaluation import evaluate
from logengine.ingestion import limit_lines, read_sources, total_size
from logengine.monitor import LiveMonitor
from logengine.rules import ALL_RULES, apply_security_rules
from logengine.sorting import LogSorter
from logengine.transform import build_record_stream, new_quality_counters


def make_batches(records: Iterator, size: int) -> Iterator[list]:
    """Regroupe un flux en lots. Un seul lot est en mémoire à la fois."""
    batch = []
    for record in records:
        batch.append(record)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


class AlertLog:
    """Écrit les alertes dans un fichier et limite les répétitions.

    Une même règle ne se redéclenche pas sur la même entité pendant une
    heure : une IP bavarde donne une alerte par heure, pas un million.
    """

    def __init__(
        self, file: TextIO, display: LineDisplay | None = None
    ) -> None:
        self.file = file
        self.display = display
        self.last_seen = {}
        self.hits = defaultdict(int)
        self.published = defaultdict(int)
        self.entities = defaultdict(set)

    def publish(self, alerts: list) -> None:
        """Enregistre une liste d'alertes."""
        for alert in alerts:
            rule = alert["rule"]
            entity = alert["entity"]
            moment = alert["timestamp"]
            self.hits[rule] += 1
            self.entities[rule].add(entity)
            last = self.last_seen.get((rule, entity))
            if last is not None:
                if (moment - last).total_seconds() < ALERT_COOLDOWN:
                    continue
            self.last_seen[(rule, entity)] = moment
            self.published[rule] += 1
            alert["timestamp"] = moment.isoformat()
            self.file.write(json.dumps(alert, ensure_ascii=False) + "\n")
            if self.display is not None:
                self.display.alerts.append(alert)


def load_blacklist(path: str) -> frozenset:
    """Charge la liste noire dans un frozenset, qui ne peut plus changer."""
    try:
        with open(path, "r", encoding="utf-8") as file:
            lines = map(str.strip, file)
            return frozenset(filter(lambda ip: ip != "", lines))
    except OSError:
        print(f"Pas de liste noire : {path}")
        return frozenset()


def load_manifest(paths: list, size: int) -> dict | None:
    """Charge la vérité terrain, si elle correspond bien au fichier lu."""
    if len(paths) != 1:
        return None
    path = os.path.join(os.path.dirname(paths[0]), "manifest.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as file:
        manifest = json.load(file)
    return manifest if manifest["bytes"] == size else None


def write_hourly_summary(path: str, by_hour: dict) -> None:
    """Écrit la répartition horaire dans un CSV."""
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["hour", "lines"])
        for hour in sorted(by_hour):
            writer.writerow([hour, by_hour[hour]])


def run_pipeline(
    paths: list,
    output: str,
    lines: Iterator | None = None,
    blacklist_path: str | None = None,
    max_lines: int = 0,
    sort_logs: bool = True,
    display: LineDisplay | None = None,
    raw_every: int = 0,
    refresh: float = REFRESH_SECONDS,
) -> dict:
    """Exécute le pipeline et retourne le résumé.

    lines permet de fournir un flux simulé à la place des fichiers.
    display affiche chaque ligne : le traitement se fait alors ligne par
    ligne, ce qui convient à une démonstration mais pas aux 15 Go.
    raw_every affiche une ligne brute sur raw_every pendant l'analyse normale.
    refresh est le délai en secondes entre deux lignes du suivi en direct.
    """
    os.makedirs(output, exist_ok=True)
    started = time.time()
    quality = new_quality_counters()
    aggregator = Aggregator()
    fast = BruteForceDetector(FAST_THRESHOLD, FAST_WINDOW, "bruteforce")
    slow = BruteForceDetector(SLOW_THRESHOLD, SLOW_WINDOW, "slow")
    state = {"port_scan": {}, "spray": {}, "travel": {}}
    rule_errors = defaultdict(int)
    batch_count = 0

    size = total_size(paths)
    # Le manifeste du générateur donne le nombre total de lignes : le suivi
    # en direct peut alors afficher un pourcentage et le temps restant.
    manifest = load_manifest(paths, size)
    expected = manifest["lines"] if manifest is not None else 0
    if max_lines > 0 and (expected == 0 or max_lines < expected):
        expected = max_lines
    monitor = LiveMonitor(refresh, expected, display is None)
    if lines is None:
        lines = read_sources(paths)
    if max_lines > 0:
        lines = limit_lines(lines, max_lines)
    if raw_every > 0 and display is None:
        lines = print_raw_lines(lines, raw_every)
    if blacklist_path is None:
        folder = os.path.dirname(paths[0])
        blacklist_path = os.path.join(folder, "blacklist.conf")
    blacklist = load_blacklist(blacklist_path)

    sorter = None
    if sort_logs:
        sorter = LogSorter(os.path.join(output, "tri"))
    alerts_path = os.path.join(output, "alerts.jsonl")
    bad_path = os.path.join(output, "bad_lines.log")
    with open(alerts_path, "w", encoding="utf-8") as alerts_file:
        with open(bad_path, "w", encoding="utf-8") as bad_lines:
            alert_log = AlertLog(alerts_file, display)
            if display is None:
                batch_size = BATCH_SIZE
                records = build_record_stream(lines, quality, bad_lines)
            else:
                batch_size = 1
                records = trace_stream(lines, quality, bad_lines, display)
            for batch in make_batches(records, batch_size):
                batch_count += 1
                aggregator.update(batch)
                if sorter is not None:
                    sorter.write(batch)
                # La force brute ne concerne que les connexions.
                logins = [r for r in batch if r["service"] == "auth"]
                fast.run_cycle(logins, alert_log.publish)
                slow.run_cycle(logins, alert_log.publish)
                alerts = apply_security_rules(
                    *ALL_RULES,
                    records=batch,
                    blacklist=blacklist,
                    state=state,
                    errors=rule_errors,
                )
                alert_log.publish(alerts)
                # Une ligne de suivi par seconde : avancement et RAM.
                monitor.check(quality, alert_log.published)
    if sorter is not None:
        sorter.close()
    # Dernière mesure, à la fin du fichier.
    monitor.check(quality, alert_log.published, final=True)

    # Sous Windows, une exécution très courte peut mesurer 0 seconde.
    seconds = max(time.time() - started, 0.001)
    read = quality["funnel"].get("read", 0)
    quality_dict = {name: dict(v) for name, v in quality.items()}
    sorted_lines = dict(sorter.counts) if sorter is not None else {}
    summary = {
        "dataset": {"files": len(paths), "bytes": size},
        "performance": {
            "seconds": round(seconds, 1),
            "lines_per_second": round(read / seconds),
            "megabytes_per_second": round(size / 1000000 / seconds, 1),
            "batches": batch_count,
            "batch_size": batch_size,
            "peak_memory_mb": round(monitor.peak, 1),
            "memory_trace": monitor.trace,
        },
        "quality": quality_dict,
        "sorted_lines": dict(sorted(sorted_lines.items())),
        "aggregates": aggregator.to_dict(blacklist),
        "detection": {
            "hits": dict(alert_log.hits),
            "published": dict(alert_log.published),
            "rule_errors": dict(rule_errors),
            "completed_cycles": fast.completed_cycles,
            "interrupted_passes": fast.interrupted_passes,
        },
    }

    # La vérité terrain ne vaut que si tout le fichier a été lu.
    stopped = display is not None and display.finished()
    if manifest is not None and max_lines == 0 and not stopped:
        summary["evaluation"] = evaluate(
            quality_dict, alert_log.entities, manifest
        )

    with open(
        os.path.join(output, "summary.json"), "w", encoding="utf-8"
    ) as file:
        json.dump(summary, file, ensure_ascii=False, indent=2)
    write_hourly_summary(
        os.path.join(output, "hourly_summary.csv"), aggregator.by_hour
    )

    # globals() et locals() sont appelées ici pour décrire cette fonction.
    report = audit.build_audit("run_pipeline", globals(), locals())
    audit.export_audit(os.path.join(output, "audit.json"), report)
    return summary
