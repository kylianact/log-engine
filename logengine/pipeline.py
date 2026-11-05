"""Orchestration du pipeline complet."""

import csv
import json
import os
import time
from collections import defaultdict
from typing import Iterator, TextIO

import psutil

from logengine import audit
from logengine.aggregation import Aggregator
from logengine.bruteforce import BruteForceDetector
from logengine.config import (
    ALERT_COOLDOWN,
    BATCH_SIZE,
    FAST_THRESHOLD,
    FAST_WINDOW,
    SLOW_THRESHOLD,
    SLOW_WINDOW,
)
from logengine.evaluation import evaluate
from logengine.ingestion import limit_lines, read_sources, total_size
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

    def __init__(self, file: TextIO) -> None:
        self.file = file
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
) -> dict:
    """Exécute le pipeline et retourne le résumé.

    lines permet de fournir un flux simulé à la place des fichiers.
    """
    os.makedirs(output, exist_ok=True)
    started = time.time()
    process = psutil.Process()
    quality = new_quality_counters()
    aggregator = Aggregator()
    fast = BruteForceDetector(FAST_THRESHOLD, FAST_WINDOW, "bruteforce")
    slow = BruteForceDetector(SLOW_THRESHOLD, SLOW_WINDOW, "slow")
    state = {"port_scan": {}, "spray": {}, "travel": {}}
    rule_errors = defaultdict(int)
    memory_trace = []
    peak_memory = 0
    batch_count = 0

    size = total_size(paths)
    if lines is None:
        lines = read_sources(paths)
    if max_lines > 0:
        lines = limit_lines(lines, max_lines)
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
            alert_log = AlertLog(alerts_file)
            records = build_record_stream(lines, quality, bad_lines)
            for batch in make_batches(records, BATCH_SIZE):
                batch_count += 1
                aggregator.update(batch)
                if sorter is not None:
                    sorter.write(batch)
                fast.run_cycle(batch, alert_log.publish)
                slow.run_cycle(batch, alert_log.publish)
                alerts = apply_security_rules(
                    *ALL_RULES,
                    records=batch,
                    blacklist=blacklist,
                    state=state,
                    errors=rule_errors,
                )
                alert_log.publish(alerts)
                if batch_count % 100 == 0:
                    memory = process.memory_info().rss / 1048576
                    peak_memory = max(peak_memory, memory)
                    memory_trace.append(
                        {
                            "lines": quality["funnel"]["read"],
                            "memory_mb": round(memory, 1),
                            "seconds": round(time.time() - started, 1),
                        }
                    )
                    print(
                        f"{quality['funnel']['read']} lignes lues, "
                        f"RAM {memory:.0f} Mo, "
                        f"{time.time() - started:.0f} s"
                    )
    if sorter is not None:
        sorter.close()

    # Sous Windows, une exécution très courte peut mesurer 0 seconde.
    seconds = max(time.time() - started, 0.001)
    memory = process.memory_info().rss / 1048576
    peak_memory = max(peak_memory, memory)
    read = quality["funnel"]["read"]
    quality_dict = {name: dict(v) for name, v in quality.items()}
    sorted_lines = dict(sorter.counts) if sorter is not None else {}
    summary = {
        "dataset": {"files": len(paths), "bytes": size},
        "performance": {
            "seconds": round(seconds, 1),
            "lines_per_second": round(read / seconds),
            "megabytes_per_second": round(size / 1000000 / seconds, 1),
            "batches": batch_count,
            "batch_size": BATCH_SIZE,
            "peak_memory_mb": round(peak_memory, 1),
            "memory_trace": memory_trace,
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

    manifest = load_manifest(paths, size)
    if manifest is not None and max_lines == 0:
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
