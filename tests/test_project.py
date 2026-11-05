"""Tests du projet. Lancement : python tests/test_project.py"""

import json
import os
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timedelta

sys.path.insert(0, os.getcwd())

import main as cli  # noqa: E402
from logengine import audit  # noqa: E402
from logengine.aggregation import compare_with_blacklist  # noqa: E402
from logengine.bruteforce import BruteForceDetector  # noqa: E402
from logengine.generator import generate_dataset  # noqa: E402
from logengine.ingestion import limit_lines, read_log_file  # noqa: E402
from logengine.ingestion import read_sources  # noqa: E402
from logengine.parsing import parse_line  # noqa: E402
from logengine.pipeline import make_batches, run_pipeline  # noqa: E402
from logengine.rules import apply_security_rules  # noqa: E402
from logengine.rules import rule_blacklist, rule_port_scan  # noqa: E402
from logengine.rules import rule_rogue_config  # noqa: E402
from logengine.sorting import LogSorter, format_record  # noqa: E402
from logengine.transform import (  # noqa: E402
    new_quality_counters,
    normalize_record,
    route_record,
    sanitize_line,
)

WORK = os.path.join("output", "tests")
CLEAN_LINE = (
    '2026-10-01T08:00:00.000Z | ERROR | 10.1.2.3:5000/TCP | u00001 | app | '
    '{"level":"ERROR","code":503}'
)


def clean(line: str) -> dict:
    """Passe une ligne dans le nettoyage complet."""
    quality = new_quality_counters()
    record = parse_line(sanitize_line(line, quality), quality)
    return normalize_record(record, quality)


def auth_record(ip: str, user: str, event: str, second: int) -> dict:
    """Crée un événement d'authentification."""
    return {
        "service": "auth",
        "ip": ip,
        "user": user,
        "timestamp": datetime(2026, 10, 1) + timedelta(seconds=second),
        "payload": {"event": event},
    }


def test_reading_is_lazy() -> None:
    lines = read_log_file("tests/server_logs_extract.txt")
    assert type(lines).__name__ == "generator"
    assert next(lines).startswith("2025-11-01")
    lines.close()


def test_read_several_sources() -> None:
    path = "tests/server_logs_extract.txt"
    lines = list(read_sources([path, "fichier_absent.log", path]))
    assert len(lines) == 12


def test_invalid_bytes_do_not_stop_reading() -> None:
    os.makedirs(WORK, exist_ok=True)
    path = os.path.join(WORK, "binaire.log")
    with open(path, "wb") as file:
        file.write(b"ligne\xff\xfe abimee\nligne suivante\n")
    assert len(list(read_log_file(path))) == 2


def test_parse_three_payload_forms() -> None:
    assert clean(CLEAN_LINE)["payload"]["code"] == 503
    head = "2026-10-01T08:00:00.000Z | INFO | 10.1.2.3:53/UDP | - | "
    assert clean(head + "system | disque plein")["payload"] == "disque plein"
    record = clean(head + "firewall | conn=(1.2.3.4,443,TCP) action=DENY")
    assert record["payload"] == ("1.2.3.4", 443, "TCP")
    assert record["extra"]["action"] == "DENY"
    assert record["meta"] == ("10.1.2.3", 53, "UDP")


def test_course_log_format() -> None:
    summary = run_pipeline(
        ["tests/server_logs_extract.txt"], os.path.join(WORK, "tp6")
    )
    assert summary["quality"]["funnel"]["analysed"] == 5
    assert summary["quality"]["rejects"]["structure"] == 1
    assert summary["quality"]["repairs"]["legacy_format"] == 5


def test_dirty_variants_give_the_same_result() -> None:
    expected = clean(CLEAN_LINE)
    variants = [
        CLEAN_LINE.replace("ERROR |", "err |", 1),
        CLEAN_LINE.replace("ERROR |", "\x1b[31mERROR\x1b[0m |", 1),
        CLEAN_LINE.replace("10.1.2.3", "010.001.002.003"),
        CLEAN_LINE.replace("10.1.2.3", "[10.1.2.3]"),
        CLEAN_LINE.replace("10.1.2.3", "::ffff:10.1.2.3"),
        CLEAN_LINE.replace("/TCP", "/tcp"),
        CLEAN_LINE.replace("u00001", "USER:u00001"),
        CLEAN_LINE.replace("2026-10-01T08:00:00.000Z",
                           "01/10/2026 08:00:00"),
        CLEAN_LINE.replace("2026-10-01T08:00:00.000Z", "1790841600"),
        CLEAN_LINE.replace("2026-10-01T08:00:00.000Z",
                           "2026-10-01T10:00:00.000+02:00"),
        CLEAN_LINE.replace('503}', '503,}'),
        CLEAN_LINE.replace('"', "'"),
        "﻿   " + CLEAN_LINE + "  \t",
    ]
    for line in variants:
        record = clean(line)
        assert "reject" not in record, line
        for field in ("timestamp", "level", "ip", "meta", "user", "payload"):
            assert record[field] == expected[field], (line, field)


def test_invalid_lines_are_rejected() -> None:
    bad = {
        "timestamp": CLEAN_LINE.replace("2026-10-01", "2026-13-45"),
        "timestamp_range": CLEAN_LINE.replace("2026-10-01", "1970-01-01"),
        "level": CLEAN_LINE.replace("ERROR |", "BANANA |", 1),
        "ip": CLEAN_LINE.replace("10.1.2.3", "999.1.2.3"),
        "port": CLEAN_LINE.replace(":5000", ":70000"),
        "json": CLEAN_LINE.replace('{"level"', '{"lev'),
        "structure": "CORRUPTED_LINE_WITHOUT_FORMAT",
    }
    for reason, line in bad.items():
        assert clean(line)["reject"] == reason, line


def test_secrets_are_masked() -> None:
    head = "2026-10-01T08:00:00.000Z | WARNING | 10.1.2.3:53/UDP | - | app | "
    record = clean(head + "erreur SMTP password=hunter2")
    assert "hunter2" not in record["payload"]


def test_routing() -> None:
    cases = [
        ({"level": "ERROR", "code": 503}, "app_error"),
        ({"path": "/health", "status": 200}, "healthcheck"),
        ({"status": 503}, "http_5xx"),
        ({"status": 404}, "http_4xx"),
        ({"status": 200}, "http_ok"),
        ({"event": "login_failed"}, "auth_event"),
        ({"event": "dns_query"}, "session_event"),
        ({"event": "sudo", "target": "x"}, "user_action"),
        ({"event": "threat_found", "threat": "x"}, "threat"),
        ({"host": "pc", "cpu": 12}, "machine_metric"),
        ({"autre": 1}, "json_other"),
        (("1.2.3.4", 22, "TCP"), "connection_sensitive"),
        (("1.2.3.4", 443, "TCP"), "connection"),
        ("%LINK-3-UPDOWN: Interface Gi0/1", "network_device"),
        ("message brut", "raw_text"),
        (42, "unknown"),
    ]
    for payload, route in cases:
        assert route_record({"payload": payload})["route"] == route


def test_set_operations() -> None:
    result = compare_with_blacklist(
        {"a", "b", "c"}, {"a"}, frozenset({"c", "d"})
    )
    assert result["union"] == 4
    assert result["intersection"] == 1
    assert result["difference"] == 2
    assert result["symmetric_difference"] == 3


def test_limit_lines_stops_reading() -> None:
    lines = iter(["a", "b", "c", "d"])
    assert list(limit_lines(lines, 2)) == ["a", "b"]
    assert next(lines) == "c"


def test_sorted_line_is_clean() -> None:
    dirty = (
        "\x1b[31m  01/10/2026 08:00:00 | err | 010.001.002.003:22/tcp | "
        "USER:u00001 | AUTH | {'event':'login_failed','code':401}"
    )
    expected = (
        "2026-10-01T08:00:00.000Z | ERROR | 10.1.2.3:22/TCP | u00001 | "
        'auth | {"event":"login_failed","code":401}'
    )
    assert format_record(clean(dirty)) == expected


def test_sorted_connection_keeps_its_details() -> None:
    line = (
        "2026-10-01T08:00:00.000Z | INFO | 10.1.2.3:53/UDP | - | firewall "
        "| conn=(1.2.3.4,443,TCP) action=DENY bytes=60"
    )
    assert format_record(clean(line)) == line


def test_unknown_service_cannot_choose_a_path() -> None:
    folder = os.path.join(WORK, "tri_piege")
    shutil.rmtree(folder, ignore_errors=True)
    record = clean(CLEAN_LINE.replace("| app |", "| ../../piege |"))
    sorter = LogSorter(folder)
    sorter.write([record])
    sorter.close()
    assert os.listdir(folder) == ["other.log"]


def test_batches_keep_every_record() -> None:
    batches = list(make_batches(range(25), 10))
    assert [len(batch) for batch in batches] == [10, 10, 5]


def test_bruteforce_threshold() -> None:
    detector = BruteForceDetector(6, 120, "bruteforce")
    alerts = []
    below = [auth_record("1.1.1.1", "root", "login_failed", i)
             for i in range(5)]
    detector.run_cycle(below, alerts.extend)
    assert alerts == []
    detector.run_cycle([auth_record("1.1.1.1", "root", "login_failed", 6)],
                       alerts.extend)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "bruteforce"


def test_bruteforce_success_resets_and_reveals() -> None:
    detector = BruteForceDetector(3, 120, "bruteforce")
    alerts = []
    batch = [
        auth_record("1.1.1.1", "bob", "login_failed", 1),
        auth_record("1.1.1.1", "bob", "login_failed", 2),
        auth_record("1.1.1.1", "bob", "login_success", 3),
        auth_record("1.1.1.1", "bob", "login_failed", 4),
    ]
    detector.run_cycle(batch, alerts.extend)
    assert alerts == []
    batch = [auth_record("2.2.2.2", "root", "login_failed", i)
             for i in range(3)]
    batch.append(auth_record("2.2.2.2", "root", "login_success", 4))
    detector.run_cycle(batch, alerts.extend)
    assert [alert["rule"] for alert in alerts] == [
        "bruteforce", "bruteforce_success",
    ]


def test_bruteforce_window() -> None:
    detector = BruteForceDetector(3, 10, "bruteforce")
    alerts = []
    batch = [auth_record("1.1.1.1", "bob", "login_failed", i * 60)
             for i in range(10)]
    detector.run_cycle(batch, alerts.extend)
    assert alerts == []


def test_cycle_else_and_break() -> None:
    detector = BruteForceDetector(2, 120, "bruteforce")
    # 1200 comptes attaqués dans un lot : plus que la limite de 500 alertes.
    batch = []
    for number in range(1200):
        for second in (0, 1):
            batch.append(
                auth_record("1.1.1.1", f"u{number}", "login_failed", second)
            )
    alerts = []
    detector.run_cycle(batch, alerts.extend)
    assert len(alerts) == 1200
    assert detector.interrupted_passes == 2
    assert detector.completed_cycles == 1


def broken_rule(record: dict, **kwargs) -> None:
    raise KeyError("champ absent")


def test_rule_engine() -> None:
    record = {"ip": "6.6.6.6", "service": "web", "payload": {},
              "timestamp": datetime(2026, 10, 1)}
    errors = defaultdict(int)
    alerts = apply_security_rules(
        broken_rule, rule_blacklist, records=[record],
        blacklist=frozenset({"6.6.6.6"}), errors=errors,
    )
    assert len(alerts) == 1
    assert errors["broken_rule"] == 1


def test_rule_configuration_by_kwargs() -> None:
    state = {"port_scan": {}}
    records = []
    for port in range(3):
        records.append(
            {
                "ip": "6.6.6.6",
                "service": "firewall",
                "payload": ("10.0.0.1", port, "TCP"),
                "timestamp": datetime(2026, 10, 1),
            }
        )
    alerts = apply_security_rules(
        rule_port_scan, records=records, state=state, errors={}, scan_ports=3
    )
    assert len(alerts) == 1


def test_rogue_router_configuration() -> None:
    record = {
        "service": "router",
        "ip": "45.70.1.2",
        "user": "cisco",
        "payload": "%SYS-5-CONFIG_I: Configured from vty0 by cisco",
        "timestamp": datetime(2026, 10, 1),
    }
    assert rule_rogue_config(record)["entity"] == "45.70.1.2"
    record["user"] = "netadmin1"
    assert rule_rogue_config(record) is None


def test_audit_does_not_consume_generators() -> None:
    def numbers():
        yield 1
        yield 2

    generator = numbers()
    password = "secret"
    report = audit.build_audit("test", globals(), locals())
    assert report["locals"]["password"]["preview"] == "***"
    assert report["locals"]["generator"]["type"] == "generator"
    assert next(generator) == 1


def test_command_line_options() -> None:
    options = cli.parse_options(
        ["--log-file=a.log", "--log-file=b.log", "--output=x", "--no-sort"]
    )
    assert options["log-file"] == ["a.log", "b.log"]
    assert options["output"] == "x"
    assert "no-sort" in options
    assert cli.parse_options(["--inconnue=1"]) is None
    assert cli.parse_options(["a.log"]) is None


def test_command_line_missing_file() -> None:
    assert cli.main(["--log-file=fichier_absent.log"]) == 1


def test_command_line_runs_and_sorts() -> None:
    folder = os.path.join(WORK, "dataset_cli")
    shutil.rmtree(folder, ignore_errors=True)
    path = os.path.join(folder, "logs.log")
    output = os.path.join(WORK, "run_cli")
    assert cli.main(
        [f"--generate={path}", "--size-gb=0.003", "--days=1", "--seed=5"]
    ) == 0
    assert cli.main([f"--log-file={path}", f"--output={output}"]) == 0
    with open(os.path.join(output, "summary.json"), encoding="utf-8") as file:
        summary = json.load(file)
    total = sum(summary["sorted_lines"].values())
    assert total == summary["quality"]["funnel"]["analysed"]
    written = 0
    for name in os.listdir(os.path.join(output, "tri")):
        service = name.replace(".log", "")
        tri_path = os.path.join(output, "tri", name)
        with open(tri_path, "r", encoding="utf-8") as file:
            for line in file:
                written += 1
                assert line.split(" | ")[4] == service
    assert written == total


def test_empty_file() -> None:
    os.makedirs(WORK, exist_ok=True)
    path = os.path.join(WORK, "vide.log")
    with open(path, "w", encoding="utf-8"):
        pass
    summary = run_pipeline([path], os.path.join(WORK, "run_vide"))
    assert summary["quality"]["funnel"].get("read", 0) == 0


def test_full_pipeline_matches_generator() -> None:
    path = os.path.join(WORK, "dataset", "logs.log")
    shutil.rmtree(os.path.dirname(path), ignore_errors=True)
    generate_dataset(path, 6000000, days=2, seed=3)
    summary = run_pipeline([path], os.path.join(WORK, "run"))
    evaluation = summary["evaluation"]
    assert evaluation["lines_written"] == evaluation["lines_read"]
    assert evaluation["empty_lines"]["injected"] > 0
    for name in ("empty_lines", "comments", "healthchecks"):
        assert evaluation[name]["injected"] == evaluation[name]["observed"]
    for group in ("repairs", "rejects"):
        for name, values in evaluation[group].items():
            assert values["injected"] == values["observed"], name
    assert summary["detection"]["rule_errors"] == {}
    for result in evaluation["detection"].values():
        assert result["recall"] == 1.0
    written = os.path.join(WORK, "run", "summary.json")
    with open(written, "r", encoding="utf-8") as file:
        assert json.load(file)["evaluation"] == evaluation


def main() -> None:
    """Lance toutes les fonctions dont le nom commence par test_."""
    failures = 0
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for test in tests:
        try:
            test()
            print(f"ok      {test.__name__}")
        except AssertionError as error:
            failures += 1
            print(f"ÉCHEC   {test.__name__} : {error}")
    print(f"\n{len(tests) - failures}/{len(tests)} tests réussis")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
