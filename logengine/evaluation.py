"""Compare les résultats du pipeline à ce que le générateur a injecté."""

REPAIRS = {
    "timestamp": ("ts_space", "ts_fr", "ts_epoch", "ts_offset"),
    "level": ("level_case", "level_alias"),
    "ip": ("ip_leading_zeros", "ip_brackets", "ip_mapped"),
    "protocol": ("proto_case",),
    "user": ("user_case", "user_null"),
    "json": ("json_single_quotes", "json_trailing_comma"),
    "control_chars": ("ansi", "control_chars"),
    "duplicate": ("duplicate",),
    "legacy_format": ("legacy_format",),
    "secret_masked": ("secret_in_log",),
}
REJECTS = {
    "structure": (
        "truncated", "corrupted_marker", "garbage", "missing_field",
    ),
    "ip": ("bad_ip",),
    "port": ("bad_port",),
    "timestamp": ("bad_timestamp",),
    "timestamp_range": ("out_of_range_timestamp",),
    "level": ("bad_level",),
    "json": ("truncated_json",),
    "service": ("bad_service",),
}


def compare_counts(observed: dict, expected: dict, injected: dict) -> dict:
    """Compare chaque compteur à la somme des défauts injectés."""
    result = {}
    for name, defects in expected.items():
        total = 0
        for defect in defects:
            total += injected.get(defect, 0)
        result[name] = {"injected": total, "observed": observed.get(name, 0)}
    return result


def score(detected: set, truth: set) -> dict:
    """Calcule la précision et le rappel."""
    hits = len(detected & truth)
    return {
        "expected": len(truth),
        "detected": len(detected),
        "true_positives": hits,
        "false_positives": len(detected - truth),
        "missed": len(truth - detected),
        "precision": round(hits / len(detected), 4) if detected else None,
        "recall": round(hits / len(truth), 4) if truth else None,
    }


def evaluate(quality: dict, entities: dict, manifest: dict) -> dict:
    """Évalue le nettoyage et la détection."""
    injected = manifest["injected"]
    truth = {name: set(v) for name, v in manifest["truth"].items()}
    funnel = quality["funnel"]

    fast = entities.get("bruteforce", set())
    slow = entities.get("slow", set()) - fast
    compromised = entities.get("bruteforce_success", set())
    compromised = compromised | entities.get("slow_success", set())
    detection = {
        "bruteforce_fast": score(fast, truth.get("bruteforce_fast", set())),
        "bruteforce_slow": score(slow, truth.get("bruteforce_slow", set())),
        "compromised": score(compromised, truth.get("compromised", set())),
    }
    rules = (
        ("password_spray", "password_spray"),
        ("port_scan", "port_scan"),
        ("web_attack", "web_attack"),
        ("exfiltration", "exfiltration"),
        ("impossible_travel", "impossible_travel"),
        ("blacklist", "blacklist_active"),
        ("rogue_config", "rogue_config"),
    )
    for rule, scenario in rules:
        detected = entities.get(rule, set())
        detection[rule] = score(detected, truth.get(scenario, set()))
    empty = injected.get("blank", 0) + injected.get("whitespace", 0)
    return {
        "lines_written": manifest["lines"],
        "lines_read": funnel.get("read", 0),
        "empty_lines": {
            "injected": empty,
            "observed": funnel.get("read", 0) - funnel.get("not_empty", 0),
        },
        "comments": {
            "injected": injected.get("comment", 0),
            "observed": funnel.get("not_empty", 0)
            - funnel.get("data_lines", 0),
        },
        "healthchecks": {
            "injected": injected.get("healthcheck", 0),
            "observed": funnel.get("valid", 0) - funnel.get("analysed", 0),
        },
        "repairs": compare_counts(quality["repairs"], REPAIRS, injected),
        "rejects": compare_counts(quality["rejects"], REJECTS, injected),
        "detection": detection,
    }
