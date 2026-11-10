"""Module 2 : nettoyage, normalisation et routage des enregistrements.

map() et filter() ne calculent rien à l'avance : ils produisent chaque
résultat quand la boucle finale le demande. Le flux reste donc en mémoire
ligne par ligne, du fichier jusqu'à l'analyse.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterator, TextIO

from logengine.config import (
    LEVEL_ALIASES,
    LEVELS,
    MAX_CACHE_SIZE,
    NULL_USERS,
    PROTOCOLS,
    SECRET_PATTERN,
)
from logengine.parsing import parse_line

OLDEST_DATE = datetime(2000, 1, 1)
NEWEST_DATE = datetime.now() + timedelta(days=1)
SENSITIVE_PORTS = (22, 23, 445, 3306, 3389)

# Cache des IP déjà validées : on évite de refaire le calcul à chaque ligne.
ip_cache = {}


def new_quality_counters() -> dict:
    """Crée les compteurs de qualité de données."""
    return {
        "funnel": defaultdict(int),
        "repairs": defaultdict(int),
        "rejects": defaultdict(int),
    }


def count_stage(items: Iterator, name: str, quality: dict) -> Iterator:
    """Laisse passer un flux en comptant ses éléments."""
    funnel = quality["funnel"]
    for item in items:
        funnel[name] += 1
        yield item


def sanitize_line(line: str, quality: dict) -> str:
    """Retire les espaces de bord, les couleurs et les caractères cachés."""
    text = line.strip()
    if text.isprintable():
        return text
    without_color = re.sub(r"\x1b\[\d*m", "", text)
    cleaned = ""
    for character in without_color:
        if character.isprintable() or character == "\t":
            cleaned += character
    if cleaned != text:
        quality["repairs"]["control_chars"] += 1
    return cleaned.strip()


def drop_duplicates(
    lines: Iterator, quality: dict, previous: str | None = None
) -> Iterator[str]:
    """Retire les lignes répétées juste à la suite."""
    for line in lines:
        if line == previous:
            quality["repairs"]["duplicate"] += 1
            continue
        previous = line
        yield line


def parse_timestamp(value: str, quality: dict) -> datetime | None:
    """Convertit un horodatage en date UTC, quel que soit son format."""
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1])
        if value.isdigit():
            moment = datetime.fromtimestamp(int(value), timezone.utc)
        elif "/" in value:
            moment = datetime.strptime(value, "%d/%m/%Y %H:%M:%S")
        else:
            moment = datetime.fromisoformat(value)
    except (ValueError, OverflowError, OSError):
        return None
    quality["repairs"]["timestamp"] += 1
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment


def clean_level(value: str, quality: dict) -> str | None:
    """Retourne le niveau standard, ou None s'il est inconnu."""
    if value in LEVELS:
        return value
    level = value.upper()
    level = LEVEL_ALIASES.get(level, level)
    if level not in LEVELS:
        return None
    quality["repairs"]["level"] += 1
    return level


def clean_ip(host: str) -> str | None:
    """Retourne une IPv4 au format standard, ou None si elle est invalide."""
    text = host.strip("[]")
    if text.startswith("::ffff:"):
        text = text[7:]
    parts = text.split(".")
    if len(parts) != 4:
        return None
    numbers = []
    for part in parts:
        if not part.isdigit() or int(part) > 255:
            return None
        numbers.append(str(int(part)))
    return ".".join(numbers)


def cached_clean_ip(host: str, quality: dict) -> str | None:
    """Valide une IP en réutilisant les résultats déjà connus."""
    if host not in ip_cache:
        if len(ip_cache) > MAX_CACHE_SIZE:
            ip_cache.clear()
        ip_cache[host] = clean_ip(host)
    ip = ip_cache[host]
    if ip is not None and ip != host:
        quality["repairs"]["ip"] += 1
    return ip


def clean_user(value: str, quality: dict) -> str | None:
    """Retourne l'utilisateur en minuscules, ou None s'il n'y en a pas."""
    if value == "-":
        return None
    user = value.lower().replace("user:", "")
    if user in NULL_USERS:
        quality["repairs"]["user"] += 1
        return None
    if user != value:
        quality["repairs"]["user"] += 1
    return user


def mask_secrets(record: dict, quality: dict) -> None:
    """Masque les mots de passe : ils n'ont rien à faire dans un rapport."""
    payload = record["payload"]
    if isinstance(payload, str):
        text = payload
    elif isinstance(payload, dict) and "path" in payload:
        text = payload["path"]
    else:
        return
    if "password=" not in text and "token=" not in text:
        return
    cleaned = re.sub(SECRET_PATTERN, r"\1=***", text)
    quality["repairs"]["secret_masked"] += 1
    record["text"] = None
    if isinstance(payload, str):
        record["payload"] = cleaned
    else:
        payload["path"] = cleaned


def normalize_record(record: dict, quality: dict) -> dict:
    """Valide et normalise les champs bruts d'un enregistrement."""
    if "reject" in record:
        return record

    moment = parse_timestamp(record["ts_raw"], quality)
    if moment is None:
        record["reject"] = "timestamp"
        return record
    if moment < OLDEST_DATE or moment > NEWEST_DATE:
        record["reject"] = "timestamp_range"
        return record

    level = clean_level(record["level_raw"], quality)
    if level is None:
        record["reject"] = "level"
        return record

    host, separator, tail = record["source_raw"].rpartition(":")
    ip = cached_clean_ip(host, quality) if separator else None
    if ip is None:
        record["reject"] = "ip"
        return record

    port, _, protocol = tail.partition("/")
    if not port.isdigit() or int(port) > 65535:
        record["reject"] = "port"
        return record

    if protocol not in PROTOCOLS:
        protocol = protocol.upper()
        if protocol not in PROTOCOLS:
            record["reject"] = "protocol"
            return record
        quality["repairs"]["protocol"] += 1

    service = record["service"]
    if service == "":
        record["reject"] = "service"
        return record

    mask_secrets(record, quality)
    record["timestamp"] = moment
    record["level"] = level
    record["ip"] = ip
    record["user"] = clean_user(record["user_raw"], quality)
    # Tuple : ces métadonnées ne doivent plus changer.
    record["meta"] = (ip, int(port), protocol)
    record["tag"] = f"{service}.{level.lower()}"
    return record


def keep_record(record: dict, quality: dict, bad_lines: TextIO) -> bool:
    """Écarte les lignes rejetées. Retourne True si la ligne est bonne."""
    reason = record.get("reject")
    if reason is None:
        return True
    quality["rejects"][reason] += 1
    # Une ligne rejetée peut contenir un secret : on le masque aussi ici.
    raw = re.sub(SECRET_PATTERN, r"\1=***", record.get("raw", ""))
    bad_lines.write(f"{reason}: {raw}\n")
    return False


def route_record(record: dict) -> dict:
    """Range un enregistrement selon la forme de son payload."""
    match record["payload"]:
        case str() as text if text.startswith("%"):
            route = "network_device"
        case str():
            route = "raw_text"
        case (_, port, _) if port in SENSITIVE_PORTS:
            route = "connection_sensitive"
        case (_, _, _):
            route = "connection"
        case {"path": "/health"}:
            route = "healthcheck"
        case {"level": "ERROR" | "CRITICAL", "code": int()}:
            route = "app_error"
        case {"status": status} if status >= 500:
            route = "http_5xx"
        case {"status": status} if status >= 400:
            route = "http_4xx"
        case {"status": _}:
            route = "http_ok"
        case {"event": "login_failed" | "login_success" | "logout"}:
            route = "auth_event"
        case {"threat": _}:
            route = "threat"
        case {"event": _, "target": _}:
            route = "user_action"
        case {"event": _}:
            route = "session_event"
        case {"cpu": _}:
            route = "machine_metric"
        case dict():
            route = "json_other"
        case _:
            route = "unknown"
    record["route"] = route
    return record


def build_record_stream(
    lines: Iterator,
    quality: dict,
    bad_lines: TextIO,
    previous: str | None = None,
) -> Iterator[dict]:
    """Assemble le pipeline. Rien n'est lu avant de parcourir le flux.

    previous est la ligne d'avant, quand le flux reprend en cours de route.
    """
    read = count_stage(lines, "read", quality)
    cleaned = map(lambda line: sanitize_line(line, quality), read)
    # filter(None, ...) retire les chaînes vides.
    not_empty = count_stage(filter(None, cleaned), "not_empty", quality)
    data_lines = count_stage(
        filter(lambda line: not line.startswith(("#", "-", "=")), not_empty),
        "data_lines",
        quality,
    )
    unique = drop_duplicates(data_lines, quality, previous)
    parsed = map(lambda line: parse_line(line, quality), unique)
    normalized = map(lambda rec: normalize_record(rec, quality), parsed)
    valid = count_stage(
        filter(lambda rec: keep_record(rec, quality, bad_lines), normalized),
        "valid",
        quality,
    )
    routed = map(route_record, valid)
    # Les sondes de supervision ne disent rien de l'activité réelle.
    useful = filter(lambda rec: rec["route"] != "healthcheck", routed)
    return count_stage(useful, "analysed", quality)
