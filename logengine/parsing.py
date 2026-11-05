"""Module 1 : transformation d'une ligne de texte en dictionnaire.

Format d'une ligne :
    horodatage | niveau | ip:port/proto | utilisateur | service | payload

Le payload a trois formes : JSON, texte brut ou tuple de connexion
conn=(ip,port,proto). L'ancien format du TP6 reste aussi accepté :
    2025-10-29T13:45:22Z 192.168.1.12 "GET /index.html" 200 1024
"""

import json

from logengine.config import FIELD_COUNT


def parse_json_payload(text: str, quality: dict) -> dict | None:
    """Lit un payload JSON, et tente de le réparer s'il est abîmé."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    # Deux défauts réparables : virgule en trop, guillemets simples.
    for repaired in (text.replace(",}", "}"), text.replace("'", '"')):
        try:
            payload = json.loads(repaired)
        except ValueError:
            continue
        quality["repairs"]["json"] += 1
        return payload
    return None


def parse_connection(text: str) -> tuple | None:
    """Lit conn=(ip,port,proto) action=DENY bytes=60."""
    head, separator, tail = text.partition(")")
    fields = head.replace("conn=(", "").split(",")
    if not separator or len(fields) != 3 or not fields[1].isdigit():
        return None
    connection = (fields[0], int(fields[1]), fields[2])
    extra = {}
    for word in tail.split():
        key, _, value = word.partition("=")
        extra[key] = value
    return connection, extra


def parse_legacy_line(line: str, quality: dict) -> dict:
    """Lit une ligne de l'ancien format du TP6."""
    parts = line.split(" ")
    if (
        len(parts) != 6
        or not parts[2].startswith('"')
        or not parts[4].isdigit()
        or not parts[5].isdigit()
    ):
        return {"reject": "structure", "raw": line}
    status = int(parts[4])
    if status >= 500:
        level = "ERROR"
    elif status >= 400:
        level = "WARNING"
    else:
        level = "INFO"
    quality["repairs"]["legacy_format"] += 1
    return {
        "ts_raw": parts[0],
        "level_raw": level,
        "source_raw": f"{parts[1]}:0/TCP",
        "user_raw": "-",
        "service": "web",
        "payload": {
            "method": parts[2].strip('"'),
            "path": parts[3].strip('"'),
            "status": status,
            "bytes": int(parts[5]),
        },
    }


def parse_line(line: str, quality: dict) -> dict:
    """Transforme une ligne en dictionnaire de champs bruts."""
    parts = line.split("|", FIELD_COUNT - 1)
    if len(parts) != FIELD_COUNT:
        return parse_legacy_line(line, quality)

    record: dict = {
        "ts_raw": parts[0].strip(),
        "level_raw": parts[1].strip(),
        "source_raw": parts[2].strip(),
        "user_raw": parts[3].strip(),
        "service": parts[4].strip().lower(),
        "raw": line,
    }
    text = parts[5].strip()
    if text.startswith("{"):
        record["payload"] = parse_json_payload(text, quality)
        if record["payload"] is None:
            record["reject"] = "json"
    elif text.startswith("conn=("):
        connection = parse_connection(text)
        if connection is None:
            record["reject"] = "payload"
        else:
            record["payload"], record["extra"] = connection
    else:
        record["payload"] = text
    return record
