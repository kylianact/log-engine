"""Module 4 : moteur de règles.

Une règle est une fonction rule(record, **kwargs) qui retourne une alerte
sous forme de dictionnaire, ou None. Les règles qui doivent se souvenir du
passé rangent leurs données dans kwargs["state"].
"""

from datetime import timedelta
from typing import Any, Callable

from logengine.config import (
    ALLOWED_IPS,
    EXFIL_BYTES,
    MAX_CACHE_SIZE,
    NETWORK_ADMINS,
    SCAN_PORTS,
    SCAN_WINDOW,
    SPRAY_USERS,
    SPRAY_WINDOW,
    TRAVEL_WINDOW,
    WEB_ATTACK_SIGNATURES,
)


def apply_security_rules(*args: Callable, **kwargs: Any) -> list:
    """Applique un nombre variable de règles à un lot d'enregistrements.

    args contient les fonctions de sécurité. kwargs contient records (le lot)
    et les paramètres de configuration, transmis tels quels à chaque règle.
    Une règle qui plante est comptée, et les autres continuent.
    """
    records = kwargs.pop("records")
    alerts = []
    for rule in args:
        for record in records:
            try:
                alert = rule(record, **kwargs)
            except (KeyError, TypeError, AttributeError, ValueError):
                kwargs["errors"][rule.__name__] += 1
                continue
            if alert is not None:
                alerts.append(alert)
    return alerts


def make_alert(rule: str, entity: str, record: dict, detail: str) -> dict:
    """Construit une alerte."""
    return {
        "rule": rule,
        "severity": "HIGH",
        "entity": entity,
        "timestamp": record["timestamp"],
        "detail": detail,
    }


def forget_old_entries(table: dict) -> None:
    """Vide un dictionnaire d'état devenu trop grand."""
    if len(table) > MAX_CACHE_SIZE:
        table.clear()


def rule_blacklist(record: dict, **kwargs: Any) -> dict | None:
    """Signale toute activité d'une IP de la liste noire."""
    if record["ip"] not in kwargs["blacklist"]:
        return None
    detail = f"activité {record['service']} d'une IP en liste noire"
    return make_alert("blacklist", record["ip"], record, detail)


def rule_web_attack(record: dict, **kwargs: Any) -> dict | None:
    """Cherche des injections SQL, du XSS et des traversées de chemin."""
    if record["service"] != "web" or isinstance(record["payload"], str):
        return None
    path = record["payload"].get("path", "").lower()
    for signature in WEB_ATTACK_SIGNATURES:
        if signature in path:
            detail = f"signature {signature} dans {path[:80]}"
            return make_alert("web_attack", record["ip"], record, detail)
    return None


def rule_exfiltration(record: dict, **kwargs: Any) -> dict | None:
    """Signale un transfert unique anormalement gros."""
    if record["service"] != "web" or isinstance(record["payload"], str):
        return None
    size = record["payload"].get("bytes", 0)
    if size < kwargs.get("exfil_bytes", EXFIL_BYTES):
        return None
    detail = f"{size // 1000000} Mo transférés d'un seul coup"
    return make_alert("exfiltration", record["ip"], record, detail)


def rule_critical_event(record: dict, **kwargs: Any) -> dict | None:
    """Remonte les événements critiques des systèmes et applications."""
    if record["level"] != "CRITICAL":
        return None
    detail = str(record["payload"])[:120]
    return make_alert("critical_event", record["service"], record, detail)


def rule_port_scan(record: dict, **kwargs: Any) -> dict | None:
    """Signale une IP qui touche beaucoup de ports en peu de temps."""
    if record["service"] != "firewall" or record["ip"] in ALLOWED_IPS:
        return None
    table = kwargs["state"]["port_scan"]
    ip = record["ip"]
    moment = record["timestamp"]
    window = timedelta(seconds=kwargs.get("scan_window", SCAN_WINDOW))
    started, ports = table.get(ip, (moment, set()))
    if moment - started > window:
        started, ports = moment, set()
    ports.add(record["payload"][1])
    table[ip] = (started, ports)
    forget_old_entries(table)
    if len(ports) < kwargs.get("scan_ports", SCAN_PORTS):
        return None
    table.pop(ip, None)
    detail = f"{len(ports)} ports visés en moins de {window}"
    return make_alert("port_scan", ip, record, detail)


def rule_password_spray(record: dict, **kwargs: Any) -> dict | None:
    """Signale une IP qui essaie beaucoup de comptes différents."""
    if record["service"] != "auth" or record["user"] is None:
        return None
    if record["payload"].get("event") != "login_failed":
        return None
    table = kwargs["state"]["spray"]
    ip = record["ip"]
    moment = record["timestamp"]
    window = timedelta(seconds=kwargs.get("spray_window", SPRAY_WINDOW))
    started, users = table.get(ip, (moment, set()))
    if moment - started > window:
        started, users = moment, set()
    users.add(record["user"])
    table[ip] = (started, users)
    forget_old_entries(table)
    if len(users) < kwargs.get("spray_users", SPRAY_USERS):
        return None
    table.pop(ip, None)
    detail = f"{len(users)} comptes visés depuis la même IP"
    return make_alert("password_spray", ip, record, detail)


def rule_impossible_travel(record: dict, **kwargs: Any) -> dict | None:
    """Signale un compte connecté depuis deux pays en très peu de temps."""
    if record["service"] != "vpn" or record["user"] is None:
        return None
    if record["payload"].get("event") != "vpn_connect":
        return None
    table = kwargs["state"]["travel"]
    user = record["user"]
    moment = record["timestamp"]
    country = record["payload"].get("country", "??")
    previous = table.get(user)
    table[user] = (moment, country)
    if previous is None or previous[1] == country:
        return None
    if moment - previous[0] > timedelta(seconds=TRAVEL_WINDOW):
        return None
    detail = f"connexions depuis {previous[1]} puis {country}"
    return make_alert("impossible_travel", user, record, detail)


def rule_rogue_config(record: dict, **kwargs: Any) -> dict | None:
    """Signale un routeur reconfiguré par un compte non autorisé."""
    if record["service"] != "router":
        return None
    if "%SYS-5-CONFIG_I" not in record["payload"]:
        return None
    if record["user"] in NETWORK_ADMINS:
        return None
    detail = f"routeur configuré par le compte {record['user']}"
    return make_alert("rogue_config", record["ip"], record, detail)


ALL_RULES = (
    rule_blacklist,
    rule_web_attack,
    rule_exfiltration,
    rule_critical_event,
    rule_port_scan,
    rule_password_spray,
    rule_impossible_travel,
    rule_rogue_config,
)
