"""Générateur de logs synthétiques, volontairement sales et variés.

Tous les logs sont écrits dans un seul fichier, dans l'ordre du temps : 16
types de sources y sont mélangés. Le générateur injecte aussi des attaques et
des défauts de qualité. Il compte tout dans manifest.json : on sait donc
exactement ce que le pipeline doit retrouver.

La même graine donne toujours le même fichier.
"""

import json
import os
import random
import time
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Iterator

# Part du volume total pour chaque type de log.
SERVICES = {
    "web": 0.22,
    "firewall": 0.16,
    "dns": 0.09,
    "auth": 0.08,
    "router": 0.07,
    "action": 0.06,
    "switch": 0.05,
    "app": 0.05,
    "wifi": 0.04,
    "database": 0.04,
    "dhcp": 0.03,
    "vpn": 0.03,
    "mail": 0.03,
    "machine": 0.02,
    "system": 0.02,
    "antivirus": 0.01,
}
OFFICE_SERVICES = (
    "web", "auth", "vpn", "app", "action", "wifi", "dns", "dhcp", "mail",
)
FIRST_DAY = date(2026, 10, 1)

# Activité relative de chaque heure de la journée.
OFFICE_HOURS = [
    0.15, 0.1, 0.08, 0.08, 0.1, 0.2, 0.5, 1.2, 2.2, 2.6, 2.5, 2.1,
    1.8, 2.3, 2.6, 2.4, 2.1, 1.6, 1.0, 0.7, 0.5, 0.4, 0.3, 0.2,
]
FLAT_HOURS = [
    0.8, 0.8, 0.7, 0.7, 0.7, 0.8, 0.9, 1.0, 1.2, 1.3, 1.3, 1.2,
    1.2, 1.3, 1.3, 1.3, 1.2, 1.1, 1.0, 1.0, 0.9, 0.9, 0.9, 0.8,
]

# Nombre d'attaques planifiées chaque jour.
CAMPAIGNS = {
    "bruteforce_fast": 6,
    "bruteforce_slow": 2,
    "benign_lockout": 2,
    "password_spray": 3,
    "port_scan": 5,
    "web_attack": 8,
    "exfiltration": 2,
    "impossible_travel": 3,
    "rogue_config": 2,
}

# Part des lignes abîmées, et poids de chaque défaut.
DEFECT_RATE = 0.09
REPAIRABLE_DEFECTS = {
    "level_case": 10, "level_alias": 8, "ts_space": 6, "ts_fr": 4,
    "ts_epoch": 3, "ts_offset": 5, "ip_leading_zeros": 5, "ip_brackets": 4,
    "ip_mapped": 3, "proto_case": 6, "user_case": 8, "user_null": 3,
    "spacing": 12, "ansi": 4, "control_chars": 4, "json_single_quotes": 5,
    "json_trailing_comma": 5, "duplicate": 5,
}
NOISE_DEFECTS = {"blank": 5, "whitespace": 2, "comment": 3}
INVALID_DEFECTS = {
    "truncated": 5, "corrupted_marker": 3, "garbage": 2, "missing_field": 4,
    "bad_ip": 4, "bad_port": 3, "bad_timestamp": 4,
    "out_of_range_timestamp": 2, "bad_level": 2, "truncated_json": 4,
    "bad_service": 1,
}

WEB_PATHS = {
    "/": 12, "/index.html": 10, "/login": 8, "/logout": 3, "/dashboard": 8,
    "/api/v1/items": 10, "/api/v1/items/ID": 12, "/api/v1/orders/ID": 7,
    "/api/v1/users/ID": 5, "/search?q=vpn": 3, "/images/logo.png": 9,
    "/static/app.js": 7, "/download/file.zip": 3, "/admin": 1,
    "/robots.txt": 2,
}
HTTP_STATUS = {
    200: 720, 201: 40, 204: 20, 301: 30, 304: 60, 400: 30, 401: 20,
    403: 20, 404: 40, 500: 10, 502: 6, 503: 4,
}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0",
    "Mozilla/5.0 (Macintosh) Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0",
    "Mozilla/5.0 (iPhone) Mobile/15E148",
    "python-requests/2.32",
    "curl/8.9.1",
]
APP_MODULES = ["billing", "catalog", "orders", "payments", "search"]
APP_MESSAGES = [
    ("INFO", "commande validée en {} ms"),
    ("INFO", "cache rechargé : {} entrées"),
    ("INFO", "tâche planifiée terminée en {} s"),
    ("DEBUG", "requête SQL exécutée en {} ms"),
    ("DEBUG", "connexion au pool obtenue, {} libres"),
    ("WARNING", "temps de réponse dégradé : {} ms"),
    ("WARNING", "file de messages chargée à {} %"),
]
APP_ERRORS = [
    (500, "Exception non gérée"),
    (503, "Service amont indisponible"),
    (504, "Délai dépassé"),
    (422, "Données incohérentes"),
    (409, "Conflit de version"),
]

# Messages en texte brut : (niveau, modèle) et poids. {0} reçoit un nombre.
RAW_MESSAGES = {
    "router": {
        ("INFO", "%LINEPROTO-5-UPDOWN: Line protocol on Interface "
                 "GigabitEthernet0/{0}, changed state to up"): 30,
        ("INFO", "%BGP-5-ADJCHANGE: neighbor 192.0.2.{0} Up"): 20,
        ("INFO", "%OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.{0} on Gi0/1 "
                 "from LOADING to FULL"): 20,
        ("INFO", "%SYS-6-CLOCKUPDATE: System clock updated"): 10,
        ("WARNING", "%SEC-6-IPACCESSLOGP: list 101 denied tcp "
                    "198.51.100.{0}(4444) -> 10.0.0.1(22), 1 packet"): 15,
        ("WARNING", "%OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.{0} on Gi0/1 "
                    "from FULL to DOWN"): 3,
        ("ERROR", "%LINK-3-UPDOWN: Interface GigabitEthernet0/{0}, "
                  "changed state to down"): 2,
    },
    "switch": {
        ("INFO", "%SPANTREE-5-TOPOTRAP: Topology change on VLAN {0}"): 30,
        ("INFO", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/{0}, "
                 "changed state to up"): 35,
        ("INFO", "%DTP-5-TRUNKPORTON: Port Gi1/0/{0} has become trunk"): 20,
        ("WARNING", "%SW_MATM-4-MACFLAP_NOTIF: Host 0011.22{0:02x}.3344 "
                    "in vlan 10 is flapping"): 8,
        ("WARNING", "%PORT_SECURITY-2-PSECURE_VIOLATION: Security "
                    "violation on port Gi1/0/{0}"): 5,
        ("ERROR", "%ILPOWER-3-CONTROLLER_PORT_ERR: Controller port error "
                  "on Gi1/0/{0}"): 2,
    },
    "wifi": {
        ("INFO", "AP-B2-{0}: client f4:5c:89:00:00:{0:02x} associé, "
                 "RSSI -{0} dBm"): 45,
        ("INFO", "AP-B2-{0}: client f4:5c:89:00:00:{0:02x} déconnecté"): 40,
        ("WARNING", "AP-B2-{0}: signal faible, RSSI -{0} dBm"): 12,
        ("ERROR", "AP-B2-{0}: échec d'authentification 802.1X"): 3,
    },
    "dhcp": {
        ("INFO", "DHCPDISCOVER from f4:5c:89:00:00:{0:02x} via eth0"): 30,
        ("INFO", "DHCPOFFER on 10.20.0.{0} via eth0"): 30,
        ("INFO", "DHCPACK on 10.20.0.{0} to f4:5c:89:00:00:{0:02x}"): 35,
        ("WARNING", "DHCPNAK on 10.20.0.{0}: adresse déjà prise"): 4,
        ("ERROR", "no free leases on subnet 10.20.{0}.0/24"): 1,
    },
    "mail": {
        ("INFO", "postfix/smtpd: connect from mail-{0}.example.org"): 40,
        ("INFO", "postfix/smtp: status=sent, delay={0}s"): 40,
        ("INFO", "postfix/qmgr: {0} messages en attente"): 10,
        ("WARNING", "spamd: message refusé, score {0}"): 7,
        ("ERROR", "postfix/smtp: status=bounced, code 550"): 3,
    },
    "database": {
        ("INFO", "postgres: checkpoint terminé, {0} tampons écrits"): 45,
        ("INFO", "postgres: connexion acceptée, base shop"): 35,
        ("WARNING", "postgres: requête lente, {0}00 ms sur orders"): 15,
        ("ERROR", "postgres: deadlock détecté sur la table orders"): 3,
        ("ERROR", "postgres: connexion refusée, {0} clients actifs"): 2,
    },
    "system": {
        ("INFO", "systemd: nginx.service redémarré"): 25,
        ("INFO", "cron: sauvegarde quotidienne lancée"): 25,
        ("INFO", "ntpd: horloge synchronisée, écart {0} ms"): 25,
        ("WARNING", "disque /var rempli à {0} %"): 12,
        ("WARNING", "température CPU élevée : {0} C"): 10,
        ("ERROR", "kernel: erreur E/S sur sda, secteur {0}"): 3,
    },
}
CRITICAL_MESSAGES = {
    "router": "%SYS-2-MALLOCFAIL: Memory allocation failed",
    "database": "postgres: arrêt d'urgence, espace disque épuisé",
    "system": "kernel: OOM killer a arrêté le processus {0}",
}
# Adresse de chaque équipement : début de l'IP et fin de la source.
RAW_SOURCES = {
    "router": ("10.255", "514/UDP"),
    "switch": ("10.254", "514/UDP"),
    "wifi": ("10.253", "514/UDP"),
    "dhcp": ("10.0", "67/UDP"),
    "mail": ("10.0", "25/TCP"),
    "database": ("10.0", "5432/TCP"),
    "system": ("10.0", "0/UDP"),
}
DOMAINS = [
    "intranet.corp.local", "mail.corp.local", "www.google.com",
    "login.microsoftonline.com", "github.com", "cdn.example.org",
    "update.windows.com", "fileserver.corp.local", "api.example.org",
]
DNS_TYPES = ["A", "A", "A", "AAAA", "MX", "TXT"]
MACHINES = [
    "srv-web-01", "srv-web-02", "srv-db-01", "srv-mail-01", "srv-file-01",
    "pc-compta-07", "pc-rh-03", "pc-dev-12", "pc-direction-01",
]
ACTIONS = {
    ("INFO", "file_open", "/srv/partage/rapport.docx"): 35,
    ("INFO", "file_copy", "/srv/partage/budget.xlsx"): 15,
    ("INFO", "print", "imprimante-etage-2"): 15,
    ("INFO", "share_access", "//fileserver/compta"): 15,
    ("INFO", "password_change", "compte personnel"): 5,
    ("WARNING", "sudo", "systemctl restart nginx"): 6,
    ("WARNING", "file_delete", "/srv/partage/ancien.zip"): 4,
    ("WARNING", "usb_insert", "clé USB inconnue"): 3,
    ("WARNING", "software_install", "putty-0.81.msi"): 2,
}
THREATS = ["Trojan.Generic", "Ransom.Lockbit", "Adware.Agent", "Worm.Blaster"]
COUNTRIES = ["FR", "FR", "FR", "FR", "FR", "DE", "ES", "BE", "IT", "GB"]
GATEWAYS = ["fgt-par-01", "fgt-par-02", "fgt-lyo-01"]
FIREWALL_PORTS = [443, 443, 443, 80, 53, 123, 22, 25, 8080, 3389, 445]
AUTH_METHODS = ["password", "password", "sso", "mfa", "publickey"]
SECRETS = ["hunter2", "P@ssw0rd", "letmein", "azerty123", "changeme"]
ATTACK_PATHS = [
    "/login?user=admin'%20OR%201=1--",
    "/search?q=' OR 1=1--",
    "/api/v1/items?id=1 UNION SELECT card FROM payments",
    "/search?q=<script>alert(1)</script>",
    "/download?file=../../../../etc/passwd",
    "/static/..%2F..%2F..%2Fetc/passwd",
    "/admin?cmd=;DROP TABLE users",
]
ATTACK_USERS = ["admin", "root", "administrator", "oracle", "postgres"]
SERVICE_ACCOUNTS = ["svc_backup", "svc_ldap", "svc_monitor", "svc_print"]
ROGUE_ACCOUNTS = ["guest", "cisco", "support"]
USER_COUNT = 20000
EXTERNAL_COUNT = 150000
BLACKLIST_SIZE = 600


def weighted_list(weights: dict) -> list:
    """Répète chaque valeur selon son poids, pour random.choice."""
    values = []
    for value, weight in weights.items():
        values += [value] * weight
    return values


def build_hour_choices() -> list:
    """Prépare, pour chaque heure, le tirage pondéré des types de logs."""
    hours = []
    for hour in range(24):
        weights = {}
        for service, share in SERVICES.items():
            office = service in OFFICE_SERVICES
            profile = OFFICE_HOURS if office else FLAT_HOURS
            weights[service] = round(share * profile[hour] * 1000)
        hours.append(weighted_list(weights))
    return hours


PATH_CHOICES = weighted_list(WEB_PATHS)
STATUS_CHOICES = weighted_list(HTTP_STATUS)
ACTION_CHOICES = weighted_list(ACTIONS)
RAW_CHOICES = {}
for raw_service, raw_messages in RAW_MESSAGES.items():
    RAW_CHOICES[raw_service] = weighted_list(raw_messages)
HOUR_CHOICES = build_hour_choices()
SAFE_DEFECTS = weighted_list(REPAIRABLE_DEFECTS)
ALL_DEFECTS = (
    SAFE_DEFECTS
    + weighted_list(NOISE_DEFECTS)
    + weighted_list(INVALID_DEFECTS)
)


def random_port() -> int:
    """Tire un port client."""
    return random.randint(1024, 65534)


def build_pools(seed: int) -> dict:
    """Crée les populations : utilisateurs, adresses, liste noire."""
    random.seed(seed)
    reserved = (10, 45, 127, 169, 172, 185, 192)
    external = []
    while len(external) < EXTERNAL_COUNT:
        first = random.randint(1, 223)
        if first not in reserved:
            external.append(
                f"{first}.{random.randint(0, 255)}."
                f"{random.randint(0, 255)}.{random.randint(1, 254)}"
            )
    users = []
    internal = []
    for index in range(USER_COUNT):
        users.append(f"u{index:05d}")
        internal.append(
            f"10.{20 + index // 62500}.{(index // 250) % 250}."
            f"{index % 250 + 1}"
        )
    blacklist = set()
    while len(blacklist) < BLACKLIST_SIZE:
        blacklist.add(
            f"185.220.{random.randint(0, 255)}.{random.randint(1, 254)}"
        )
    ordered_blacklist = sorted(blacklist)
    return {
        "users": users,
        "internal": internal,
        "external": external,
        "blacklist": ordered_blacklist,
        "blacklist_active": ordered_blacklist[:360],
    }


def pick_client(pools: dict) -> tuple:
    """Choisit un client : certains sont bien plus actifs que d'autres."""
    index = int(random.random() ** 3 * USER_COUNT)
    return pools["internal"][index], pools["users"][index]


def pick_external(pools: dict) -> str:
    """Choisit une IP externe."""
    index = int(random.random() ** 2 * EXTERNAL_COUNT)
    return pools["external"][index]


def build_web(pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée une requête web avec un payload JSON."""
    if random.random() < 0.45:
        ip, user = pick_client(pools)
    elif random.random() < 0.002:
        ip, user = random.choice(pools["blacklist_active"]), "-"
        flags["blacklisted"] = ip
    else:
        ip, user = pick_external(pools), "-"
    path = random.choice(PATH_CHOICES).replace(
        "ID", str(random.randint(1, 99999))
    )
    status = random.choice(STATUS_CHOICES)
    if outage and random.random() < 0.6:
        status = 503
    if random.random() < 0.002:
        path = f"/login?user={user}&password={random.choice(SECRETS)}"
        flags["secret"] = True
    if status >= 500:
        level = "ERROR"
    elif status >= 400:
        level = "WARNING"
    else:
        level = "INFO"
    method = "POST" if random.random() < 0.22 else "GET"
    size = int(200 + 60000 * random.random() ** 3)
    latency = int(4 + 400 * random.random() ** 4)
    agent = random.choice(USER_AGENTS)
    payload = (
        f'{{"method":"{method}","path":"{path}","status":{status},'
        f'"bytes":{size},"latency_ms":{latency},"agent":"{agent}"}}'
    )
    return level, f"{ip}:{random_port()}/TCP", user, payload


def build_firewall(pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée une connexion réseau avec un payload en tuple."""
    internal = random.random() < 0.35
    if internal:
        ip = pick_client(pools)[0]
    elif random.random() < 0.002:
        ip = random.choice(pools["blacklist_active"])
        flags["blacklisted"] = ip
    else:
        ip = pick_external(pools)
    protocol = "UDP" if random.random() < 0.18 else "TCP"
    allowed = random.random() < (0.9 if internal else 0.55)
    action = "ALLOW" if allowed else "DENY"
    level = "INFO" if allowed else "WARNING"
    target = f"172.16.{random.randint(0, 7)}.{random.randint(1, 254)}"
    port = random.choice(FIREWALL_PORTS)
    size = int(64 + 90000 * random.random() ** 4)
    payload = f"conn=({target},{port},{protocol}) action={action} bytes={size}"
    return level, f"{ip}:{random_port()}/{protocol}", "-", payload


def auth_payload(event: str, code: int, method: str = "password") -> str:
    """Crée le payload JSON d'un événement d'authentification."""
    session = random.randint(100000000, 999999999)
    return (
        f'{{"event":"{event}","code":{code},"method":"{method}",'
        f'"session":"{session}"}}'
    )


def build_auth(pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée un événement d'authentification normal."""
    ip, user = pick_client(pools)
    draw = random.random()
    if draw < 0.82:
        event, level, code = "login_success", "INFO", 200
    elif draw < 0.9:
        event, level, code = "login_failed", "WARNING", 401
    else:
        event, level, code = "logout", "INFO", 200
    payload = auth_payload(event, code, random.choice(AUTH_METHODS))
    return level, f"{ip}:{random_port()}/TCP", user, payload


def vpn_payload(event: str, country: str, size: int, duration: int) -> str:
    """Crée le payload JSON d'un événement VPN."""
    gateway = random.choice(GATEWAYS)
    return (
        f'{{"event":"{event}","country":"{country}","gateway":"{gateway}",'
        f'"bytes":{size},"duration_s":{duration}}}'
    )


def build_vpn(pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée un événement VPN normal. Un utilisateur garde son pays."""
    internal_ip, user = pick_client(pools)
    number = int(user[1:])
    country = COUNTRIES[number % len(COUNTRIES)]
    ip = pools["external"][number]
    draw = random.random()
    if draw < 0.5:
        event, level = "vpn_connect", "INFO"
    elif draw < 0.92:
        event, level = "vpn_disconnect", "INFO"
    else:
        event, level = "vpn_tunnel_error", "ERROR"
    size = int(1000 + 40000000 * random.random() ** 5)
    payload = vpn_payload(event, country, size, random.randint(1, 28800))
    return level, f"{ip}:{random_port()}/UDP", user, payload


def build_app(pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée un log applicatif : JSON si erreur, texte brut sinon."""
    ip, user = pick_client(pools)
    module = random.choice(APP_MODULES)
    source = f"{ip}:{random_port()}/TCP"
    if random.random() < (0.35 if outage else 0.06):
        code, message = random.choice(APP_ERRORS)
        critical = code == 503 and random.random() < 0.08
        level = "CRITICAL" if critical else "ERROR"
        payload = (
            f'{{"level":"{level}","code":{code},"module":"{module}",'
            f'"message":"{message}"}}'
        )
        return level, source, user, payload
    if random.random() < 0.0015:
        flags["secret"] = True
        secret = random.choice(SECRETS)
        message = f"{module}: échec SMTP avec password={secret}"
        return "WARNING", source, user, message
    level, template = random.choice(APP_MESSAGES)
    message = template.format(random.randint(1, 5000))
    return level, source, user, f"{module}: {message}"


def build_raw(service: str, pools: dict) -> tuple:
    """Crée un message brut d'équipement : routeur, switch, wifi, etc."""
    prefix, tail = RAW_SOURCES[service]
    source = (
        f"{prefix}.{random.randint(1, 9)}.{random.randint(1, 39)}:{tail}"
    )
    number = random.randint(1, 99)
    if service == "router" and random.random() < 0.01:
        # Changement de configuration normal, par un administrateur.
        admin = random.choice(["netadmin1", "netadmin2"])
        ip = f"10.0.1.{random.randint(1, 9)}"
        message = f"%SYS-5-CONFIG_I: Configured from console by {admin}"
        return "INFO", f"{ip}:22/TCP", admin, message
    if service in CRITICAL_MESSAGES and random.random() < 0.002:
        message = CRITICAL_MESSAGES[service].format(number)
        return "CRITICAL", source, "-", message
    level, template = random.choice(RAW_CHOICES[service])
    return level, source, "-", template.format(number)


def build_dns(pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée une requête DNS."""
    ip = pick_client(pools)[0]
    failed = random.random() < 0.05
    code = "NXDOMAIN" if failed else "NOERROR"
    level = "WARNING" if failed else "INFO"
    payload = (
        f'{{"event":"dns_query","name":"{random.choice(DOMAINS)}",'
        f'"type":"{random.choice(DNS_TYPES)}","rcode":"{code}",'
        f'"latency_ms":{random.randint(1, 120)}}}'
    )
    return level, f"{ip}:{random_port()}/UDP", "-", payload


def build_action(pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée une action faite par un utilisateur sur une machine."""
    ip, user = pick_client(pools)
    level, event, target = random.choice(ACTION_CHOICES)
    payload = f'{{"event":"{event}","target":"{target}","result":"ok"}}'
    return level, f"{ip}:0/TCP", user, payload


def build_machine(pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée une mesure d'état d'une machine."""
    number = random.randint(0, len(MACHINES) - 1)
    cpu = int(5 + 95 * random.random() ** 3)
    ram = random.randint(20, 95)
    disk = random.randint(30, 97)
    level = "WARNING" if cpu > 90 or disk > 95 else "INFO"
    payload = (
        f'{{"host":"{MACHINES[number]}","cpu":{cpu},"ram":{ram},'
        f'"disk":{disk},"temp":{random.randint(35, 80)}}}'
    )
    return level, f"10.0.1.{number + 10}:0/UDP", "-", payload


def build_antivirus(pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée un événement de l'antivirus."""
    ip = pick_client(pools)[0]
    if random.random() < 0.02:
        threat = random.choice(THREATS)
        payload = (
            f'{{"event":"threat_found","threat":"{threat}",'
            f'"action":"quarantine"}}'
        )
        return "ERROR", f"{ip}:0/TCP", "-", payload
    files = random.randint(100, 90000)
    payload = f'{{"event":"scan_finished","files":{files},"threats":0}}'
    return "INFO", f"{ip}:0/TCP", "-", payload


def format_time(moment: datetime) -> str:
    """Formate une date, par exemple 2026-10-01T08:14:03.120Z."""
    return moment.isoformat(timespec="milliseconds") + "Z"


def join_fields(fields: list) -> str:
    """Assemble les six champs d'une ligne."""
    return " | ".join(fields)


def apply_defect(name: str, fields: list, moment: datetime) -> tuple:
    """Abîme une ligne. Retourne le défaut appliqué et le texte obtenu.

    Si le défaut n'a pas de sens sur cette ligne, la casse du niveau est
    changée à la place.
    """
    host, _, tail = fields[2].rpartition(":")
    protocol = tail.partition("/")[2]
    padded = ".".join([part.zfill(3) for part in host.split(".")])
    line = fields[5]
    match name:
        case "level_case":
            fields[1] = fields[1].lower()
        case "level_alias":
            aliases = {
                "WARNING": "WARN", "ERROR": "ERR", "CRITICAL": "FATAL",
                "INFO": "NOTICE", "DEBUG": "TRACE",
            }
            fields[1] = aliases[fields[1]]
        case "ts_space":
            fields[0] = fields[0][:-1].replace("T", " ")
        case "ts_fr":
            fields[0] = moment.strftime("%d/%m/%Y %H:%M:%S")
        case "ts_epoch":
            seconds = (moment - datetime(1970, 1, 1)).total_seconds()
            fields[0] = str(int(seconds))
        case "ts_offset":
            local = moment + timedelta(hours=2)
            fields[0] = local.isoformat(timespec="milliseconds") + "+02:00"
        case "ip_leading_zeros" if padded != host:
            fields[2] = f"{padded}:{tail}"
        case "ip_brackets":
            fields[2] = f"[{host}]:{tail}"
        case "ip_mapped":
            fields[2] = f"::ffff:{host}:{tail}"
        case "proto_case":
            fields[2] = fields[2].lower()
        case "user_case" if fields[3] != "-":
            fields[3] = "USER:" + fields[3]
        case "user_null" if fields[3] == "-":
            fields[3] = random.choice(["null", "N/A", "none", "anonymous"])
        case "spacing":
            return name, "   " + "\t|  ".join(fields) + "  \t"
        case "ansi":
            fields[1] = f"\x1b[31m{fields[1]}\x1b[0m"
        case "control_chars":
            return name, "﻿" + join_fields(fields)
        case "json_single_quotes" if "'" not in line and line[0] == "{":
            fields[5] = fields[5].replace('"', "'")
        case "json_trailing_comma" if fields[5].startswith("{"):
            fields[5] = fields[5][:-1] + ",}"
        case "duplicate":
            return name, join_fields(fields) + "\n" + join_fields(fields)
        case "blank":
            return name, ""
        case "whitespace":
            return name, "   \t "
        case "comment":
            return name, "# logrotate: fichier tourné"
        case "truncated":
            return name, join_fields(fields)[:random.randint(8, 40)]
        case "corrupted_marker":
            return name, "CORRUPTED_LINE_WITHOUT_FORMAT"
        case "garbage":
            return name, "¤§¶þ¿" * random.randint(2, 12)
        case "missing_field":
            del fields[random.randint(1, 4)]
        case "bad_ip":
            bad = random.choice(["999.12.3.4", "not_an_ip", "10.20.30"])
            fields[2] = f"{bad}:{tail}"
        case "bad_port":
            bad = random.choice(["70000", "abc"])
            fields[2] = f"{host}:{bad}/{protocol}"
        case "bad_timestamp":
            fields[0] = random.choice(["2026-13-45T25:61:00Z", "not-a-date"])
        case "out_of_range_timestamp":
            fields[0] = random.choice(
                ["1970-01-01T00:00:00.000Z", "2099-06-15T12:00:00.000Z"]
            )
        case "bad_level":
            fields[1] = random.choice(["BANANA", "???", "LEVEL5"])
        case "truncated_json" if fields[5].startswith("{"):
            fields[5] = fields[5][:len(fields[5]) // 3]
        case "bad_service":
            fields[4] = ""
        case _:
            fields[1] = fields[1].lower()
            return "level_case", join_fields(fields)
    return name, join_fields(fields)


def attacker_ip(block: int) -> str:
    """Tire une IP réservée à un type d'attaque."""
    return f"45.{block}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def add_failures(plan: list, moment: datetime, source: str, user: str,
                 count: int, low: int, high: int) -> datetime:
    """Planifie une série d'échecs de connexion. Retourne la dernière date."""
    for _ in range(count):
        moment += timedelta(milliseconds=random.randint(low, high))
        payload = auth_payload("login_failed", 401)
        plan.append((moment, ("WARNING", source, user, payload)))
    return moment


def plan_auth(day: datetime, pools: dict, truth: dict) -> list:
    """Planifie les attaques visibles dans les logs d'authentification."""
    plan = []
    for _ in range(CAMPAIGNS["bruteforce_fast"]):
        ip = attacker_ip(10)
        user = random.choice(ATTACK_USERS + pools["users"][:50])
        moment = day + timedelta(seconds=random.randint(0, 82000))
        source = f"{ip}:{random_port()}/TCP"
        count = random.randint(15, 79)
        moment = add_failures(plan, moment, source, user, count, 600, 5000)
        truth["bruteforce_fast"].add(ip)
        if random.random() < 0.3:
            moment += timedelta(seconds=2)
            payload = auth_payload("login_success", 200)
            plan.append((moment, ("INFO", source, user, payload)))
            truth["compromised"].add(ip)

    for _ in range(CAMPAIGNS["bruteforce_slow"]):
        ip = attacker_ip(20)
        user = random.choice(ATTACK_USERS)
        moment = day + timedelta(seconds=random.randint(0, 43000))
        source = f"{ip}:{random_port()}/TCP"
        count = random.randint(20, 39)
        add_failures(plan, moment, source, user, count, 200000, 800000)
        truth["bruteforce_slow"].add(ip)

    for _ in range(CAMPAIGNS["benign_lockout"]):
        # Compte de service au mot de passe expiré : un faux positif attendu.
        ip = f"10.250.{random.randint(0, 255)}.{random.randint(1, 254)}"
        user = random.choice(SERVICE_ACCOUNTS)
        moment = day + timedelta(seconds=random.randint(0, 85000))
        source = f"{ip}:{random_port()}/TCP"
        count = random.randint(7, 11)
        add_failures(plan, moment, source, user, count, 2000, 8000)
        truth["benign_lockout"].add(ip)

    for _ in range(CAMPAIGNS["password_spray"]):
        ip = attacker_ip(30)
        moment = day + timedelta(seconds=random.randint(0, 82000))
        source = f"{ip}:{random_port()}/TCP"
        for _ in range(random.randint(25, 69)):
            user = random.choice(pools["users"])
            moment = add_failures(plan, moment, source, user, 1, 1000, 12000)
        truth["password_spray"].add(ip)
    return plan


def plan_firewall(day: datetime, pools: dict, truth: dict) -> list:
    """Planifie les scans de ports, dont celui du scanner autorisé."""
    plan = []
    scanners = ["10.0.0.50"]
    for _ in range(CAMPAIGNS["port_scan"]):
        ip = attacker_ip(40)
        scanners.append(ip)
        truth["port_scan"].add(ip)
    for ip in scanners:
        moment = day + timedelta(seconds=random.randint(0, 85000))
        for _ in range(random.randint(30, 119)):
            moment += timedelta(milliseconds=random.randint(5, 800))
            port = random.randint(1, 9999)
            payload = f"conn=(172.16.0.10,{port},TCP) action=DENY bytes=60"
            source = f"{ip}:{random_port()}/TCP"
            plan.append((moment, ("WARNING", source, "-", payload)))
    return plan


def web_payload(path: str, status: int, size: int) -> str:
    """Crée le payload JSON d'une requête web planifiée."""
    return (
        f'{{"method":"GET","path":"{path}","status":{status},'
        f'"bytes":{size},"latency_ms":40,"agent":"curl/8.9.1"}}'
    )


def plan_web(day: datetime, pools: dict, truth: dict) -> list:
    """Planifie les attaques web et les exfiltrations."""
    plan = []
    for _ in range(CAMPAIGNS["web_attack"]):
        ip = attacker_ip(50)
        moment = day + timedelta(seconds=random.randint(0, 82000))
        for _ in range(random.randint(5, 39)):
            moment += timedelta(milliseconds=random.randint(100, 3000))
            status = random.choice([400, 403, 404, 500, 200])
            level = "ERROR" if status == 500 else "WARNING"
            payload = web_payload(random.choice(ATTACK_PATHS), status, 512)
            source = f"{ip}:{random_port()}/TCP"
            plan.append((moment, (level, source, "-", payload)))
        truth["web_attack"].add(ip)
    for _ in range(CAMPAIGNS["exfiltration"]):
        index = random.randint(0, USER_COUNT - 1)
        ip = pools["internal"][index]
        moment = day + timedelta(seconds=random.randint(0, 86000))
        size = random.randint(600000000, 4000000000)
        payload = web_payload("/download/file.zip", 200, size)
        source = f"{ip}:{random_port()}/TCP"
        plan.append((moment, ("INFO", source, pools["users"][index], payload)))
        truth["exfiltration"].add(ip)
    return plan


def plan_vpn(day: datetime, pools: dict, truth: dict) -> list:
    """Planifie des connexions depuis deux pays à quelques minutes d'écart."""
    plan = []
    for _ in range(CAMPAIGNS["impossible_travel"]):
        user = pools["users"][random.randint(1000, USER_COUNT - 1)]
        moment = day + timedelta(seconds=random.randint(0, 82000))
        for country, block in (("FR", 60), ("BR", 61)):
            ip = attacker_ip(block)
            payload = vpn_payload("vpn_connect", country, 2048, 120)
            source = f"{ip}:{random_port()}/UDP"
            plan.append((moment, ("INFO", source, user, payload)))
            moment += timedelta(seconds=random.randint(60, 600))
        truth["impossible_travel"].add(user)
    return plan


def plan_router(day: datetime, pools: dict, truth: dict) -> list:
    """Planifie des changements de configuration par un compte étranger."""
    plan = []
    for _ in range(CAMPAIGNS["rogue_config"]):
        ip = attacker_ip(70)
        user = random.choice(ROGUE_ACCOUNTS)
        moment = day + timedelta(seconds=random.randint(0, 86000))
        message = f"%SYS-5-CONFIG_I: Configured from vty0 by {user}"
        plan.append((moment, ("WARNING", f"{ip}:22/TCP", user, message)))
        truth["rogue_config"].add(ip)
    return plan


BUILDERS = {
    "web": build_web,
    "firewall": build_firewall,
    "auth": build_auth,
    "vpn": build_vpn,
    "app": build_app,
    "dns": build_dns,
    "action": build_action,
    "machine": build_machine,
    "antivirus": build_antivirus,
}
PLANNERS = {
    "auth": plan_auth,
    "firewall": plan_firewall,
    "web": plan_web,
    "vpn": plan_vpn,
    "router": plan_router,
}


def lines_per_hour(total: int, spike: bool) -> list:
    """Répartit les lignes d'une journée sur les 24 heures."""
    activity = [len(choices) for choices in HOUR_CHOICES]
    if spike:
        activity[14] *= 3
        activity[15] *= 3
    weight = sum(activity)
    return [round(total * value / weight) for value in activity]


def finish_line(parts: tuple, service: str, moment: datetime, state: dict,
                safe: bool, clean: bool) -> str:
    """Assemble une ligne, en lui ajoutant parfois un défaut."""
    fields = [format_time(moment), parts[0], parts[1], parts[2], service,
              parts[3]]
    defect = ""
    line = None
    if not clean and random.random() < DEFECT_RATE:
        choices = SAFE_DEFECTS if safe else ALL_DEFECTS
        defect, line = apply_defect(random.choice(choices), fields, moment)
    if line is None:
        line = join_fields(fields)
    if defect in NOISE_DEFECTS:
        state["injected"][defect] += 1
        return line
    if line == state["previous"]:
        # Deux lignes identiques à la suite comptent comme un doublon.
        state["injected"]["duplicate"] += 1
        return line
    if defect:
        state["injected"][defect] += 1
    state["previous"] = line
    return line


def build_line(service: str, pools: dict, outage: bool, flags: dict) -> tuple:
    """Crée le contenu d'une ligne normale pour un service."""
    if service in RAW_CHOICES:
        return build_raw(service, pools)
    return BUILDERS[service](pools, outage, flags)


def plan_day(day: datetime, pools: dict, truth: dict) -> list:
    """Regroupe les attaques d'une journée, triées par date."""
    plan = []
    for service, planner in PLANNERS.items():
        for moment, parts in planner(day, pools, truth):
            plan.append((moment, service, parts))
    plan.sort(key=lambda item: item[0])
    return plan


def web_side_line(moment: datetime, pools: dict, state: dict) -> str | None:
    """Crée parfois une sonde de supervision ou une ligne à l'ancien format."""
    draw = random.random()
    if draw < 0.02:
        state["injected"]["healthcheck"] += 1
        payload = (
            '{"method":"GET","path":"/health","status":200,'
            '"bytes":2,"latency_ms":1,"agent":"kube-probe/1.31"}'
        )
        parts = ("INFO", f"10.0.0.5:{random_port()}/TCP", "-", payload)
        return finish_line(parts, "web", moment, state, False, True)
    if draw < 0.03:
        # Une ancienne application écrit encore au format du TP6.
        state["injected"]["legacy_format"] += 1
        state["previous"] = None
        stamp = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
        status = random.choice(STATUS_CHOICES)
        return (
            f'{stamp} {pick_external(pools)} "GET /index.html" {status} '
            f"{random.randint(200, 50000)}"
        )
    return None


def iter_day(job: dict, pools: dict, state: dict) -> Iterator[str]:
    """Produit les lignes d'une journée dans l'ordre du temps."""
    day = job["day"]
    plan = plan_day(day, pools, state["truth"])
    counts = lines_per_hour(job["lines"], job["spike"])
    for hour in range(24):
        count = counts[hour]
        if count == 0:
            continue
        choices = HOUR_CHOICES[hour]
        outage = job["outage"] and hour in (10, 11, 12)
        rush = job["spike"] and hour in (14, 15)
        step = 3600 / count
        for position in range(count):
            seconds = hour * 3600 + (position + random.random()) * step
            moment = day + timedelta(seconds=seconds)
            while plan and plan[0][0] <= moment:
                planned, service, parts = plan.pop(0)
                yield finish_line(parts, service, planned, state, True, False)
            service = random.choice(choices)
            if rush and random.random() < 0.7:
                service = "web"
            if service == "web":
                line = web_side_line(moment, pools, state)
                if line is not None:
                    yield line
                    continue
            flags = {}
            parts = build_line(service, pools, outage, flags)
            if "secret" in flags:
                state["injected"]["secret_in_log"] += 1
            if "blacklisted" in flags:
                state["truth"]["blacklist_active"].add(flags["blacklisted"])
            clean = "secret" in flags
            safe = "blacklisted" in flags
            yield finish_line(parts, service, moment, state, safe, clean)
    while plan:
        planned, service, parts = plan.pop(0)
        yield finish_line(parts, service, planned, state, True, False)


def new_state() -> dict:
    """Crée le suivi de la génération."""
    return {
        "previous": None,
        "injected": defaultdict(int),
        "truth": defaultdict(set),
    }


def average_line_size(pools: dict) -> float:
    """Mesure la longueur moyenne d'une ligne pour viser le bon volume."""
    state = new_state()
    job = {
        "day": datetime(2026, 10, 1),
        "lines": 40000,
        "spike": False,
        "outage": False,
    }
    total = 0
    count = 0
    for line in iter_day(job, pools, state):
        total += len(line.encode("utf-8")) + 1
        count += 1 + line.count("\n")
    return total / count


def plan_days(total_lines: int, days: int) -> list:
    """Répartit les lignes entre les jours : moins le week-end, plus au pic."""
    spike_day = min(days - 1, 17)
    outage_day = min(days - 1, 9)
    weights = []
    for offset in range(days):
        current = FIRST_DAY + timedelta(days=offset)
        weight = 0.6 if current.weekday() >= 5 else 1.0
        weights.append(1.4 if offset == spike_day else weight)
    jobs = []
    for offset in range(days):
        current = FIRST_DAY + timedelta(days=offset)
        jobs.append(
            {
                "day": datetime(current.year, current.month, current.day),
                "lines": int(total_lines * weights[offset] / sum(weights)),
                "spike": offset == spike_day,
                "outage": offset == outage_day,
            }
        )
    return jobs


def generate_dataset(
    path: str, target: int, days: int = 30, seed: int = 42
) -> dict:
    """Génère le fichier de logs, sa liste noire et son manifeste."""
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    started = time.time()
    pools = build_pools(seed)
    # Petite marge pour ne pas finir juste en dessous de la taille demandée.
    jobs = plan_days(int(target * 1.005 / average_line_size(pools)), days)
    state = new_state()
    line_count = 0
    with open(path, "w", encoding="utf-8", newline="\n") as file:
        for number, job in enumerate(jobs, start=1):
            for line in iter_day(job, pools, state):
                file.write(line + "\n")
                line_count += 1 + line.count("\n")
            print(f"Jour {number}/{days} : {line_count} lignes")
    size = os.path.getsize(path)

    with open(os.path.join(folder, "blacklist.conf"), "w",
              encoding="utf-8") as file:
        for ip in pools["blacklist"]:
            file.write(ip + "\n")

    manifest = {
        "seed": seed,
        "days": days,
        "lines": line_count,
        "bytes": size,
        "seconds": round(time.time() - started, 1),
        "injected": dict(sorted(state["injected"].items())),
        "truth": {k: sorted(v) for k, v in state["truth"].items()},
    }
    with open(os.path.join(folder, "manifest.json"), "w",
              encoding="utf-8") as file:
        json.dump(manifest, file, indent=1)
    print(f"{size / 1024 ** 3:.2f} Go, {line_count} lignes : {path}")
    return manifest


def simulated_stream(lines_per_day: int, seed: int = 7) -> Iterator[str]:
    """Simule un flux en direct, sans fichier, avec yield from."""
    pools = build_pools(seed)
    state = new_state()
    for day in (5, 6):
        job = {
            "day": datetime(2026, 10, day),
            "lines": lines_per_day,
            "spike": False,
            "outage": False,
        }
        yield from iter_day(job, pools, state)
