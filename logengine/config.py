"""Constantes du projet, regroupées pour être faciles à modifier."""

# Format d'une ligne : 6 champs séparés par le caractère |
FIELD_COUNT = 6

LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LEVEL_ALIASES = {
    "WARN": "WARNING",
    "ERR": "ERROR",
    "CRIT": "CRITICAL",
    "FATAL": "CRITICAL",
    "NOTICE": "INFO",
    "TRACE": "DEBUG",
}
ERROR_LEVELS = ("ERROR", "CRITICAL")

PROTOCOLS = ("TCP", "UDP", "ICMP")
NULL_USERS = ("", "null", "none", "n/a", "anonymous", "unknown")
SECRET_PATTERN = r"(password|token)=\S+"

# Nombre de lignes traitées d'un coup : c'est lui qui borne la RAM.
BATCH_SIZE = 10000

# Taille maximale des dictionnaires de cache et d'état.
MAX_CACHE_SIZE = 300000

# Force brute : nombre d'échecs tolérés dans une fenêtre de temps.
FAST_THRESHOLD = 6
FAST_WINDOW = 120
SLOW_THRESHOLD = 12
SLOW_WINDOW = 6 * 3600
MAX_ALERTS_PER_PASS = 500

# Seuils des autres règles de sécurité.
SCAN_PORTS = 20
SCAN_WINDOW = 60
SPRAY_USERS = 10
SPRAY_WINDOW = 600
EXFIL_BYTES = 500000000
TRAVEL_WINDOW = 1800
ALERT_COOLDOWN = 3600

# Scanner de vulnérabilités interne : il scanne, mais il est autorisé.
ALLOWED_IPS = frozenset(["10.0.0.50"])

# Seuls ces comptes ont le droit de modifier la configuration des routeurs.
NETWORK_ADMINS = ("netadmin1", "netadmin2")

# Types de logs connus. Chacun a son fichier après le tri. Le reste va dans
# other.log : un nom de service lu dans un log ne doit jamais servir de nom
# de fichier, sinon une ligne piégée pourrait écrire n'importe où.
KNOWN_SERVICES = (
    "web", "firewall", "router", "switch", "wifi", "dns", "dhcp", "auth",
    "vpn", "action", "app", "database", "mail", "machine", "system",
    "antivirus",
)

WEB_ATTACK_SIGNATURES = (
    "' or 1=1",
    "%20or%201=1",
    "union select",
    "<script",
    "../..",
    "..%2f",
    "/etc/passwd",
    ";drop table",
)
