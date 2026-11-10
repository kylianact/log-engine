"""Affichage lisible des lignes dans le terminal, pour montrer le tri.

    python main.py --generate=logs.log --show=30    lignes créées
    python main.py --log-file=logs.log --show=30    lignes analysées

Pendant l'affichage, chaque ligne passe seule dans le pipeline normal, avec
ses propres compteurs. Ce qui est écrit à l'écran est donc ce que le programme
a vraiment fait de cette ligne.
"""

import re
from typing import Iterator, TextIO

from logengine.config import KNOWN_SERVICES, SECRET_PATTERN
from logengine.monitor import current_ram
from logengine.sorting import format_record
from logengine.transform import (
    build_record_stream,
    new_quality_counters,
    sanitize_line,
)

DEFECT_LABELS = {
    "ansi": "codes couleur dans la ligne",
    "bad_ip": "IP invalide",
    "bad_level": "niveau inconnu",
    "bad_port": "port invalide",
    "bad_service": "service vide",
    "bad_timestamp": "date invalide",
    "blank": "ligne vide",
    "comment": "commentaire",
    "control_chars": "caractère invisible en début de ligne",
    "corrupted_marker": "ligne corrompue",
    "duplicate": "ligne répétée deux fois",
    "garbage": "caractères illisibles",
    "healthcheck": "sonde de supervision",
    "ip_brackets": "IP entre crochets",
    "ip_leading_zeros": "IP avec des zéros en trop",
    "ip_mapped": "IP précédée de ::ffff:",
    "json_single_quotes": "JSON avec des guillemets simples",
    "json_trailing_comma": "JSON avec une virgule en trop",
    "legacy_format": "ancien format du TP6",
    "level_alias": "niveau écrit autrement",
    "level_case": "niveau en minuscules",
    "missing_field": "champ manquant",
    "out_of_range_timestamp": "date hors plage",
    "proto_case": "protocole en minuscules",
    "secret_in_log": "mot de passe en clair",
    "spacing": "espaces et tabulations en trop",
    "truncated": "ligne coupée",
    "truncated_json": "JSON coupé",
    "ts_epoch": "date en secondes",
    "ts_fr": "date au format français",
    "ts_offset": "date avec un fuseau horaire",
    "ts_space": "date sans le T ni le Z",
    "user_case": "utilisateur préfixé par USER:",
    "user_null": "utilisateur vide écrit en toutes lettres",
    "whitespace": "ligne faite d'espaces",
}

REPAIR_LABELS = {
    "control_chars": "caractères cachés retirés",
    "ip": "adresse IP réécrite",
    "json": "JSON réparé",
    "legacy_format": "ancien format du TP6 converti",
    "level": "niveau réécrit",
    "protocol": "protocole mis en majuscules",
    "secret_masked": "mot de passe masqué",
    "timestamp": "date réécrite au format standard",
    "user": "utilisateur nettoyé",
}

REJECT_LABELS = {
    "ip": "l'adresse IP est invalide",
    "json": "le JSON est irrécupérable",
    "level": "le niveau est inconnu",
    "payload": "le tuple de connexion est illisible",
    "port": "le port est invalide",
    "protocol": "le protocole est inconnu",
    "service": "le champ service est vide",
    "structure": "la ligne n'a pas les 6 champs attendus",
    "timestamp": "la date est illisible",
    "timestamp_range": "la date est trop ancienne ou dans le futur",
}

# Chaque catégorie correspond à un case de route_record, dans transform.py.
ROUTE_LABELS = {
    "app_error": "le JSON a un niveau ERROR ou CRITICAL et un code",
    "auth_event": "le JSON décrit une connexion ou une déconnexion",
    "connection": "c'est une connexion (ip, port, protocole)",
    "connection_sensitive": "c'est une connexion vers un port sensible",
    "healthcheck": "le chemin demandé est /health",
    "http_4xx": "le JSON a un statut HTTP de 400 à 499",
    "http_5xx": "le JSON a un statut HTTP de 500 ou plus",
    "http_ok": "le JSON a un statut HTTP inférieur à 400",
    "json_other": "le JSON n'a aucun champ reconnu",
    "machine_metric": "le JSON a un champ cpu",
    "network_device": "le texte commence par %, comme un message Cisco",
    "raw_text": "c'est un texte brut",
    "session_event": "le JSON a un champ event, sans champ target",
    "threat": "le JSON a un champ threat",
    "unknown": "le contenu n'a pas de forme connue",
    "user_action": "le JSON a un champ event et un champ target",
}

STATUS_TITLES = {
    "doublon": "DOUBLON",
    "ignoree": "IGNORÉE",
    "ok": "OK",
    "reparee": "RÉPARÉE",
    "rejetee": "REJETÉE",
    "sonde": "SONDE",
}

ONLY_VALUES = (
    list(KNOWN_SERVICES)
    + list(ROUTE_LABELS)
    + list(STATUS_TITLES)
    + ["alerte"]
)


def visible(text: str) -> str:
    """Rend visibles les caractères cachés, sans abîmer le terminal."""
    if text.isprintable():
        return text
    shown = ""
    for character in text:
        if character.isprintable():
            shown += character
        else:
            shown += f"<{ord(character):02x}>"
    return shown


def print_raw_lines(lines: Iterator, every: int) -> Iterator[str]:
    """Affiche les lignes telles qu'elles sont lues, pendant l'analyse.

    every vaut 1 pour tout montrer, ou 1000 pour une ligne sur mille. Les
    lignes continuent ensuite dans le pipeline, sans aucun changement. Les
    mots de passe restent masqués, comme dans tous les fichiers produits.
    """
    for number, line in enumerate(lines, start=1):
        if number % every == 0:
            text = re.sub(SECRET_PATTERN, r"\1=***", line.rstrip("\n"))
            print(f"{number} | {visible(text) or '(vide)'}")
        yield line


def print_generated(number: int, line: str, service: str, kind: str) -> None:
    """Affiche une ligne créée par le générateur et son éventuel défaut."""
    label = DEFECT_LABELS.get(kind, kind)
    for text in line.split("\n"):
        print(f"Ligne {number} | {service} | {label}")
        print(f"  {visible(text) or '(vide)'}")
        number += 1


def print_categories() -> None:
    """Affiche les types de logs et les catégories du tri."""
    print("Types de logs : le champ service choisit le fichier de tri/")
    print(f"  {', '.join(KNOWN_SERVICES)}")
    print("  Un type inconnu part dans other.log.")
    print("\nCatégories : la forme du contenu choisit la catégorie")
    for route, reason in ROUTE_LABELS.items():
        print(f"  {route:<22}{reason}")
    print("\nÉtats d'une ligne avec --show")
    print("  OK, RÉPARÉE          la ligne est triée")
    print("  REJETÉE              la ligne part dans bad_lines.log")
    print("  IGNORÉE, DOUBLON     la ligne ne contient rien de nouveau")
    print("  SONDE                la ligne vient de la supervision /health")


def line_status(trace: dict) -> str:
    """Dit ce qui est arrivé à une ligne, d'après ses propres compteurs."""
    if trace["rejects"]:
        return "rejetee"
    if "data_lines" not in trace["funnel"]:
        return "ignoree"
    if "duplicate" in trace["repairs"]:
        return "doublon"
    if "analysed" not in trace["funnel"]:
        return "sonde"
    if trace["repairs"]:
        return "reparee"
    return "ok"


def print_decision(status: str, trace: dict, record: dict | None) -> None:
    """Explique pourquoi une ligne a été écartée ou triée."""
    if status == "rejetee":
        reason = REJECT_LABELS[list(trace["rejects"])[0]]
        print(f"  motif     : {reason} -> bad_lines.log")
    elif status == "doublon":
        print("  motif     : même ligne que la précédente")
    elif status == "sonde":
        print("  motif     : le chemin demandé est /health")
    elif status == "ignoree":
        empty = "not_empty" not in trace["funnel"]
        print(f"  motif     : {'ligne vide' if empty else 'commentaire'}")
    if record is None:
        return
    service = record["service"]
    target = service if service in KNOWN_SERVICES else "other"
    if "legacy_format" in trace["repairs"]:
        reason = "le format du TP6 ne contient que du web"
    elif target == "other":
        reason = f"le service {service} n'est pas un type connu"
    else:
        reason = f"le champ service vaut {service}"
    route = record["route"]
    if status == "reparee":
        print(f"  propre    : {visible(format_record(record))}")
    print(f"  type      : {target} -> tri/{target}.log, car {reason}")
    print(f"  catégorie : {route}, car {ROUTE_LABELS[route]}")


class LineDisplay:
    """Affiche les lignes analysées, avec la raison de leur tri.

    limit vaut le nombre de lignes à montrer avant de s'arrêter, ou 0 pour
    tout montrer. only garde un type, une catégorie, un état ou "alerte".
    """

    def __init__(self, limit: int = 0, only: str = "") -> None:
        self.limit = limit
        self.only = only
        self.shown = 0
        self.alerts = []

    def wanted(self, status: str, record: dict | None) -> bool:
        """Dit si une ligne correspond au filtre demandé."""
        if self.only == "":
            return True
        if self.only == "alerte":
            return len(self.alerts) > 0
        if record is None:
            return self.only == status
        return self.only in (status, record["service"], record["route"])

    def show(self, number: int, line: str, trace: dict,
             records: list) -> None:
        """Affiche une ligne si elle correspond au filtre."""
        status = line_status(trace)
        record = records[0] if records else None
        if self.wanted(status, record):
            self.shown += 1
            text = re.sub(SECRET_PATTERN, r"\1=***", line.rstrip("\n"))
            title = f"Ligne {number} [{STATUS_TITLES[status]}]"
            # La RAM est mesurée au moment où la ligne vient d'être traitée.
            print(f"\n{title:<26}RAM {current_ram():.1f} Mo")
            print(f"  lue       : {visible(text) or '(vide)'}")
            fixes = [
                REPAIR_LABELS[name]
                for name in trace["repairs"]
                if name in REPAIR_LABELS
            ]
            if fixes:
                print(f"  réparée   : {', '.join(fixes)}")
            print_decision(status, trace, record)
            for alert in self.alerts:
                print(f"  ALERTE    : {alert['rule']}, {alert['detail']}")
        self.alerts = []

    def finished(self) -> bool:
        """Dit si assez de lignes ont été montrées."""
        return 0 < self.limit <= self.shown


def merge_counters(total: dict, part: dict) -> None:
    """Ajoute les compteurs d'une ligne aux compteurs généraux."""
    for section, counters in part.items():
        for name, value in counters.items():
            total[section][name] += value


def trace_stream(
    lines: Iterator, quality: dict, bad_lines: TextIO, display: LineDisplay
) -> Iterator[dict]:
    """Fait passer les lignes une par une dans le pipeline normal.

    La ligne est affichée après le yield : la boucle principale a alors fini
    de la traiter, et on connaît les alertes qu'elle a déclenchées.
    """
    previous = None
    for number, line in enumerate(lines, start=1):
        trace = new_quality_counters()
        records = list(
            build_record_stream(iter([line]), trace, bad_lines, previous)
        )
        merge_counters(quality, trace)
        if "data_lines" in trace["funnel"]:
            previous = sanitize_line(line, new_quality_counters())
        yield from records
        display.show(number, line, trace, records)
        if display.finished():
            return
