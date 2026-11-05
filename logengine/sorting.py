"""Tri des logs : chaque ligne nettoyée rejoint le fichier de son type."""

import json
import os
from collections import defaultdict

from logengine.config import KNOWN_SERVICES


def format_payload(record: dict) -> str:
    """Réécrit le payload d'un enregistrement sous forme de texte."""
    payload = record["payload"]
    match payload:
        case dict():
            return json.dumps(payload, ensure_ascii=False,
                              separators=(",", ":"))
        case (ip, port, protocol):
            extra = record.get("extra", {})
            words = [f"{key}={value}" for key, value in extra.items()]
            return " ".join([f"conn=({ip},{port},{protocol})"] + words)
        case _:
            return str(payload)


def format_record(record: dict) -> str:
    """Réécrit un enregistrement au format standard, une fois nettoyé."""
    stamp = record["timestamp"].isoformat(timespec="milliseconds")
    ip, port, protocol = record["meta"]
    user = record["user"] or "-"
    return (
        f"{stamp}Z | {record['level']} | {ip}:{port}/{protocol} | {user} | "
        f"{record['service']} | {format_payload(record)}"
    )


class LogSorter:
    """Écrit chaque enregistrement dans le fichier de son service.

    Les lignes partent sur le disque au fil de l'eau : rien n'est gardé en
    mémoire, même si le fichier de départ fait 15 Go.
    """

    def __init__(self, folder: str) -> None:
        self.folder = folder
        self.files = {}
        self.counts = defaultdict(int)
        os.makedirs(folder, exist_ok=True)

    def write(self, batch: list) -> None:
        """Range un lot d'enregistrements."""
        for record in batch:
            service = record["service"]
            if service not in KNOWN_SERVICES:
                service = "other"
            if service not in self.files:
                path = os.path.join(self.folder, f"{service}.log")
                self.files[service] = open(path, "w", encoding="utf-8")
            self.files[service].write(format_record(record) + "\n")
            self.counts[service] += 1

    def close(self) -> None:
        """Ferme tous les fichiers."""
        for file in self.files.values():
            file.close()
