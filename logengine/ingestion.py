"""Module 1 : lecture des logs ligne par ligne, sans tout charger en RAM."""

import os
from typing import Iterator


def read_log_file(path: str) -> Iterator[str]:
    """Produit les lignes d'un fichier une par une avec yield."""
    # errors="replace" : un octet illisible ne doit pas arrêter la lecture.
    with open(path, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            yield line


def read_sources(paths: list[str]) -> Iterator[str]:
    """Enchaîne un ou plusieurs fichiers avec yield from."""
    for path in paths:
        try:
            yield from read_log_file(path)
        except FileNotFoundError:
            print(f"Fichier introuvable, ignoré : {path}")
        except OSError as error:
            print(f"Lecture impossible, fichier ignoré : {error}")


def limit_lines(lines: Iterator, maximum: int) -> Iterator[str]:
    """Arrête la lecture après un nombre de lignes donné."""
    for number, line in enumerate(lines, start=1):
        yield line
        if number == maximum:
            break


def total_size(paths: list[str]) -> int:
    """Retourne la taille totale des fichiers, en octets."""
    return sum([os.path.getsize(path) for path in paths])
