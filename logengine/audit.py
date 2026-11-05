"""Module 4 : audit des variables en mémoire avec globals() et locals().

globals() et locals() décrivent l'endroit où on les appelle. C'est donc
l'appelant qui les évalue, puis qui transmet les dictionnaires à ce module.
"""

import json
import sys
from typing import Any

SENSITIVE_NAMES = ("password", "secret", "token")


def describe_variable(name: str, value: Any) -> dict:
    """Décrit une variable sans la modifier.

    Un générateur n'est jamais parcouru : le lire le viderait.
    """
    description = {
        "type": type(value).__name__,
        "size_bytes": sys.getsizeof(value),
    }
    try:
        description["length"] = len(value)
    except TypeError:
        pass
    hidden = False
    for word in SENSITIVE_NAMES:
        if word in name.lower():
            hidden = True
    description["preview"] = "***" if hidden else repr(value)[:80]
    return description


def build_audit(label: str, scope_globals: dict, scope_locals: dict) -> dict:
    """Décrit les variables globales et locales d'une portée."""
    report: dict = {
        "scope": label,
        "python": sys.version.split()[0],
        "loaded_modules": len(sys.modules),
        "globals": {},
        "locals": {},
    }
    for name, value in scope_globals.items():
        if not name.startswith("__"):
            report["globals"][name] = describe_variable(name, value)
    for name, value in scope_locals.items():
        report["locals"][name] = describe_variable(name, value)
    return report


def export_audit(path: str, report: dict) -> None:
    """Écrit le rapport d'audit en JSON."""
    with open(path, "w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)
