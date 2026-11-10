"""Module 3 : détection des attaques par force brute.

Une attaque est signalée quand un couple (IP, compte) accumule trop d'échecs
de connexion dans une fenêtre de temps, sans réussite entre deux.
"""

from datetime import datetime, timedelta
from typing import Callable

from logengine.config import FORGET_EVERY, MAX_ALERTS_PER_PASS


class BruteForceDetector:
    """Détecteur alimenté lot par lot."""

    def __init__(self, threshold: int, window: int, rule: str) -> None:
        self.threshold = threshold
        self.window = timedelta(seconds=window)
        self.rule = rule
        self.failures = {}
        self.flagged = {}
        self.completed_cycles = 0
        self.interrupted_passes = 0

    def run_cycle(self, batch: list, publish: Callable) -> None:
        """Inspecte tout un lot et transmet les alertes à publish.

        publish est une fonction reçue en argument (callback).

        Si trop d'alertes s'accumulent, break quitte le for pour les publier,
        et le while relance l'inspection juste après la dernière ligne vue.
        Le else du for ne s'exécute que si aucun break n'a eu lieu : le lot a
        été vu jusqu'au bout, le cycle est donc validé.
        """
        position = 0
        while position < len(batch):
            alerts = []
            for index in range(position, len(batch)):
                record = batch[index]
                if record["service"] != "auth" or record["user"] is None:
                    continue
                if not isinstance(record["payload"], dict):
                    continue
                event = record["payload"].get("event")
                key = (record["ip"], record["user"])
                if event == "login_failed":
                    alert = self.on_failure(key, record["timestamp"])
                elif event == "login_success":
                    alert = self.on_success(key, record["timestamp"])
                else:
                    continue
                if alert is None:
                    continue
                alerts.append(alert)
                if len(alerts) >= MAX_ALERTS_PER_PASS:
                    position = index + 1
                    self.interrupted_passes += 1
                    break
            else:
                position = len(batch)
                self.completed_cycles += 1
                if self.completed_cycles % FORGET_EVERY == 0:
                    self.forget_old_keys(batch[-1]["timestamp"])
            publish(alerts)

    def on_failure(self, key: tuple, moment: datetime) -> dict | None:
        """Ajoute un échec et retire ceux sortis de la fenêtre de temps."""
        failures = self.failures.get(key, [])
        failures.append(moment)
        while moment - failures[0] > self.window:
            failures.pop(0)
        self.failures[key] = failures
        if len(failures) < self.threshold:
            return None
        already_flagged = key in self.flagged
        self.flagged[key] = moment
        if already_flagged:
            return None
        return {
            "rule": self.rule,
            "severity": "HIGH",
            "entity": key[0],
            "timestamp": moment,
            "detail": f"{len(failures)} échecs consécutifs sur {key[1]}",
        }

    def on_success(self, key: tuple, moment: datetime) -> dict | None:
        """Une réussite efface les échecs, mais peut révéler une intrusion."""
        self.failures.pop(key, None)
        flagged_at = self.flagged.pop(key, None)
        if flagged_at is None or moment - flagged_at > self.window * 2:
            return None
        return {
            "rule": self.rule + "_success",
            "severity": "CRITICAL",
            "entity": key[0],
            "timestamp": moment,
            "detail": f"connexion réussie sur {key[1]} après une rafale",
        }

    def forget_old_keys(self, moment: datetime) -> None:
        """Oublie les clés trop anciennes pour que la mémoire reste bornée."""
        limit = moment - self.window * 2
        for key in list(self.failures):
            if self.failures[key][-1] < limit:
                del self.failures[key]
        for key in list(self.flagged):
            if self.flagged[key] < limit:
                del self.flagged[key]
