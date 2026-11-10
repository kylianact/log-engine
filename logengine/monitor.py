"""Suivi en direct : avancement du traitement et RAM, pendant l'analyse.

Toutes les secondes, deux lignes s'affichent. Elles montrent que la RAM reste
stable alors que le nombre de lignes lues augmente : le fichier n'est jamais
chargé en entier.
"""

import time

import psutil

PROCESS = psutil.Process()


def current_ram() -> float:
    """RAM utilisée par le programme en ce moment, en Mo."""
    return PROCESS.memory_info().rss / 1048576


def format_duration(seconds: float) -> str:
    """Écrit une durée en minutes et secondes : 75 donne 1 min 15 s."""
    total = round(seconds)
    minutes = total // 60
    rest = total % 60
    if minutes == 0:
        return f"{rest} s"
    return f"{minutes} min {rest:02d} s"


class LiveMonitor:
    """Mesure la RAM à intervalle régulier et affiche l'avancement.

    every : délai en secondes entre deux mesures.
    total : nombre de lignes attendu, ou 0 s'il est inconnu.
    show  : False avec --show, qui affiche déjà la RAM de chaque ligne.
    """

    def __init__(self, every: float, total: int = 0,
                 show: bool = True) -> None:
        self.every = every
        self.total = total
        self.show = show
        self.started = time.time()
        self.next_check = self.started
        self.last_time = self.started
        self.last_read = 0
        self.peak = 0.0
        self.trace = []

    def check(self, counters: dict, alerts: dict,
              final: bool = False) -> None:
        """Mesure la RAM si le délai est écoulé, et l'affiche.

        counters contient les compteurs du pipeline, alerts le nombre
        d'alertes publiées par règle. final vaut True pour la dernière
        mesure, faite à la fin du fichier sans attendre le délai.
        """
        now = time.time()
        if now < self.next_check and not final:
            return
        self.next_check = now + self.every
        read = counters["funnel"].get("read", 0)
        memory = current_ram()
        self.peak = max(self.peak, memory)
        elapsed = max(now - self.started, 0.001)
        # Débit sur la dernière seconde ; à la fin, débit moyen.
        speed = (read - self.last_read) / max(now - self.last_time, 0.001)
        if final:
            speed = read / elapsed
        self.last_time = now
        self.last_read = read
        self.trace.append(
            {
                "lines": read,
                "memory_mb": round(memory, 1),
                "seconds": round(elapsed, 1),
            }
        )
        if not self.show:
            return
        progress = ""
        if self.total > 0:
            percent = min(100 * read / self.total, 100)
            progress = f"{percent:3.0f} % | "
            if 0 < read < self.total:
                remaining = (self.total - read) * elapsed / read
                progress = f"{percent:3.0f} %, reste "
                progress += f"{format_duration(remaining)} | "
        print(
            f"[{format_duration(elapsed):>10}] {progress}lues {read}"
            f" | {speed:.0f} lignes/s | RAM {memory:.0f} Mo"
            f" (max {self.peak:.0f})"
        )
        rejected = sum(counters["rejects"].values())
        analysed = counters["funnel"].get("analysed", 0)
        # flush=True affiche tout de suite, même si la sortie est redirigée.
        print(
            f"{' ' * 13}analysées {analysed} | rejetées {rejected} | "
            f"alertes {sum(alerts.values())}",
            flush=True,
        )
