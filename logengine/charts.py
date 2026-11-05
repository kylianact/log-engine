"""Graphiques du rapport, tracés avec matplotlib à partir de summary.json."""

import json
import os

import matplotlib.pyplot as plt

COLOR = "#2a6f97"
ALERT_COLOR = "#c8553d"
GRID_COLOR = "#e4e4e4"


def prepare_axes(title: str, ylabel: str) -> tuple:
    """Crée une figure sobre : titre à gauche, grille discrète."""
    figure, axes = plt.subplots(figsize=(8, 3.4))
    axes.set_title(title, loc="left", fontsize=12)
    axes.set_ylabel(ylabel)
    axes.grid(True, axis="y", color=GRID_COLOR)
    axes.set_axisbelow(True)
    axes.spines["top"].set_visible(False)
    axes.spines["right"].set_visible(False)
    return figure, axes


def save_figure(figure: plt.Figure, folder: str, name: str) -> None:
    """Enregistre et ferme une figure."""
    figure.tight_layout()
    figure.savefig(os.path.join(folder, name), dpi=180)
    plt.close(figure)


def draw_memory(summary: dict, folder: str) -> None:
    """RAM utilisée au fil de la lecture."""
    trace = summary["performance"]["memory_trace"]
    lines = [point["lines"] / 1000000 for point in trace]
    memory = [point["memory_mb"] for point in trace]
    figure, axes = prepare_axes("RAM utilisée pendant la lecture", "Mo")
    axes.plot(lines, memory, color=COLOR, linewidth=2)
    axes.set_xlabel("Millions de lignes lues")
    axes.set_ylim(bottom=0)
    save_figure(figure, folder, "ram.png")


def draw_daily(summary: dict, folder: str) -> None:
    """Volume de lignes par jour."""
    by_day = summary["aggregates"]["by_day"]
    days = [day[8:] for day in by_day]
    values = [count / 1000000 for count in by_day.values()]
    figure, axes = prepare_axes("Lignes analysées par jour", "Millions")
    axes.bar(days, values, color=COLOR)
    axes.set_xlabel("Jour d'octobre 2026")
    axes.tick_params(axis="x", labelsize=7)
    save_figure(figure, folder, "jours.png")


def draw_errors(summary: dict, folder: str) -> None:
    """Erreurs par jour."""
    by_day = summary["aggregates"]["errors_by_day"]
    days = [day[8:] for day in by_day]
    values = [count / 1000 for count in by_day.values()]
    figure, axes = prepare_axes("Erreurs par jour", "Milliers")
    axes.plot(days, values, color=ALERT_COLOR, marker="o", linewidth=2)
    axes.set_xlabel("Jour d'octobre 2026")
    axes.set_ylim(bottom=0)
    axes.tick_params(axis="x", labelsize=7)
    save_figure(figure, folder, "erreurs.png")


def draw_hours(summary: dict, folder: str) -> None:
    """Activité par heure."""
    by_hour = summary["aggregates"]["by_hour"]
    hours = [str(hour) for hour in by_hour]
    values = [count / 1000000 for count in by_hour.values()]
    figure, axes = prepare_axes("Activité par heure (UTC)", "Millions")
    axes.bar(hours, values, color=COLOR)
    axes.set_xlabel("Heure")
    save_figure(figure, folder, "heures.png")


def draw_services(summary: dict, folder: str) -> None:
    """Lignes par type de log, de la plus petite à la plus grande."""
    services = sorted(summary["aggregates"]["services"].items(),
                      key=lambda item: item[1])
    names = [item[0] for item in services]
    values = [item[1] / 1000000 for item in services]
    figure, axes = plt.subplots(figsize=(8, 4.2))
    axes.set_title("Lignes analysées par type de log", loc="left",
                   fontsize=12)
    axes.barh(names, values, color=COLOR)
    axes.set_xlabel("Millions de lignes")
    axes.spines["top"].set_visible(False)
    axes.spines["right"].set_visible(False)
    save_figure(figure, folder, "types.png")


def draw_rejects(summary: dict, folder: str) -> None:
    """Lignes rejetées par motif."""
    rejects = sorted(summary["quality"]["rejects"].items(),
                     key=lambda item: item[1])
    names = [item[0] for item in rejects]
    values = [item[1] / 1000 for item in rejects]
    figure, axes = plt.subplots(figsize=(8, 3.4))
    axes.set_title("Lignes rejetées par motif", loc="left", fontsize=12)
    axes.barh(names, values, color=COLOR)
    axes.set_xlabel("Milliers de lignes")
    axes.spines["top"].set_visible(False)
    axes.spines["right"].set_visible(False)
    save_figure(figure, folder, "rejets.png")


def draw_charts(output: str) -> None:
    """Trace tous les graphiques d'une exécution."""
    with open(os.path.join(output, "summary.json"), "r",
              encoding="utf-8") as file:
        summary = json.load(file)
    folder = os.path.join(output, "graphiques")
    os.makedirs(folder, exist_ok=True)
    draw_memory(summary, folder)
    draw_daily(summary, folder)
    draw_errors(summary, folder)
    draw_hours(summary, folder)
    draw_services(summary, folder)
    draw_rejects(summary, folder)
    print(f"Graphiques enregistrés dans {folder}")
