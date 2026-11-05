"""Moteur d'analyse de logs en ligne de commande."""

import os
import sys

from logengine.generator import generate_dataset, simulated_stream
from logengine.pipeline import run_pipeline

PROJECT_FOLDER = os.path.dirname(os.path.abspath(__file__))
SAMPLE_FILE = os.path.join(PROJECT_FOLDER, "data", "sample", "logs.log")
SAMPLE_BLACKLIST = os.path.join(PROJECT_FOLDER, "data", "sample",
                                "blacklist.conf")
KNOWN_OPTIONS = (
    "blacklist", "charts", "days", "generate", "help", "max-lines",
    "no-sort", "output", "seed", "simulate", "size-gb",
)
HELP = """Utilisation :

  python main.py --log-file=CHEMIN      analyse et trie un fichier de logs
      --log-file=AUTRE                  ajoute un deuxième fichier
      --output=DOSSIER                  dossier des résultats (défaut : output)
      --blacklist=FICHIER               liste noire (défaut : à côté du log)
      --max-lines=N                     s'arrête après N lignes
      --no-sort                         n'écrit pas les fichiers triés

  python main.py --generate=CHEMIN      génère le fichier de logs
      --size-gb=15                      taille en Go (15 par défaut)
      --days=30                         nombre de jours (30 par défaut)
      --seed=42                         graine aléatoire (42 par défaut)

  python main.py --charts=DOSSIER       trace les graphiques d'une analyse
  python main.py --simulate             analyse un flux simulé, sans fichier
  python main.py                        démonstration sur le jeu de test
"""


def parse_options(arguments: list) -> dict | None:
    """Lit les options --nom=valeur. Retourne None si l'une est inconnue."""
    options = {"log-file": []}
    for argument in arguments:
        name, _, value = argument.removeprefix("--").partition("=")
        if not argument.startswith("--"):
            return None
        if name == "log-file":
            options["log-file"].append(value)
        elif name in KNOWN_OPTIONS:
            options[name] = value
        else:
            return None
    return options


def print_summary(summary: dict) -> None:
    """Affiche l'essentiel d'une exécution."""
    quality = summary["quality"]
    performance = summary["performance"]
    ip_sets = summary["aggregates"]["ip_sets"]
    print("\n=== Résultat ===")
    print(f"Lignes lues      : {quality['funnel'].get('read', 0)}")
    print(f"Lignes analysées : {quality['funnel'].get('analysed', 0)}")
    print(f"Lignes rejetées  : {sum(quality['rejects'].values())}")
    print(f"Durée            : {performance['seconds']} s")
    print(f"Débit            : {performance['lines_per_second']} lignes/s")
    print(f"Pic de RAM       : {performance['peak_memory_mb']} Mo")
    print(
        f"IP actives       : {ip_sets['active']}, "
        f"dont {ip_sets['intersection']} en liste noire"
    )
    if summary["sorted_lines"]:
        print("\nLignes triées par type :")
        for service, count in summary["sorted_lines"].items():
            print(f"  {service:<24}{count}")
    print("\nAlertes par règle :")
    for rule, count in sorted(summary["detection"]["published"].items()):
        print(f"  {rule:<24}{count}")
    if "evaluation" in summary:
        print("\nComparaison avec la vérité terrain :")
        for name, result in summary["evaluation"]["detection"].items():
            print(
                f"  {name:<24}précision {result['precision']}, "
                f"rappel {result['recall']}"
            )


def analyse(options: dict) -> int:
    """Analyse et trie les fichiers donnés avec --log-file."""
    paths = options["log-file"]
    for path in paths:
        if not os.path.isfile(path):
            print(f"Fichier introuvable : {path}")
            return 1
    output = options.get("output") or "output"
    print(f"Analyse de {', '.join(paths)}")
    summary = run_pipeline(
        paths,
        output,
        blacklist_path=options.get("blacklist"),
        max_lines=int(options.get("max-lines", 0)),
        sort_logs="no-sort" not in options,
    )
    print_summary(summary)
    print(f"\nRésultats écrits dans : {output}")
    return 0


def main(arguments: list) -> int:
    """Lance l'action demandée et retourne le code de sortie."""
    options = parse_options(arguments)
    if options is None:
        print(HELP)
        return 1
    if "help" in options:
        print(HELP)
        return 0
    if "generate" in options:
        # 1 Go tel qu'affiché par Windows vaut 1024 ** 3 octets.
        size = float(options.get("size-gb", 15)) * 1024 ** 3
        days = int(options.get("days", 30))
        seed = int(options.get("seed", 42))
        generate_dataset(options["generate"], int(size), days, seed)
        return 0
    if "charts" in options:
        # Import local : matplotlib n'est chargé que pour les graphiques.
        from logengine.charts import draw_charts
        draw_charts(options["charts"])
        return 0
    if "simulate" in options:
        summary = run_pipeline(
            [],
            options.get("output") or "output/simulation",
            lines=simulated_stream(3000),
            blacklist_path=SAMPLE_BLACKLIST,
            sort_logs=False,
        )
        print_summary(summary)
        return 0
    if options["log-file"]:
        return analyse(options)
    print("Démonstration sur le jeu de test fourni")
    options["log-file"] = [SAMPLE_FILE]
    options["output"] = options.get("output") or "output/demo"
    return analyse(options)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ValueError as error:
        print(f"Valeur invalide : {error}")
        sys.exit(1)
    except OSError as error:
        print(f"Erreur de fichier : {error}")
        sys.exit(1)
