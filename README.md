# Moteur de traitement et d'analyse de logs

Projet final Python ING3. Ce programme en ligne de commande lit un très gros
fichier de logs ligne par ligne, le nettoie, trie chaque ligne selon son type,
calcule des statistiques et détecte des attaques, sans jamais charger le
fichier en mémoire.

## Installation

Python 3.10 à 3.14.

    python -m venv .venv
    .venv\Scripts\activate          (Windows)
    source .venv/bin/activate       (Linux, macOS)
    pip install -r requirements.txt

`requirements.txt` vient de `pip freeze`. numpy et contourpy ont deux lignes,
car aucune de leurs versions n'existe à la fois pour Python 3.10 et 3.14.

## Utilisation

Analyser et trier un fichier de logs :

    python main.py --log-file=chemin/vers/logs.log

Options de l'analyse :

    --output=DOSSIER      dossier des résultats (output par défaut)
    --blacklist=FICHIER   liste noire (blacklist.conf à côté du log par défaut)
    --max-lines=N         s'arrête après N lignes
    --no-sort             n'écrit pas les fichiers triés
    --log-file=AUTRE      ajoute un fichier à la suite du premier

Autres commandes :

    python main.py                                 démonstration sur le jeu fourni
    python main.py --generate=data/logs/logs.log   génère le fichier de 15 Go
    python main.py --charts=output                 trace les graphiques
    python main.py --simulate                      analyse un flux simulé
    python main.py --help                          affiche l'aide
    python tests/test_project.py                   lance les tests

## Place sur le disque

Le fichier de logs fait 15 Go et les fichiers triés environ 15 Go de plus. Il
faut donc prévoir 30 Go libres. `--no-sort` évite les 15 Go du tri.

## Format des logs

Un seul fichier contient tous les types de logs, dans l'ordre du temps :

    horodatage | niveau | ip:port/proto | utilisateur | service | payload

Le payload a trois formes :

    {"event":"login_failed","code":401}                   JSON
    conn=(172.16.0.10,443,TCP) action=DENY bytes=60       tuple de connexion
    %LINK-3-UPDOWN: Interface GigabitEthernet0/1, ...     texte brut

## Types de logs

    Réseau        router, switch, firewall, wifi, dns, dhcp, vpn
    Connexions    auth, web
    Actions       action
    Machines      machine, system, antivirus
    Applications  app, database, mail

## Organisation

    main.py                  ligne de commande
    logengine/
        config.py            constantes et seuils
        generator.py         générateur de logs sales et variés
        ingestion.py         module 1 : yield et yield from
        parsing.py           module 1 : ligne vers dictionnaire
        transform.py         module 2 : map, filter, lambda, match-case
        aggregation.py       module 3 : set, frozenset, defaultdict
        bruteforce.py        module 3 : while, for, break, continue, else
        rules.py             module 4 : apply_security_rules(*args, **kwargs)
        audit.py             module 4 : globals() et locals()
        sorting.py           tri des lignes par type
        pipeline.py          enchaînement des étapes
        evaluation.py        comparaison avec la vérité terrain
        charts.py            graphiques matplotlib
    data/sample/             jeu de test fourni
    tests/                   tests du projet
    docs/rapport.pdf         rapport final

## Fichiers produits par une analyse

    tri/router.log, ...      lignes nettoyées, un fichier par type de log
    bad_lines.log            lignes rejetées, avec le motif du rejet
    alerts.jsonl             alertes de sécurité, une par ligne
    summary.json             tous les résultats
    hourly_summary.csv       activité par heure
    audit.json               variables en mémoire à la fin de l'exécution
    graphiques/              images créées par --charts

## Vérité terrain

Le générateur écrit `manifest.json` à côté du fichier de logs : le nombre exact
de défauts injectés et la liste des attaquants. Le pipeline compare ses
résultats à ce fichier, ce qui vérifie le nettoyage et la détection sur une
base connue.
