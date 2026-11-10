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
    --show=N              montre N lignes et la raison de leur tri, puis s'arrête
    --show                montre toutes les lignes (lent)
    --only=VALEUR         ne montre qu'une sorte de ligne (voir plus bas)
    --raw                 montre chaque ligne brute pendant l'analyse (lent)
    --raw=1000            montre une ligne brute sur 1000
    --refresh=5           suivi en direct toutes les 5 secondes (1 par défaut)

Autres commandes :

    python main.py                                 démonstration sur le jeu fourni
    python main.py --generate=data/logs/logs.log   génère le fichier de 15 Go
    python main.py --categories                    liste les types et catégories
    python main.py --charts=output                 trace les graphiques
    python main.py --simulate                      analyse un flux simulé
    python main.py --help                          affiche l'aide
    python tests/test_project.py                   lance les tests

## Suivi en direct de la RAM

Pendant une analyse, deux lignes s'affichent chaque seconde : l'avancement,
le débit, la RAM utilisée par le programme et son maximum, puis le nombre de
lignes analysées, rejetées et d'alertes. Quand le fichier vient du générateur,
son manifeste donne le nombre total de lignes : le suivi affiche alors un
pourcentage et le temps restant. Début de l'analyse des 15 Go :

    Suivi en direct de l'avancement et de la RAM, chaque seconde :
    [       0 s]   0 %, reste 27 min 19 s | lues 1037 | 67769 lignes/s | RAM 20 Mo (max 20)
                 analysées 1000 | rejetées 20 | alertes 1
    [       1 s]   0 %, reste 19 min 52 s | lues 94795 | 93469 lignes/s | RAM 38 Mo (max 38)
                 analysées 92000 | rejetées 1794 | alertes 53

La RAM monte au début, quand le programme découvre les adresses IP, puis se
stabilise : sur les 15 Go, elle ne dépasse pas 200 Mo alors que le fichier fait
15 Go. `--refresh=5` espace les mesures, pratique pour une longue analyse. Avec
`--show`, chaque ligne affichée indique la RAM au moment de son traitement.
`--generate` affiche aussi la RAM à la fin de chaque jour généré.

Pour une démonstration de quelques minutes, génère un fichier de 1 Go :

    python main.py --generate=C:\logs\1go\logs.log --size-gb=1
    python main.py --log-file=C:\logs\1go\logs.log --output=C:\logs\1go\resultats

## Montrer le tri ligne par ligne

`--show` affiche dans le terminal ce que le programme fait de chaque ligne. Il
fonctionne sur un petit fichier : afficher 111 millions de lignes prendrait des
jours. On commence par créer un petit fichier en montrant ses 30 premières
lignes, avec le défaut ajouté à chacune :

    python main.py --generate=data/logs/demo/logs.log --size-gb=0.001 --days=1 --show=30

Puis on analyse ce fichier en montrant 30 lignes :

    python main.py --log-file=data/logs/demo/logs.log --output=output/demo --show=30

Chaque ligne affiche son état, son texte, les réparations faites, son fichier
de tri et sa catégorie, avec la raison de chaque décision :

    Ligne 5 [RÉPARÉE]         RAM 17.2 Mo
      lue       : 2026-10-01T00:01:10.449Z | INFO | 010.255.003.032:514/UDP | ...
      réparée   : adresse IP réécrite
      propre    : 2026-10-01T00:01:10.449Z | INFO | 10.255.3.32:514/UDP | ...
      type      : router -> tri/router.log, car le champ service vaut router
      catégorie : network_device, car le texte commence par %, comme un message Cisco

`--only` ne montre qu'une sorte de ligne :

    --only=rejetee            les lignes rejetées et leur motif
    --only=reparee            les lignes réparées
    --only=router             un type de log
    --only=auth_event         une catégorie
    --only=alerte             les lignes qui déclenchent une alerte

Avec `--show`, chaque ligne passe seule dans le pipeline normal. Les résultats
sont les mêmes que sans `--show`, et un test le vérifie.

Pour voir défiler les lignes brutes pendant l'analyse, sans explication, utilise
`--raw`. Chaque ligne est précédée de son numéro dans le fichier :

    python main.py --log-file=data/logs/demo/logs.log --output=output/demo --raw

Sur les 15 Go, montre seulement une partie des lignes. L'analyse garde presque
toute sa vitesse, alors qu'afficher les 111 millions de lignes prendrait des
heures :

    python main.py --log-file=C:\logs\logs.log --output=C:\logs\resultats --raw=1000

Les mots de passe restent masqués à l'écran, comme dans les fichiers produits.

## Types et catégories

Une ligne reçoit deux étiquettes :

- son **type** vient du champ `service`. Il choisit le fichier de `tri/`.
- sa **catégorie** vient de la forme du contenu. Elle est calculée par le
  `match-case` de `route_record`.

`python main.py --categories` affiche la liste complète :

    network_device          texte qui commence par %, comme un message Cisco
    raw_text                texte brut
    connection              connexion (ip, port, protocole)
    connection_sensitive    connexion vers un port sensible
    http_ok, http_4xx, http_5xx    requête web selon son statut
    auth_event              connexion ou déconnexion d'un compte
    user_action             action d'un utilisateur sur une cible
    session_event           autre événement
    machine_metric          mesure CPU, RAM, disque
    threat                  menace trouvée par l'antivirus
    app_error               erreur d'une application

## Place sur le disque

Le fichier de logs fait 15 Go et les fichiers triés environ 15 Go de plus. Il
faut donc prévoir 30 Go libres. `--no-sort` évite les 15 Go du tri. Ne les mets
pas dans un dossier OneDrive : il essaierait de tout synchroniser.

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
        display.py           affichage de chaque ligne et raison du tri
        monitor.py           suivi en direct de l'avancement et de la RAM
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
