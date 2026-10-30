"""Accès aux fichiers LANL avec DuckDB, partagé par tous les notebooks."""

import os
from pathlib import Path

import duckdb

# Dossier des données : data/ à la racine du projet (surchargeable via LANL_DATA_DIR)
DATA_DIR = Path(os.environ.get("LANL_DATA_DIR", Path(__file__).parent.parent / "data"))
AUTH = DATA_DIR / "auth.txt.gz"
REDTEAM = DATA_DIR / "redteam.txt.gz"
AUTH_USERS = DATA_DIR / "auth_users.parquet"
FEATURES = DATA_DIR / "features_user_day.parquet"
DATASET = DATA_DIR / "dataset_user_day.parquet"
SCORES = DATA_DIR / "scores_test.parquet"

# Figures exportées pour l'article (versionnées, contrairement à data/)
FIGURES_DIR = Path(__file__).parent.parent / "article" / "figures"

# Copie publiée du jeu (variables + labels, quelques Mo) : permet de lancer les
# notebooks 05 et 06 sans télécharger les 7 Go de données brutes
SAMPLE_DATASET = Path(__file__).parent.parent / "sample" / "dataset_user_day.parquet"


def dataset_path():
    """Jeu de l'étape 4 : celui de data/ s'il existe, sinon la copie de sample/."""
    return DATASET if DATASET.exists() else SAMPLE_DATASET


# Les fichiers n'ont pas d'en-tête : on donne nous-mêmes le nom et le type des colonnes.
# Ça évite aussi à DuckDB de "deviner" les types en lisant un gros morceau du fichier.
AUTH_COLUMNS = {
    "time": "BIGINT",
    "src_user": "VARCHAR",
    "dst_user": "VARCHAR",
    "src_pc": "VARCHAR",
    "dst_pc": "VARCHAR",
    "auth_type": "VARCHAR",
    "logon_type": "VARCHAR",
    "orientation": "VARCHAR",
    "result": "VARCHAR",
}
REDTEAM_COLUMNS = {
    "time": "BIGINT",
    "user": "VARCHAR",
    "src_pc": "VARCHAR",
    "dst_pc": "VARCHAR",
}


def connect():
    """Connexion DuckDB avec deux vues : `auth` et `redteam`.

    Une vue ne lit rien tout de suite : le fichier n'est parcouru qu'au moment
    où une requête l'interroge, et seulement autant que nécessaire.
    """
    con = duckdb.connect()
    con.execute(f"""
        CREATE VIEW auth AS
        SELECT * FROM read_csv('{AUTH}', header = false, delim = ',', columns = {AUTH_COLUMNS})
    """)
    con.execute(f"""
        CREATE VIEW redteam AS
        SELECT * FROM read_csv('{REDTEAM}', header = false, delim = ',', columns = {REDTEAM_COLUMNS})
    """)
    return con
