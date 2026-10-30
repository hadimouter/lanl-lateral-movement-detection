import marimo

__generated_with = "0.25.2"
app = marimo.App(width="medium")


@app.cell
def _():
    import marimo as mo

    import lanl

    return lanl, mo


@app.cell
def _(mo):
    mo.md("""
    # 01 - Exploration des données LANL

    On regarde les deux fichiers sans jamais charger `auth.txt.gz` en mémoire.
    DuckDB lit le fichier compressé ligne par ligne et ne garde que ce que la
    requête demande (ici 10 lignes, grâce à `LIMIT`).
    """)
    return


@app.cell
def _(lanl):
    # Vues `auth` et `redteam` sur les fichiers .gz (voir notebooks/lanl.py)
    con = lanl.connect()
    return (con,)


@app.cell
def _(mo):
    mo.md("""
    ## Aperçu de `auth` (10 lignes)

    Chaque ligne = une tentative d'authentification : qui (`src_user`) se connecte
    en tant que qui (`dst_user`), depuis quelle machine (`src_pc`) vers quelle
    machine (`dst_pc`), avec quel protocole, et si ça a réussi (`result`).
    Un `?` veut dire "valeur inconnue".
    """)
    return


@app.cell
def _(con):
    con.sql("SELECT * FROM auth LIMIT 10").pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## Tous les événements red team

    Ce sont nos **labels** : les connexions faites par l'équipe d'attaque.
    `time` est en secondes depuis le début de la collecte.
    """)
    return


@app.cell
def _(con):
    con.sql("SELECT * FROM redteam ORDER BY time").pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## Combien d'événements, d'utilisateurs et de machines ?
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            count(*)                AS nb_evenements,
            count(DISTINCT "user")  AS nb_utilisateurs,
            count(DISTINCT src_pc)  AS nb_machines_source,
            count(DISTINCT dst_pc)  AS nb_machines_cible,
            (SELECT count(*) FROM (
                SELECT src_pc FROM redteam UNION SELECT dst_pc FROM redteam
            ))                      AS nb_machines_total
        FROM redteam
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## Quels jours ont lieu les attaques ?

    `time // 86400` donne le numéro du jour (86 400 = secondes dans une journée).
    Ça nous dira plus tard quels jours garder pour l'entraînement et pour le test.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            time // 86400           AS jour,
            count(*)                AS nb_evenements,
            count(DISTINCT "user")  AS nb_utilisateurs,
            min(time)               AS premier_time,
            max(time)               AS dernier_time
        FROM redteam
        GROUP BY jour
        ORDER BY jour
    """).pl()
    return


if __name__ == "__main__":
    app.run()
