import marimo

__generated_with = "0.25.2"
app = marimo.App(width="medium")


@app.cell
def _():
    from pathlib import Path

    import marimo as mo
    import polars as pl

    import lanl

    DETECTION_DIR = Path(lanl.__file__).parent.parent / "detection"
    return DETECTION_DIR, lanl, mo, pl


@app.cell
def _(mo):
    mo.md("""
    # 07 - Du notebook au SOC

    Un modèle dans un notebook ne protège personne. Cette étape traduit le travail
    en éléments utilisables par une équipe de détection :

    1. le **mapping MITRE ATT&CK** : quelles techniques d'attaque on couvre, et lesquelles non ;
    2. des **règles KQL pour Microsoft Sentinel**, la traduction des règles de l'étape 5 ;
    3. une **vérification** : la logique des règles KQL, rejouée sur les données LANL,
       donne-t-elle les résultats attendus ?

    Les fichiers produits sont dans `detection/`.
    """)
    return


@app.cell
def _(DETECTION_DIR, mo):
    mo.md((DETECTION_DIR / "mitre_mapping.md").read_text())
    return


@app.cell
def _(mo):
    mo.md(r"""
    ## Les règles Sentinel

    Trois fichiers dans `detection/sentinel/` :

    | Fichier | Rôle |
    |---|---|
    | `shared_source_ntlm.yaml` | règle planifiée : compte en NTLM depuis une machine partagée par au moins 10 comptes (règle 2) |
    | `new_source_ntlm.yaml` | règle planifiée : compte en NTLM depuis une machine jamais vue en 14 jours (règle 1) |
    | `hunting_account_day_features.kql` | requête de chasse : les variables principales du modèle, par compte, sur 24 h |

    Les deux `.yaml` suivent le format du dépôt communautaire Azure-Sentinel
    (fréquence, période, tactiques, techniques, entités). Pour les importer par le
    portail (Analytics > Import), il faut les convertir en modèle ARM au format JSON.

    Choix de conception, valables dans un vrai Active Directory :

    - **exécution quotidienne** : un compte remonte au plus une fois par jour ;
    - **compte = `domaine\compte`** : sans le domaine, les comptes locaux
      "Administrator" de toutes les machines seraient confondus ;
    - **machine source = adresse IP** : en NTLM, le nom de poste (`WorkstationName`)
      est déclaré par le client, donc falsifiable par un attaquant ;
    - **types de connexion 3 et 10** seulement (réseau et bureau à distance).

    Voici la règle principale :
    """)
    return


@app.cell
def _(DETECTION_DIR, mo):
    mo.md(f"```yaml\n{(DETECTION_DIR / 'sentinel' / 'shared_source_ntlm.yaml').read_text()}```")
    return


@app.cell
def _(mo):
    mo.md("""
    ## Vérification : la logique KQL rejouée sur LANL

    On n'a pas de Sentinel sous la main, mais on peut traduire chaque requête KQL
    en SQL et l'exécuter sur les données LANL. Différences avec les règles
    de l'étape 5 :

    - Windows sépare les connexions **réussies** (événement 4624) et **échouées**
      (4625). La règle 2 compte les deux pour mesurer le partage d'une machine
      (un attaquant qui essaie des identifiants la rend "partagée" même quand il
      échoue), mais n'exige une connexion NTLM **réussie** que pour le compte alerté.
    - La règle 1 compare à une référence glissante des **14 jours précédents**,
      au lieu de "jamais vue depuis le début des données".
    - Le compte est identifié avec son domaine (`U1718@DOM1` et `U1718@C15244` sont
      deux comptes), seuls les types de connexion réseau et bureau à distance
      comptent, et la machine source LANL (`src_pc`) joue le rôle de l'adresse IP.
    - Le KQL tourne une fois par jour ; ici, chaque jour du dataset est traité à part.

    Pour comparer avec les labels, les alertes sont ramenées au couple
    (nom du compte, jour) : « alertes par jour » compte ces couples.

    Première ligne du tableau : la logique exacte de l'étape 5, réécrite dans la
    même forme. Elle doit redonner les mêmes chiffres, c'est le contrôle que la
    traduction est correcte.
    """)
    return


@app.cell
def _(lanl, mo):
    mo.stop(
        not lanl.AUTH_USERS.exists(),
        mo.md("Vérification non disponible : elle demande les données brutes (étape 2)."),
    )
    con = lanl.connect()
    # Connexions (LogOn) des jours 1 à 29. Deux identités de compte :
    # - account : le nom seul (U1718), comme dans les étapes 3 à 6 et les labels ;
    # - account_full : nom + domaine (U1718@DOM1), comme domaine\\compte dans Sentinel.
    con.execute(f"""
        CREATE TABLE logons AS
        SELECT
            day,
            split_part(src_user, '@', 1) AS account,
            src_user AS account_full,
            src_pc,
            dst_pc,
            auth_type,
            logon_type,
            result
        FROM '{lanl.AUTH_USERS}'
        WHERE orientation = 'LogOn' AND day BETWEEN 1 AND 29
    """)
    con.execute(f"""CREATE VIEW labels AS SELECT "user" AS account, day, compromised FROM '{lanl.dataset_path()}'""")
    return (con,)


@app.cell
def _():
    # Règle 2, logique de l'étape 5 : partage et NTLM comptés sur toutes les connexions
    rule_2_step5 = """
        WITH remote AS (SELECT * FROM logons WHERE src_pc <> dst_pc),
        shared AS (SELECT day, src_pc FROM remote GROUP BY ALL HAVING count(DISTINCT account) >= 10),
        ntlm AS (SELECT DISTINCT day, account FROM logons WHERE auth_type = 'NTLM')
        SELECT DISTINCT r.day, r.account
        FROM remote r JOIN shared USING (day, src_pc) JOIN ntlm USING (day, account)
    """

    # Traduction des règles KQL : types de connexion 3 et 10 (réseau, bureau à distance),
    # compte identifié avec son domaine, machine source = src_pc (l'adresse IP dans Sentinel).
    # Les alertes sont ensuite ramenées au nom seul pour être comparées aux labels.
    _types = "logon_type IN ('Network', 'RemoteInteractive')"

    # Règle 2 : partage compté sur 4624 + 4625, NTLM exigé sur 4624 seulement
    rule_2_kql = f"""
        WITH lt AS (SELECT * FROM logons WHERE {_types}),
        remote AS (SELECT * FROM lt WHERE src_pc <> dst_pc),
        shared AS (SELECT day, src_pc FROM remote GROUP BY ALL HAVING count(DISTINCT account_full) >= 10),
        ntlm AS (SELECT DISTINCT day, account_full FROM lt WHERE auth_type = 'NTLM' AND result = 'Success')
        SELECT DISTINCT r.day, r.account
        FROM remote r JOIN shared USING (day, src_pc) JOIN ntlm USING (day, account_full)
    """

    # Règle 1 : connexions réussies, référence des 14 jours précédents
    rule_1_kql = f"""
        WITH remote AS (
            SELECT DISTINCT day, account, account_full, src_pc FROM logons
            WHERE src_pc <> dst_pc AND result = 'Success' AND {_types}
        ),
        ntlm AS (
            SELECT DISTINCT day, account_full FROM logons
            WHERE auth_type = 'NTLM' AND result = 'Success' AND {_types}
        )
        SELECT DISTINCT t.day, t.account
        FROM remote t JOIN ntlm USING (day, account_full)
        WHERE NOT EXISTS (
            SELECT 1 FROM remote b
            WHERE b.account_full = t.account_full AND b.src_pc = t.src_pc
              AND b.day BETWEEN t.day - 14 AND t.day - 1
        )
    """
    return rule_1_kql, rule_2_kql, rule_2_step5


@app.cell
def _(con, pl, rule_1_kql, rule_2_kql, rule_2_step5):
    def _evaluate(name, query):
        # Alertes des jours de test (15 à 29) croisées avec les labels
        _row = con.sql(f"""
            SELECT
                count(*)                            AS nb_alertes,
                sum(coalesce(l.compromised, 0))     AS vp,
                (SELECT sum(compromised) FROM labels WHERE day BETWEEN 15 AND 29) AS nb_attaques
            FROM ({query}) a
            LEFT JOIN labels l USING (account, day)
            WHERE a.day BETWEEN 15 AND 29
        """).fetchall()[0]
        return {
            "regle": name,
            "alertes_par_jour": round(_row[0] / 15),
            "attaques_attrapees": f"{int(_row[1])} / {int(_row[2])}",
            "rappel": round(_row[1] / _row[2], 2),
            "precision": round(_row[1] / _row[0], 3),
        }

    pl.DataFrame([
        _evaluate("règle 2, logique de l'étape 5 (contrôle)", rule_2_step5),
        _evaluate("règle 2, version KQL", rule_2_kql),
        _evaluate("règle 1, version KQL (référence 14 jours)", rule_1_kql),
    ])
    return


@app.cell
def _(mo):
    mo.md("""
    Lecture :

    - **Contrôle** : 246 alertes par jour et 38 attaques, exactement les chiffres
      de l'étape 5. La traduction est fidèle.
    - **Règle 2 en KQL** : les mêmes 38 attaques avec 206 alertes par jour au lieu
      de 246. Exiger une connexion NTLM *réussie* écarte des comptes qui n'ont fait
      qu'échouer, et ne garder que les connexions réseau et bureau à distance
      retire du bruit.
    - **Règle 1 en KQL** : 32 attaques au lieu de 23, avec moins d'alertes (302 au
      lieu de 403). Une référence glissante de 14 jours fonctionne mieux que "jamais
      vue depuis le début" : une machine utilisée il y a un mois redevient "nouvelle".

    Les deux règles restent trop bruyantes pour une alerte directe (200 à 300 par
    jour). En production, on les combinerait : liste d'exclusion des serveurs
    partagés légitimes, corrélation des deux règles, ou score du Random Forest
    pour classer les alertes et n'en remonter que les 10 à 20 premières par jour.

    **Limite** : ces règles n'ont pas été exécutées sur un vrai Sentinel. La
    syntaxe suit la documentation KQL et le schéma de `SecurityEvent`, mais il
    faut les valider sur un espace de travail réel avant de les activer.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## Résumé des résultats

    Les chiffres clés du projet, repris dans le README et l'article.
    """)
    return


@app.cell
def _(lanl, pl):
    import numpy as np
    from sklearn.metrics import average_precision_score

    _scores = pl.read_parquet(lanl.SCORES)
    _y = _scores["compromised"].to_numpy()
    _rf = _scores["score_rf"].to_numpy()
    _days = _scores["day"].to_numpy()

    def _at_budget(per_day):
        # Les per_day couples les plus suspects de chaque jour
        _alert = np.zeros(len(_y), dtype=bool)
        for _d in np.unique(_days):
            _idx = np.flatnonzero(_days == _d)
            _alert[_idx[np.argsort(-_rf[_idx], kind="stable")[:per_day]]] = True
        _tp = int((_alert & (_y == 1)).sum())
        return f"rappel {_tp / _y.sum():.2f}, précision {_tp / _alert.sum():.3f}"

    pl.DataFrame({
        "indicateur": [
            "Événements d'authentification analysés",
            "Couples (utilisateur, jour) après nettoyage",
            "Couples compromis (labels red team)",
            "Couples compromis sur la période de test (jours 15-29)",
            "Précision moyenne du Random Forest (hasard = 0,0004)",
            "Random Forest, 10 alertes par jour (tri jour par jour)",
            "Random Forest, 100 alertes par jour (tri jour par jour)",
        ],
        "valeur": [
            "1 051 430 459",
            "440 972",
            "176",
            f"{int(_y.sum())} sur {len(_y):,}".replace(",", " "),
            f"{average_precision_score(_y, _rf):.3f}",
            _at_budget(10),
            _at_budget(100),
        ],
    })
    return


if __name__ == "__main__":
    app.run()
