import marimo

__generated_with = "0.25.2"
app = marimo.App(width="medium")


@app.cell
def _():
    import time

    import marimo as mo

    import lanl

    return lanl, mo, time


@app.cell
def _(mo):
    mo.md("""
    # 02 - Nettoyage

    Le but : ne garder que ce qui décrit le comportement des **personnes**,
    puisque c'est un compte humain volé qu'on cherche. Quatre décisions :

    1. garder seulement les comptes utilisateurs (pas les machines ni les comptes système) ;
    2. retirer les déconnexions (`LogOff`), qui n'apportent rien de plus que la connexion ;
    3. remplacer les `?` par une vraie valeur "inconnue" (`NULL`) ;
    4. vérifier qu'aucune attaque red team n'a été perdue au passage.

    Les explorations tournent sur un **échantillon** (10 millions de lignes,
    environ la première journée). Seul l'export final parcourt le fichier entier.
    """)
    return


@app.cell
def _(lanl):
    con = lanl.connect()

    # Échantillon chargé une fois en mémoire : ~10 M lignes, quelques secondes
    con.execute("CREATE TABLE sample AS SELECT * FROM auth LIMIT 10_000_000")

    # Une "macro" = une petite fonction SQL réutilisable.
    # Un compte s'écrit nom@domaine ; c'est le nom qui dit de quel type de compte il s'agit.
    con.execute("""
        CREATE MACRO account_category(u) AS CASE
            WHEN split_part(u, '@', 1) LIKE '%$' THEN 'machine'
            WHEN regexp_matches(split_part(u, '@', 1), '^U[0-9]+$') THEN 'utilisateur'
            ELSE 'systeme'
        END
    """)
    return (con,)


@app.cell
def _(mo):
    mo.md("""
    ## 1. Trois familles de comptes

    - **utilisateur** (`U620@DOM1`) : une personne. C'est ce qu'on surveille.
    - **machine** (`C101$@DOM1`, le `$` final) : un ordinateur qui s'authentifie
      tout seul (mises à jour, partages réseau...). Très bavard, peu intéressant ici.
    - **système** (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`) :
      comptes intégrés à Windows, utilisés par les services.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            account_category(src_user)                     AS categorie,
            count(*)                                       AS nb_evenements,
            round(100 * count(*) / sum(count(*)) OVER (), 1) AS pct,
            count(DISTINCT split_part(src_user, '@', 1))   AS nb_comptes
        FROM sample
        GROUP BY categorie
        ORDER BY nb_evenements DESC
    """).pl()
    return


@app.cell
def _(con):
    # Liste exhaustive des comptes "système" vus dans l'échantillon
    con.sql("""
        SELECT split_part(src_user, '@', 1) AS compte, count(*) AS nb_evenements
        FROM sample
        WHERE account_category(src_user) = 'systeme'
        GROUP BY compte
        ORDER BY nb_evenements DESC
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## 2. D'où viennent les `?`

    Le tableau croise le type d'événement (`orientation`) avec la présence d'un `?`
    dans le protocole (`auth_type`). Presque tous les `?` sont sur des événements
    où la question n'a **pas de sens** : une déconnexion (`LogOff`) ou une demande
    de ticket Kerberos (`TGS`, `TGT`) n'a pas de "protocole de connexion".
    Ce ne sont donc pas des erreurs, juste des champs sans objet.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            orientation,
            count(*)                                    AS nb_evenements,
            count(*) FILTER (WHERE auth_type = '?')     AS auth_type_inconnu,
            count(*) FILTER (WHERE logon_type = '?')    AS logon_type_inconnu
        FROM sample
        GROUP BY orientation
        ORDER BY nb_evenements DESC
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    **Décisions :**

    - On retire les `LogOff` : chaque déconnexion répond à une connexion déjà
      présente, elles sont toujours en `Success` et n'ont jamais de protocole.
      C'est environ 40 % des lignes en moins, sans perte d'information.
    - On **garde** `TGT` et `TGS` (tickets Kerberos) : c'est là que se trouvent
      la plupart des échecs d'authentification (mauvais mot de passe), utiles à l'étape 3.
    - Les `?` restants deviennent `NULL`. En SQL, `NULL` veut dire "pas d'information" :
      les fonctions comme `count(auth_type)` l'ignorent automatiquement, alors
      qu'un `?` serait compté comme un protocole à part entière.
    - Le protocole `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` apparaît parfois tronqué
      (`MICROSOFT_AUTHENTICATION_PACK`, ...) : on remet le nom complet.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT auth_type, count(*) AS nb_evenements
        FROM sample
        WHERE auth_type LIKE 'MICROSOFT_AUTH%'
        GROUP BY auth_type
        ORDER BY nb_evenements DESC
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## 3. Les attaques survivent-elles au nettoyage ?

    Si les comptes red team étaient des comptes machine, le filtre les ferait
    disparaître et on n'aurait plus rien à détecter. On vérifie sur le fichier
    `redteam` complet (749 lignes, lecture instantanée).
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT account_category("user") AS categorie, count(*) AS nb_evenements
        FROM redteam
        GROUP BY categorie
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## 4. Export du fichier nettoyé

    La requête ci-dessous applique toutes les décisions. Le résultat est écrit en
    **Parquet** : un format en colonnes, compressé, que DuckDB et polars lisent
    beaucoup plus vite qu'un `.gz` (il peut ne lire que les colonnes demandées).
    Les étapes suivantes partiront de ce fichier, `data/auth_users.parquet`.

    L'export parcourt le milliard de lignes (1 à 3 minutes) : il ne se lance
    qu'en cliquant sur le bouton.
    """)
    return


@app.cell
def _():
    clean_sql = """
        SELECT
            time,
            time // 86400 AS day,
            src_user,
            dst_user,
            src_pc,
            dst_pc,
            CASE
                WHEN auth_type LIKE 'MICROSOFT_AUTH%' THEN 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'
                ELSE nullif(auth_type, '?')
            END AS auth_type,
            nullif(logon_type, '?') AS logon_type,
            orientation,
            result
        FROM auth
        WHERE account_category(src_user) = 'utilisateur'
          AND orientation <> 'LogOff'
    """
    return (clean_sql,)


@app.cell
def _(mo):
    export_button = mo.ui.run_button(label="Lancer l'export complet")
    export_button
    return (export_button,)


@app.cell
def _(clean_sql, con, export_button, lanl, mo, time):
    mo.stop(not export_button.value)

    _start = time.time()
    con.execute(f"COPY ({clean_sql}) TO '{lanl.AUTH_USERS}' (FORMAT parquet, COMPRESSION zstd)")
    mo.md(f"Export terminé en {time.time() - _start:.0f} s.")
    return


@app.cell
def _(mo):
    mo.md("""
    ## 5. Vérification du fichier nettoyé

    Ces cellules lisent `auth_users.parquet` s'il existe déjà.
    Le test le plus important : retrouver les **749** événements red team.
    """)
    return


@app.cell
def _(con, lanl, mo):
    mo.stop(
        not lanl.AUTH_USERS.exists(),
        mo.md("Pas encore de fichier nettoyé : lance l'export ci-dessus."),
    )
    con.execute(f"CREATE OR REPLACE VIEW auth_users AS SELECT * FROM '{lanl.AUTH_USERS}'")
    con.sql("""
        SELECT
            count(*)                    AS nb_evenements,
            count(DISTINCT src_user)    AS nb_utilisateurs,
            min(day)                    AS premier_jour,
            max(day)                    AS dernier_jour,
            count(*) FILTER (WHERE auth_type IS NULL)  AS auth_type_null,
            count(*) FILTER (WHERE logon_type IS NULL) AS logon_type_null
        FROM auth_users
    """).pl()
    return


@app.cell
def _(con, lanl, mo):
    mo.stop(not lanl.AUTH_USERS.exists())
    con.sql("""
        SELECT
            orientation,
            count(*)                                  AS nb_evenements,
            count(*) FILTER (WHERE result = 'Fail')   AS nb_echecs
        FROM auth_users
        GROUP BY orientation
        ORDER BY nb_evenements DESC
    """).pl()
    return


@app.cell
def _(con, lanl, mo):
    mo.stop(not lanl.AUTH_USERS.exists())
    # Un événement red team est retrouvé si une ligne a le même instant,
    # le même compte et la même machine source. On compte à part ceux dont
    # la machine cible correspond aussi.
    con.sql("""
        SELECT
            count(*)                                   AS nb_redteam,
            count(*) FILTER (WHERE trouve)             AS nb_retrouves,
            count(*) FILTER (WHERE meme_cible)         AS nb_meme_machine_cible
        FROM (
            SELECT
                EXISTS (
                    SELECT 1 FROM auth_users a
                    WHERE a.time = r.time AND a.src_user = r."user"
                      AND a.src_pc = r.src_pc AND a.orientation = 'LogOn'
                ) AS trouve,
                EXISTS (
                    SELECT 1 FROM auth_users a
                    WHERE a.time = r.time AND a.src_user = r."user"
                      AND a.src_pc = r.src_pc AND a.dst_pc = r.dst_pc
                ) AS meme_cible
            FROM redteam r
        )
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    Les 749 attaques sont bien dans le fichier nettoyé. Mais pour 14 d'entre elles,
    la machine cible ne porte pas le même nom dans `redteam` et dans `auth`
    (par exemple `C21814` côté redteam, `C14319` côté auth), toujours de façon
    cohérente. C'est une incohérence du dataset, pas du nettoyage : la connexion
    existe avec le même instant, le même compte et la même machine source.

    Conséquence pour la suite : pour relier les labels aux logs, on se basera sur
    le compte et le jour (étape 4), pas sur la machine cible.
    """)
    return


if __name__ == "__main__":
    app.run()
