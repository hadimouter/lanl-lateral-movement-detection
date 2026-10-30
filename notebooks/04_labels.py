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
    # 04 - Labels

    Un **label**, c'est la bonne réponse qu'on associe à chaque ligne :
    ce couple (utilisateur, jour) était-il compromis, oui ou non ?
    Sans labels, impossible d'entraîner un modèle supervisé (Random Forest)
    ni de mesurer si une méthode détecte quoi que ce soit.

    Règle : un couple (utilisateur, jour) est **compromis** si la red team a
    utilisé ce compte ce jour-là, au moins une fois.
    """)
    return


@app.cell
def _(lanl):
    con = lanl.connect()
    con.execute(f"CREATE VIEW features AS SELECT * FROM '{lanl.FEATURES}'")

    # Événements red team regroupés par (nom du compte sans domaine, jour),
    # comme les variables de l'étape 3
    con.execute("""
        CREATE TABLE redteam_user_day AS
        SELECT
            split_part("user", '@', 1)  AS "user",
            time // 86400               AS day,
            count(*)                    AS n_redteam_events
        FROM redteam
        GROUP BY ALL
    """)
    return (con,)


@app.cell
def _(mo):
    mo.md("""
    ## 1. De 749 événements à des couples (utilisateur, jour)
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            (SELECT count(*) FROM redteam)                  AS nb_evenements,
            (SELECT count(DISTINCT "user") FROM redteam)    AS nb_comptes_avec_domaine,
            count(DISTINCT "user")                          AS nb_comptes_sans_domaine,
            count(*)                                        AS nb_couples_compromis
        FROM redteam_user_day
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    Les 749 événements se regroupent en **176 couples** (utilisateur, jour) :
    la red team utilise souvent un même compte plusieurs fois dans la journée.

    104 comptes deviennent 98 une fois le domaine retiré : la red team a elle-même
    utilisé un même nom sur plusieurs domaines (compte du domaine `DOM1` et
    comptes locaux de machines). Ça confirme le choix de l'étape 3 d'identifier
    un compte par son nom seul.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            split_part("user", '@', 1)  AS compte,
            list(DISTINCT "user")       AS variantes_vues_dans_redteam
        FROM redteam
        GROUP BY compte
        HAVING count(DISTINCT "user") > 1
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    Vérification : chaque couple compromis doit exister dans le tableau des
    variables, sinon on perdrait des attaques.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            count(*)                                    AS nb_couples_compromis,
            count(*) FILTER (WHERE f."user" IS NOT NULL) AS nb_retrouves_dans_features
        FROM redteam_user_day r
        LEFT JOIN features f USING ("user", day)
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## 2. Le déséquilibre

    C'est LE chiffre du projet. Regarde la colonne `un_sur` : il y a un couple
    compromis pour plusieurs milliers de couples normaux. Un modèle qui répondrait
    toujours "normal" aurait raison 99,96 % du temps... et ne servirait à rien.
    C'est pour ça qu'on mesurera le rappel et la précision, jamais l'accuracy.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            count(*)                                        AS nb_couples,
            count(r."user")                                 AS nb_compromis,
            count(*) - count(r."user")                      AS nb_normaux,
            round(100 * count(r."user") / count(*), 3)      AS pct_compromis,
            round(count(*) / count(r."user"))               AS un_sur
        FROM features f
        LEFT JOIN redteam_user_day r USING ("user", day)
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## 3. Quels jours sont compromis ?

    Pour l'étape 5, on entraînera sur certains jours et on testera sur d'autres.
    Il faut des couples compromis des deux côtés : ce tableau dit où ils sont.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            day                         AS jour,
            count(*)                    AS nb_couples_compromis,
            sum(n_redteam_events)       AS nb_evenements_redteam
        FROM redteam_user_day
        GROUP BY day
        ORDER BY day
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## 4. Nos variables distinguent-elles les comptes compromis ?

    Premier aperçu, avant tout modèle : on compare la **médiane** de chaque
    variable chez les couples compromis et chez les normaux. La médiane, c'est
    la valeur du milieu : la moitié des couples est au-dessus, l'autre moitié
    en dessous. On l'utilise plutôt que la moyenne parce qu'elle n'est pas
    déformée par quelques valeurs extrêmes (comme les 9 000 machines de U6836).

    Les deux dernières colonnes donnent la part des couples qui ont au moins
    une machine source jamais vue, et au moins une connexion NTLM.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            CASE WHEN r."user" IS NULL THEN 'normal' ELSE 'compromis' END AS classe,
            count(*)                                AS nb_couples,
            median(n_events)                        AS n_events,
            median(n_dst_pc)                        AS n_dst_pc,
            median(n_src_pc)                        AS n_src_pc,
            median(n_new_dst_pc)                    AS n_new_dst_pc,
            median(n_new_src_pc)                    AS n_new_src_pc,
            round(median(fail_rate), 4)             AS fail_rate,
            round(median(ntlm_share), 3)            AS ntlm_share,
            median(n_rdp)                           AS n_rdp,
            round(median(night_share), 3)           AS night_share,
            median(max_src_users)                   AS max_src_users,
            round(median(max_src_users_ratio), 2)   AS max_src_users_ratio,
            round(median(src_ratio), 2)             AS src_ratio,
            round(median(past_ntlm_share), 3)       AS past_ntlm_share,
            round(avg((n_new_src_pc > 0)::INT), 2)  AS part_new_src,
            round(avg((ntlm_share > 0)::INT), 2)    AS part_ntlm
        FROM features f
        LEFT JOIN redteam_user_day r USING ("user", day)
        GROUP BY classe
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    Ce qu'on lit :

    - **NTLM** : 100 % des couples compromis ont au moins une connexion NTLM,
      contre environ un tiers des normaux. Toutes les connexions red team sont
      en NTLM. C'est compatible avec du pass-the-hash, sans le prouver : le jeu
      de données ne dit pas quelle technique la red team a utilisée, et beaucoup
      de connexions NTLM sont légitimes.
    - **Machine source jamais vue** : environ 8 couples compromis sur 10,
      contre environ 1 normal sur 8. L'attaquant arrive depuis ses propres postes.
    - **Machines touchées** : environ deux fois plus de machines cibles,
      et 6 machines source contre 1.
    - **Machine source partagée** (`max_src_users`) : c'est le signal le plus net.
      Un couple compromis passe par une machine utilisée par une trentaine de
      comptes ce jour-là, contre 1 pour un couple normal. L'attaquant utilise
      ses identifiants volés depuis quelques machines seulement.
    - **Variables relatives** : un compte compromis touche plus de machines
      source que d'habitude (`src_ratio` plus élevé), et sa machine source est
      plus partagée que d'habitude (`max_src_users_ratio`).
    - **Échecs, RDP, nuit** : pas de différence, voire l'inverse pour la nuit
      (la red team agit en journée). Ces variables aideront peu.
    - **Attention** : les comptes compromis sont aussi plus actifs en général
      (`n_events` trois fois plus élevé). La red team a peut-être choisi des
      comptes très utilisés. Un modèle pourrait apprendre "compte actif = suspect",
      ce qui serait un raccourci trompeur.

    Aucune variable ne sépare parfaitement les deux classes : il faudra les
    combiner, c'est le rôle des modèles de l'étape 5.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 5. Les valeurs extrêmes de l'étape 3 étaient-elles des attaques ?

    U6836 (9 000 machines en une journée) et U1718 (des centaines d'échecs par jour) :
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT "user", count(*) AS nb_jours_compromis
        FROM redteam_user_day
        WHERE "user" IN ('U6836', 'U1718')
        GROUP BY "user"
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    Tableau vide : **aucun des deux n'est dans la red team**. Les comportements les
    plus extrêmes du réseau ne sont pas des attaques. Une méthode qui cherche
    simplement "ce qui sort de l'ordinaire" les signalerait en premier : ce
    seraient des faux positifs. C'est un bon avertissement avant l'étape 5.

    Rappel : les labels ne contiennent que ce que la red team a déclaré.
    Un couple marqué "normal" n'est pas garanti sain.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 6. Export du jeu de données final

    Variables de l'étape 3 + deux colonnes :

    - `compromised` : 1 si le couple est compromis, 0 sinon (c'est le label) ;
    - `n_redteam_events` : nombre d'événements red team ce jour-là (0 si aucun),
      pour l'analyse des résultats seulement. **Ne jamais le donner au modèle** :
      il contient la réponse.
    """)
    return


@app.cell
def _(con, lanl):
    con.execute(f"""
        COPY (
            SELECT
                f.*,
                (r."user" IS NOT NULL)::INT         AS compromised,
                coalesce(r.n_redteam_events, 0)     AS n_redteam_events
            FROM features f
            LEFT JOIN redteam_user_day r USING ("user", day)
            ORDER BY f."user", f.day
        ) TO '{lanl.DATASET}' (FORMAT parquet)
    """)
    con.sql(f"""
        SELECT count(*) AS nb_lignes, sum(compromised) AS nb_compromis
        FROM '{lanl.DATASET}'
    """).pl()
    return


if __name__ == "__main__":
    app.run()
