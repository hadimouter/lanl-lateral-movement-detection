import marimo

__generated_with = "0.25.2"
app = marimo.App(width="medium")


@app.cell
def _():
    import time

    import marimo as mo
    import polars as pl

    import lanl

    return lanl, mo, pl, time


@app.cell
def _(mo):
    mo.md("""
    # 03 - Variables par utilisateur et par jour

    Un modèle ne lit pas des logs : il lit un **tableau de nombres**. On résume donc
    l'activité de chaque compte, chaque jour, en une ligne de quelques chiffres
    (les "variables", ou *features*). Une ligne = un couple (utilisateur, jour).

    L'idée : un compte volé et utilisé pour rebondir de machine en machine
    laisse des traces chiffrables. Il touche plus de machines que d'habitude,
    des machines qu'il n'avait jamais vues, avec un protocole inhabituel...

    On part du fichier nettoyé de l'étape 2, `data/auth_users.parquet`.
    """)
    return


@app.cell
def _(lanl):
    con = lanl.connect()
    con.execute(f"CREATE VIEW auth_users AS SELECT * FROM '{lanl.AUTH_USERS}'")
    return (con,)


@app.cell
def _(mo):
    mo.md("""
    ## 1. Où est la nuit ?

    Le dataset ne donne pas l'heure réelle : `time` compte les secondes depuis le
    début de la collecte. `time % 86400` donne la seconde dans la journée, et
    `// 3600` l'heure (0 à 23). On regarde le volume de connexions par heure :
    le creux d'activité, c'est la nuit.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT
            (time % 86400) // 3600      AS heure,
            count(*)                    AS nb_connexions,
            count(DISTINCT src_user)    AS nb_utilisateurs_actifs
        FROM auth_users
        WHERE orientation = 'LogOn'
        GROUP BY heure
        ORDER BY heure
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    L'activité est minimale de 0 h à 5 h et maximale de 8 h à 16 h : le `time = 0`
    du dataset tombe vraisemblablement à minuit. On définit donc la **nuit = 0 h à 5 h**.

    À noter : les connexions red team ont surtout lieu entre 8 h et 22 h
    (tableau ci-dessous). L'activité nocturne risque d'être une variable peu utile
    ici ; on la garde quand même, c'est au modèle de nous le dire.
    """)
    return


@app.cell
def _(con):
    con.sql("""
        SELECT (time % 86400) // 3600 AS heure, count(*) AS nb_evenements_redteam
        FROM redteam
        GROUP BY heure
        ORDER BY heure
    """).pl()
    return


@app.cell
def _(mo):
    mo.md("""
    ## 2. Les variables

    Pour chaque (utilisateur, jour) :

    | Variable | Ce qu'elle mesure | Pourquoi c'est suspect |
    |---|---|---|
    | `n_events` | nombre total d'événements | volume d'activité, sert de repère |
    | `n_logons` | nombre de connexions (LogOn) | |
    | `n_dst_pc` | machines **cibles** distinctes | le mouvement latéral = toucher beaucoup de machines |
    | `n_src_pc` | machines **source** distinctes | se connecter depuis des postes inhabituels |
    | `n_new_dst_pc` | machines cibles **jamais vues** avant pour ce compte | un attaquant explore, un humain retourne aux mêmes serveurs |
    | `n_new_src_pc` | machines source jamais vues avant | la red team part de 4 machines seulement, inconnues des victimes |
    | `n_fails`, `fail_rate` | échecs (nombre et proportion) | mots de passe essayés, accès refusés |
    | `ntlm_share` | part des connexions en NTLM (vs Kerberos) | le pass-the-hash passe par NTLM (T1550.002) |
    | `n_network` | connexions réseau (`Network`) | accès à distance à des partages, des services |
    | `n_rdp` | connexions bureau à distance (`RemoteInteractive`) | prise de main à distance (T1021.001) |
    | `night_share` | part de l'activité entre 0 h et 5 h | activité hors heures de bureau |
    | `max_src_users` | nombre de comptes différents qui se connectent, ce jour-là, depuis la machine source la plus partagée utilisée par ce compte | un poste de travail sert à 1 ou 2 personnes ; un attaquant qui a volé des dizaines d'identifiants les utilise depuis la même machine |

    **Variables relatives** : les variables ci-dessus sont absolues ("15 machines
    aujourd'hui"). Elles ne disent pas si c'est inhabituel **pour ce compte**.
    On ajoute donc des comparaisons avec l'historique du compte :

    | Variable | Ce qu'elle mesure |
    |---|---|
    | `past_active_days` | nombre de jours d'activité avant aujourd'hui (un compte presque dormant qui se réveille) |
    | `past_ntlm_share` | part NTLM habituelle du compte (NTLM aujourd'hui chez un compte qui n'en fait jamais = suspect) |
    | `dst_ratio`, `src_ratio`, `events_ratio` | valeur du jour divisée par la moyenne des jours précédents (+1 pour éviter de diviser par 0) : 1 = comme d'habitude, 5 = cinq fois plus |
    | `max_src_users_ratio` | même idée côté machine : partage de la machine source aujourd'hui, divisé par son partage habituel. Un serveur partagé tous les jours reste à ~1 ; un poste personnel soudain utilisé par 30 comptes monte haut |

    Ces variables ne regardent **que le passé** : en production, le jour J,
    on ne connaît pas encore le jour J+1. Utiliser le futur serait une "fuite"
    qui gonflerait artificiellement les résultats.

    **Attention, effet "premier jour"** : "jamais vue avant" se calcule depuis le
    début des données. Le jour 0, toutes les machines sont nouvelles pour tout le
    monde, et les premiers jours restent gonflés. Il faudra en tenir compte pour
    entraîner les modèles (étape 5), par exemple en écartant le jour 0.
    """)
    return


@app.cell
def _():
    features_sql = """
        WITH ev AS (
            -- Le compte est identifié par son nom seul (U620), quel que soit le domaine
            SELECT *, split_part(src_user, '@', 1) AS user_name FROM auth_users
        ),
        logons AS (
            SELECT * FROM ev WHERE orientation = 'LogOn'
        ),
        -- Premier jour où chaque compte touche chaque machine cible / source
        first_dst AS (
            SELECT user_name, dst_pc, min(day) AS first_day FROM logons GROUP BY ALL
        ),
        first_src AS (
            SELECT user_name, src_pc, min(day) AS first_day FROM logons GROUP BY ALL
        ),
        -- Une machine est "nouvelle" le jour où elle apparaît pour la première fois
        new_dst AS (
            SELECT user_name, first_day AS day, count(*) AS n_new_dst_pc FROM first_dst GROUP BY ALL
        ),
        new_src AS (
            SELECT user_name, first_day AS day, count(*) AS n_new_src_pc FROM first_src GROUP BY ALL
        ),
        daily AS (
            SELECT
                user_name,
                day,
                count(*)                                                        AS n_events,
                count(*) FILTER (WHERE orientation = 'LogOn')                   AS n_logons,
                count(DISTINCT dst_pc) FILTER (WHERE orientation = 'LogOn')     AS n_dst_pc,
                count(DISTINCT src_pc) FILTER (WHERE orientation = 'LogOn')     AS n_src_pc,
                count(*) FILTER (WHERE result = 'Fail')                         AS n_fails,
                avg((result = 'Fail')::INT)                                     AS fail_rate,
                avg((auth_type = 'NTLM')::INT)
                    FILTER (WHERE orientation = 'LogOn' AND auth_type IS NOT NULL) AS ntlm_share,
                count(*) FILTER (WHERE orientation = 'LogOn' AND logon_type = 'Network')           AS n_network,
                count(*) FILTER (WHERE orientation = 'LogOn' AND logon_type = 'RemoteInteractive') AS n_rdp,
                avg(((time % 86400) // 3600 < 6)::INT)                          AS night_share
            FROM ev
            GROUP BY ALL
        ),
        -- Nombre de comptes distincts qui se connectent depuis chaque machine, chaque jour
        -- (hors connexions d'une machine à elle-même)
        src_users AS (
            SELECT day, src_pc, count(DISTINCT user_name) AS n_users_on_src
            FROM logons
            WHERE src_pc <> dst_pc
            GROUP BY ALL
        ),
        -- Partage habituel de chaque machine : moyenne des jours précédents où elle a servi
        src_hist AS (
            SELECT
                *,
                coalesce(avg(n_users_on_src) OVER (
                    PARTITION BY src_pc ORDER BY day ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
                ), 0) AS past_users_on_src
            FROM src_users
        ),
        -- Pour chaque (compte, jour) : la machine source la plus "partagée" qu'il a utilisée,
        -- en absolu et comparée à son partage habituel
        max_src AS (
            SELECT
                l.user_name,
                l.day,
                max(s.n_users_on_src)                                AS max_src_users,
                max(s.n_users_on_src / (s.past_users_on_src + 1))    AS max_src_users_ratio
            FROM (SELECT DISTINCT user_name, day, src_pc FROM logons WHERE src_pc <> dst_pc) l
            JOIN src_hist s USING (day, src_pc)
            GROUP BY ALL
        ),
        base AS (
        SELECT
            d.user_name AS "user",
            d.day,
            d.n_events,
            d.n_logons,
            d.n_dst_pc,
            d.n_src_pc,
            coalesce(nd.n_new_dst_pc, 0)  AS n_new_dst_pc,
            coalesce(ns.n_new_src_pc, 0)  AS n_new_src_pc,
            d.n_fails,
            d.fail_rate,
            coalesce(d.ntlm_share, 0)     AS ntlm_share,
            d.n_network,
            d.n_rdp,
            d.night_share,
            coalesce(ms.max_src_users, 0) AS max_src_users,
            coalesce(ms.max_src_users_ratio, 0) AS max_src_users_ratio
        FROM daily d
        LEFT JOIN new_dst nd USING (user_name, day)
        LEFT JOIN new_src ns USING (user_name, day)
        LEFT JOIN max_src ms USING (user_name, day)
        )
        -- Variables relatives : aujourd'hui comparé aux jours PRÉCÉDENTS du même compte.
        -- La fenêtre `past` ne regarde que le passé (jusqu'à la veille).
        SELECT
            *,
            count(*) OVER past                                       AS past_active_days,
            coalesce(avg(ntlm_share) OVER past, 0)                   AS past_ntlm_share,
            n_dst_pc / (coalesce(avg(n_dst_pc) OVER past, 0) + 1)   AS dst_ratio,
            n_src_pc / (coalesce(avg(n_src_pc) OVER past, 0) + 1)   AS src_ratio,
            n_events / (coalesce(avg(n_events) OVER past, 0) + 1)   AS events_ratio
        FROM base
        WINDOW past AS (PARTITION BY "user" ORDER BY day ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING)
        ORDER BY "user", day
    """
    return (features_sql,)


@app.cell
def _(mo):
    mo.md("""
    Quelques choix :

    - Un compte est identifié par son **nom seul** (`U1718`), sans le domaine.
      Les identifiants LANL sont anonymisés de façon cohérente : `U1718@DOM1`,
      `U1718@?` (domaine inconnu, souvent sur des échecs) et `U1718@C15244`
      (compte local d'une machine) désignent la même personne. Garder le domaine
      éparpillerait l'activité d'un même compte sur plusieurs lignes.
    - `ntlm_share` vaut 0 un jour sans connexion au protocole connu (pas de NTLM vu).
    - Les machines "nouvelles" ne comptent que les connexions (`LogOn`), pas les tickets Kerberos.
    - `coalesce(x, 0)` remplace "rien trouvé" (`NULL`) par 0 : un jour sans nouvelle machine, c'est 0 nouvelle machine.

    Le calcul parcourt les 202 millions de lignes du fichier nettoyé et écrit
    `data/features_user_day.parquet`. Il ne se lance qu'avec le bouton.
    """)
    return


@app.cell
def _(mo):
    compute_button = mo.ui.run_button(label="Calculer les variables")
    compute_button
    return (compute_button,)


@app.cell
def _(compute_button, con, features_sql, lanl, mo, time):
    mo.stop(not compute_button.value)

    _start = time.time()
    con.execute(f"COPY ({features_sql}) TO '{lanl.FEATURES}' (FORMAT parquet)")
    mo.md(f"Calcul terminé en {time.time() - _start:.0f} s.")
    return


@app.cell
def _(mo):
    mo.md("""
    ## 3. À quoi ressemblent les variables ?

    Le tableau des variables est petit (environ 440 000 lignes) : on peut le charger
    entièrement en mémoire avec polars.

    `describe()` donne pour chaque variable la moyenne, l'écart type (`std`),
    le minimum, les quartiles (25 %, 50 % = médiane, 75 %) et le maximum.
    Regarde surtout l'écart entre la médiane et le maximum : quelques comptes
    ont une activité très éloignée de la norme. Ce sont les candidats à surveiller.
    """)
    return


@app.cell
def _(lanl, mo, pl):
    mo.stop(
        not lanl.FEATURES.exists(),
        mo.md("Pas encore de fichier de variables : lance le calcul ci-dessus."),
    )
    features = pl.read_parquet(lanl.FEATURES)
    features
    return (features,)


@app.cell
def _(features):
    features.drop("user").describe()
    return


@app.cell
def _(mo):
    mo.md("""
    Les 10 couples (utilisateur, jour) qui touchent le plus de machines jamais vues,
    hors jour 0 (où tout est nouveau) :
    """)
    return


@app.cell
def _(features, pl):
    features.filter(pl.col("day") > 0).sort("n_new_dst_pc", descending=True).head(10)
    return


@app.cell
def _(mo):
    mo.md("""
    Deux profils ressortent :

    - **U6836, jour 14** : tente de se connecter à plus de 9 000 machines en une
      journée, presque toujours en échec, majoritairement en NTLM. Ça ressemble à
      un balayage du réseau ou à du *password spraying*.
    - **U1718** : échoue sur des centaines de machines **tous les jours**. Un
      comportement chronique ressemble plutôt à un script mal configuré qu'à une
      attaque, et c'est typiquement le genre de compte qui produira des fausses alertes.

    On saura à l'étape 4, avec les labels, si l'un d'eux faisait partie de la red team.
    Une valeur extrême n'est pas forcément une attaque, et une attaque n'est pas
    forcément une valeur extrême : c'est toute la difficulté.
    """)
    return


if __name__ == "__main__":
    app.run()
