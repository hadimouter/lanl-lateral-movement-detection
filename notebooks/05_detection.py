import marimo

__generated_with = "0.25.2"
app = marimo.App(width="medium")


@app.cell
def _():
    import altair as alt
    import marimo as mo
    import numpy as np
    import polars as pl
    from sklearn.cluster import KMeans
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    import lanl

    return (
        IsolationForest,
        KMeans,
        StandardScaler,
        alt,
        lanl,
        mo,
        np,
        pl,
    )


@app.cell
def _(mo):
    mo.md("""
    # 05 - Détection

    Quatre méthodes, de la plus simple à la plus élaborée :

    | Méthode | Type | Utilise les labels ? |
    |---|---|---|
    | Règles simples | écrites à la main par un analyste | non (sauf pour régler un seuil) |
    | Random Forest | **supervisée** : apprend à partir d'exemples étiquetés | oui |
    | Isolation Forest | **non supervisée** : cherche ce qui est rare | non |
    | k-means | **non supervisée** : cherche ce qui ne ressemble à aucun groupe | non |

    Chaque méthode donne un **score** à chaque couple (utilisateur, jour) :
    plus il est élevé, plus le couple est suspect. Ici on entraîne et on calcule
    les scores ; l'évaluation détaillée (rappel, précision, seuils) est l'étape 6.
    """)
    return


@app.cell
def _(lanl, pl):
    dataset = pl.read_parquet(lanl.dataset_path())

    # Les variables données aux modèles. On exclut `user` et `day` (des identifiants,
    # pas des comportements), `compromised` (la réponse) et `n_redteam_events`
    # (qui contient la réponse : ce serait tricher).
    BASE_FEATURES = [
        "n_events",
        "n_logons",
        "n_dst_pc",
        "n_src_pc",
        "n_new_dst_pc",
        "n_new_src_pc",
        "n_fails",
        "fail_rate",
        "ntlm_share",
        "n_network",
        "n_rdp",
        "night_share",
    ]
    # Ajoutées après une première version du projet (voir section 5) :
    # partage de la machine source et comparaison avec l'historique du compte
    NEW_FEATURES = [
        "max_src_users",
        "max_src_users_ratio",
        "past_active_days",
        "past_ntlm_share",
        "dst_ratio",
        "src_ratio",
        "events_ratio",
    ]
    FEATURES = BASE_FEATURES + NEW_FEATURES
    return BASE_FEATURES, FEATURES, dataset


@app.cell
def _(mo):
    mo.md("""
    ## 1. Découpage par jours : entraînement, validation, test

    - **Entraînement : jours 1 à 10.** Les modèles apprennent sur ces jours.
    - **Validation : jours 11 à 14.** On y compare les variantes et on y fait les
      choix (quelles variables garder). C'est le "brouillon" de l'examen.
    - **Test : jours 15 à 29.** Consulté une seule fois, à la fin, pour la note
      finale. Le modèle final est réentraîné sur les jours 1 à 14 avant ce test.

    Pourquoi par jours et pas au hasard ? En vrai, on entraîne sur le passé et on
    détecte dans le futur. Mélanger les jours laisserait le modèle "voir" des
    morceaux d'une attaque à l'entraînement et les reconnaître au test : le score
    serait trop beau.

    On écarte le **jour 0** (toutes les machines y sont "jamais vues", voir étape 3)
    et les **jours 30 à 57** (aucune activité red team, donc rien à trouver ni à apprendre).
    """)
    return


@app.cell
def _(dataset, pl):
    fit_part = dataset.filter(pl.col("day").is_between(1, 10))
    valid = dataset.filter(pl.col("day").is_between(11, 14))
    # Entraînement final (entraînement + validation), une fois les choix faits
    train = dataset.filter(pl.col("day").is_between(1, 14))
    test = dataset.filter(pl.col("day").is_between(15, 29))

    pl.DataFrame({
        "jeu": [
            "entraînement (jours 1-10)",
            "validation (jours 11-14)",
            "entraînement final (jours 1-14)",
            "test (jours 15-29)",
        ],
        "nb_couples": [fit_part.height, valid.height, train.height, test.height],
        "nb_compromis": [
            fit_part["compromised"].sum(),
            valid["compromised"].sum(),
            train["compromised"].sum(),
            test["compromised"].sum(),
        ],
    })
    return fit_part, test, train, valid


@app.cell
def _(FEATURES, test, train):
    # scikit-learn travaille sur des tableaux de nombres (numpy) :
    # X = les variables, y = la réponse (0 ou 1)
    X_train = train.select(FEATURES).to_numpy()
    y_train = train["compromised"].to_numpy()
    X_test = test.select(FEATURES).to_numpy()
    y_test = test["compromised"].to_numpy()
    return X_test, X_train, y_test, y_train


@app.cell
def _(mo):
    mo.md("""
    ## 2. Méthode 1 : des règles simples

    Ce qu'écrirait un analyste SOC. Pas d'apprentissage : la règle dit oui (1)
    ou non (0). C'est la référence à battre : un modèle compliqué qui ne fait pas
    mieux qu'une règle de deux lignes ne vaut pas sa complexité.

    **Règle 1** (indices de pass-the-hash et de mouvement latéral) :

    > Alerte si, dans la journée, le compte se connecte depuis au moins une
    > machine jamais vue ET utilise NTLM.

    **Règle 2** (identifiants volés utilisés depuis une même machine) :

    > Alerte si le compte se connecte depuis une machine utilisée par au moins
    > N comptes différents ce jour-là ET utilise NTLM.

    Pour la règle 2, il faut choisir N. On le choisit **sur les jours 1 à 14**
    (entraînement et validation), jamais sur le test : regarder le test pour
    régler un seuil, ce serait tricher, le seuil serait optimisé pour ces jours précis.
    """)
    return


@app.function
def rule_table(df, rules, n_days):
    """Pour chaque règle (nom -> masque booléen) : nombre d'alertes et d'attaques attrapées."""
    import polars as pl

    return pl.DataFrame([
        {
            "regle": name,
            "nb_alertes": int(mask.sum()),
            "alertes_par_jour": round(int(mask.sum()) / n_days),
            "vraies_attaques": int(df.filter(mask)["compromised"].sum()),
            "attaques_au_total": int(df["compromised"].sum()),
        }
        for name, mask in rules.items()
    ])


@app.cell
def _(pl, train):
    # Choix du seuil N sur les jours 1 à 14 (entraînement + validation)
    rule_table(
        train,
        {
            f"machine partagée >= {n} comptes + NTLM": (train["max_src_users"] >= n) & (train["ntlm_share"] > 0)
            for n in (3, 5, 10, 20)
        },
        n_days=14,
    ).with_columns(pl.lit("jours 1-14").alias("jeu"))
    return


@app.cell
def _(mo):
    mo.md("""
    Avec N = 10, on garde presque toutes les attaques des jours 1 à 14
    (114 sur 129) avec nettement moins d'alertes qu'avec N = 3 ou 5. Au-delà,
    on perd trop d'attaques. On fixe **N = 10**, puis on applique les deux règles
    sur les jours de test :
    """)
    return


@app.cell
def _(pl, test):
    rule_1 = (test["n_new_src_pc"] > 0) & (test["ntlm_share"] > 0)
    rule_2 = (test["max_src_users"] >= 10) & (test["ntlm_share"] > 0)
    score_rule_1 = rule_1.cast(pl.Int8).to_numpy()
    score_rule_2 = rule_2.cast(pl.Int8).to_numpy()

    rule_table(
        test,
        {"règle 1 : machine source jamais vue + NTLM": rule_1, "règle 2 : machine partagée >= 10 + NTLM": rule_2},
        n_days=15,
    )
    return score_rule_1, score_rule_2


@app.cell
def _(mo):
    mo.md("""
    La règle 2 attrape bien plus d'attaques que la règle 1, avec moins d'alertes.
    Mais elle reste à plus de 200 alertes par jour : trop pour une équipe SOC.
    Beaucoup de machines sont **légitimement** partagées (serveurs, postes en
    libre-service) et déclenchent la règle tous les jours.

    ### Le piège de l'historique contaminé

    Idée naturelle : ne plus regarder le partage absolu, mais le partage
    **comparé à l'habitude de la machine** (`max_src_users_ratio`). Un serveur
    partagé tous les jours reste à ~1, un poste personnel soudain partagé par
    30 comptes monte très haut. Sur les jours 1 à 14, c'est spectaculaire.
    Sur le test, beaucoup moins :
    """)
    return


@app.cell
def _(pl, test, train):
    pl.concat([
        rule_table(
            _df,
            {"partage >= 3 fois l'habitude + NTLM": (_df["max_src_users_ratio"] >= 3) & (_df["ntlm_share"] > 0)},
            n_days=_days,
        ).with_columns(pl.lit(_name).alias("jeu"))
        for _df, _days, _name in [(train, 14, "jours 1-14"), (test, 15, "test")]
    ])
    return


@app.cell
def _(mo):
    mo.md("""
    Pourquoi cet effondrement ? La machine d'où part l'attaquant (C17693) est
    utilisée par des dizaines de comptes **depuis le début de l'attaque**. Au fil
    des jours, son "habitude" calculée inclut l'activité de l'attaquant lui-même :
    au bout de deux semaines, être partagée par 30 comptes est devenu normal
    pour elle. L'attaque s'est fondue dans la référence.

    C'est un piège classique des détections par comportement de référence
    (*baseline*) : si l'attaquant est déjà présent pendant l'apprentissage de
    la référence, il devient la norme. En production, il faut une référence
    apprise sur une période saine et la figer, ou la surveiller.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    Le graphique suivant le montre jour par jour pour C17693, la machine principale
    de l'attaquant : le nombre de comptes qui s'y connectent chaque jour, sa moyenne
    sur les jours précédents (l'« habitude »), et le seuil d'alerte de la règle
    (3 fois l'habitude). Après le jour 12, plus aucun jour d'attaque ne dépasse le seuil.
    """)
    return


@app.cell
def _(alt, lanl, mo, pl):
    mo.stop(
        not lanl.AUTH_USERS.exists(),
        mo.md("Graphique non disponible : il demande les données brutes (étape 2)."),
    )
    # Comptes distincts connectés chaque jour depuis C17693, et leur moyenne sur les
    # jours précédents, calculée comme pour max_src_users_ratio (étape 3)
    _daily = (
        lanl.connect()
        .sql(f"""
            WITH s AS (
                SELECT day, count(DISTINCT split_part(src_user, '@', 1)) AS comptes
                FROM '{lanl.AUTH_USERS}'
                WHERE src_pc = 'C17693' AND orientation = 'LogOn' AND src_pc <> dst_pc
                GROUP BY day
            )
            SELECT
                day,
                comptes,
                coalesce(avg(comptes) OVER (
                    ORDER BY day ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
                ), 0) AS habitude
            FROM s
        """)
        .pl()
        .filter(pl.col("day") <= 29)
        .with_columns(seuil=3 * (pl.col("habitude") + 1))
        .sort("day")
    )

    _series = [
        "Comptes connectés ce jour-là",
        "Habitude (moyenne des jours précédents)",
        "Seuil d’alerte (3 fois l’habitude)",
    ]
    _color = alt.Color(
        "serie:N",
        scale=alt.Scale(domain=_series, range=["#2a78d6", "#eb6834", "#52514e"]),
        legend=alt.Legend(title=None, orient="top", direction="vertical", labelLimit=400),
    )
    _x = alt.X("day:Q", title="Jour", scale=alt.Scale(domain=[0, 30], nice=False), axis=alt.Axis(values=list(range(0, 31, 2))))
    _y_title = "Nombre de comptes"

    _bars = (
        alt.Chart(_daily.with_columns(serie=pl.lit(_series[0])))
        .mark_bar(size=10, cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
        .encode(
            _x,
            alt.Y("comptes:Q", title=_y_title),
            _color,
            tooltip=[alt.Tooltip("day:Q", title="Jour"), alt.Tooltip("comptes:Q", title="Comptes")],
        )
    )
    _lines_data = _daily.unpivot(index="day", on=["habitude", "seuil"], variable_name="serie", value_name="valeur").with_columns(
        pl.col("serie").replace_strict({"habitude": _series[1], "seuil": _series[2]})
    )
    _lines = (
        alt.Chart(_lines_data)
        .mark_line(strokeWidth=2, point=alt.OverlayMarkDef(size=40))
        .encode(
            _x,
            alt.Y("valeur:Q", title=_y_title),
            _color,
            strokeDash=alt.StrokeDash("serie:N", scale=alt.Scale(domain=_series[1:], range=[[1, 0], [5, 4]]), legend=None),
            tooltip=[alt.Tooltip("day:Q", title="Jour"), alt.Tooltip("serie:N", title="Série"), alt.Tooltip("valeur:Q", title="Valeur", format=".1f")],
        )
    )
    _split = alt.Chart(pl.DataFrame({"x": [14.5]})).mark_rule(color="#52514e", strokeDash=[2, 2]).encode(x="x:Q")
    _labels = alt.layer(*[
        alt.Chart(pl.DataFrame({"x": [_xpos], "y": [75], "t": [_txt]}))
        .mark_text(color="#52514e", fontSize=11, align=_align)
        .encode(x="x:Q", y="y:Q", text="t:N")
        for _xpos, _txt, _align in [(14, "jours 1-14", "right"), (15, "test", "left")]
    ])

    contamination_chart = (_bars + _lines + _split + _labels).properties(
        width=560, height=320, title="La machine de l’attaquant (C17693) finit par paraître normale"
    ).configure_axis(gridOpacity=0.4)
    contamination_chart.save(str(lanl.FIGURES_DIR / "reference_contaminee.png"), scale_factor=2)
    contamination_chart
    return


@app.cell
def _(mo):
    mo.md("""
    ## 3. Méthode 2 : Random Forest (supervisée)

    Un **arbre de décision** pose une suite de questions ("plus de 3 machines
    source ?", "part NTLM > 0 ?") et arrive à une réponse. Une **forêt** en
    entraîne des centaines, chacune sur un tirage différent des données, et
    fait voter tous les arbres. Le score = la part des arbres qui votent "compromis".

    `class_weight="balanced"` : il y a 1 compromis pour environ 800 normaux dans
    l'entraînement. Sans correction, le modèle apprendrait à dire "normal" tout le
    temps. Cette option donne à chaque exemple compromis un poids beaucoup plus
    fort, comme si les deux classes étaient de même taille.

    `min_samples_leaf=5` empêche un arbre de créer une règle pour un seul exemple
    (sinon il apprend par cœur au lieu de généraliser). `random_state=0` rend le
    résultat reproductible.
    """)
    return


@app.function
def train_forest(X, y):
    from sklearn.ensemble import RandomForestClassifier

    return RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        min_samples_leaf=5,
        n_jobs=-1,
        random_state=0,
    ).fit(X, y)


@app.cell
def _(mo):
    mo.md("""
    ### Choisir les variables sur la validation, pas sur le test

    Histoire honnête du projet : la première version n'avait que les 12 variables
    de base. L'idée des variables de partage de la machine source est venue en
    analysant une erreur sur un jour de **test** (U8170, jour 15, section 9).
    Le test a donc servi à concevoir le modèle : c'est une fuite de données, et
    les résultats sur le test en sont un peu optimistes.

    On refait donc le choix proprement : chaque variante est entraînée sur les
    jours 1 à 10 et comparée sur la validation (jours 11 à 14), sans toucher au test.
    Les colonnes `top_N` donnent le nombre d'attaques (sur 72) parmi les N couples
    les plus suspects, avec l'équivalent en alertes par jour.
    """)
    return


@app.cell
def _(BASE_FEATURES, FEATURES, fit_part, pl, valid):
    from sklearn.metrics import average_precision_score

    _y = valid["compromised"].to_numpy()
    _rows = []
    for _name, _feats in [("12 variables de base", BASE_FEATURES), ("19 variables", FEATURES)]:
        _model = train_forest(fit_part.select(_feats).to_numpy(), fit_part["compromised"].to_numpy())
        _score = _model.predict_proba(valid.select(_feats).to_numpy())[:, 1]
        _rows.append({
            "variables": _name,
            "precision_moyenne": round(average_precision_score(_y, _score), 3),
            **{f"top_{n} ({n // 4}/jour)": found_in_top(_score, _y, n) for n in (20, 50, 200)},
        })
    pl.DataFrame(_rows)
    return


@app.cell
def _(mo):
    mo.md("""
    L'idée était-elle trouvable sans le test ? On cherche, dans la validation, les
    journées compromises **identiques** à des journées normales sur les 12 variables
    de base : avec ces seules variables, aucun modèle ne peut les séparer.
    """)
    return


@app.cell
def _(BASE_FEATURES, pl, valid):
    _profiles = (
        valid.group_by(BASE_FEATURES)
        .agg(
            n_normaux_identiques=(pl.col("compromised") == 0).sum(),
            n_compromis=pl.col("compromised").sum(),
            machine_source_normaux=pl.col("max_src_users").filter(pl.col("compromised") == 0).median(),
        )
        .filter((pl.col("n_compromis") > 0) & (pl.col("n_normaux_identiques") > 0))
    )
    (
        valid.filter(pl.col("compromised") == 1)
        .join(_profiles, on=BASE_FEATURES)
        .select(
            "user",
            "day",
            "n_logons",
            "ntlm_share",
            "n_normaux_identiques",
            pl.col("max_src_users").alias("comptes_sur_sa_machine_source"),
            pl.col("machine_source_normaux").alias("idem_mediane_des_normaux_identiques"),
        )
        .sort("day")
    )
    return


@app.cell
def _(mo):
    mo.md("""
    Ce qu'on lit :

    - La validation contient elle aussi des journées compromises indiscernables
      avec les 12 variables, dont **U8170 lui-même, le jour 14**. Chaque fois, leur
      machine source est partagée par 18 à 56 comptes, contre 1 pour leurs "jumeaux"
      normaux. L'idée de la variable était donc trouvable sans toucher au test.
    - Sur la validation, les 19 variables font un peu mieux en précision moyenne,
      font jeu égal vers 12 alertes par jour, et font nettement mieux à 50 alertes
      par jour. Mais avec un budget très serré (5 alertes par jour), le modèle à
      12 variables fait mieux.
    - **Décision** : on garde les 19 variables, parce qu'un SOC travaille plutôt
      avec 10 à 50 alertes par jour. Le gain réel est sans doute plus proche de
      celui mesuré ici que du gain spectaculaire mesuré sur le test (section 7).

    Le modèle final est entraîné sur les jours 1 à 14 avec les 19 variables,
    puis évalué une seule fois sur le test.
    """)
    return


@app.cell
def _(X_test, X_train, y_train):
    rf = train_forest(X_train, y_train)
    score_rf = rf.predict_proba(X_test)[:, 1]
    return rf, score_rf


@app.cell
def _(mo):
    mo.md("""
    **Importance des variables** : à quel point chaque variable a servi aux arbres
    pour séparer les classes (le total fait 1).
    """)
    return


@app.cell
def _(FEATURES, pl, rf):
    pl.DataFrame({"variable": FEATURES, "importance": rf.feature_importances_.round(3)}).sort(
        "importance", descending=True
    )
    return


@app.cell
def _(mo):
    mo.md("""
    Le modèle s'appuie d'abord sur le partage de la machine source, puis sur la
    part NTLM et les machines source nouvelles : exactement les signaux repérés
    à l'étape 4. Le volume d'activité (`n_events`) compte peu. Les échecs, la nuit
    et le RDP ne servent presque à rien, comme prévu.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 4. Méthode 3 : Isolation Forest (non supervisée)

    Idée : un point **rare** est facile à isoler. L'algorithme coupe les données
    au hasard (une variable, une valeur) jusqu'à ce que chaque point soit seul.
    Un comportement banal demande beaucoup de coupes ; un comportement étrange
    est isolé en quelques coupes. Moins il faut de coupes, plus le score d'anomalie
    est élevé.

    Elle n'utilise **aucun label** : c'est ce qu'on ferait sans red team pour
    s'entraîner. Elle trouve ce qui est inhabituel, pas forcément ce qui est malveillant.
    """)
    return


@app.cell
def _(IsolationForest, X_test, X_train):
    iforest = IsolationForest(n_estimators=300, n_jobs=-1, random_state=0)
    iforest.fit(X_train)
    # score_samples : plus c'est bas, plus c'est anormal. On inverse le signe
    # pour que, comme les autres scores, "plus haut = plus suspect".
    score_iforest = -iforest.score_samples(X_test)
    return (score_iforest,)


@app.cell
def _(mo):
    mo.md("""
    ## 5. Méthode 4 : k-means (non supervisée)

    k-means range les couples en **k groupes** de comportements semblables
    (ici 10) et calcule le centre de chaque groupe. Score d'anomalie = distance
    au centre le plus proche : un couple loin de tous les groupes ne ressemble
    à aucun comportement habituel.

    k-means mesure des distances, donc deux préparations sont indispensables :

    - `log1p` (logarithme de 1 + x) écrase les valeurs énormes : sans ça,
      9 000 machines contre 7 écraserait toutes les autres différences ;
    - `StandardScaler` met toutes les variables à la même échelle, pour qu'un
      nombre d'événements (centaines) ne compte pas plus qu'une part NTLM (entre 0 et 1).
    """)
    return


@app.cell
def _(KMeans, StandardScaler, X_test, X_train, np):
    scaler = StandardScaler().fit(np.log1p(X_train))
    kmeans = KMeans(n_clusters=10, n_init=10, random_state=0)
    kmeans.fit(scaler.transform(np.log1p(X_train)))
    # transform() donne la distance à chacun des 10 centres ; on garde la plus petite
    score_kmeans = kmeans.transform(scaler.transform(np.log1p(X_test))).min(axis=1)
    return (score_kmeans,)


@app.cell
def _(mo):
    mo.md("""
    ## 6. Premier aperçu

    Une façon concrète de comparer : si un analyste examine les **N couples les
    plus suspects** de la période de test (15 jours), combien des 47 couples
    compromis trouve-t-il ?

    Les règles n'ont pas de classement (elles disent juste oui ou non) : elles
    sont comparées à part, plus haut. L'évaluation complète, avec rappel,
    précision et seuils, est l'étape 6.
    """)
    return


@app.function
def found_in_top(score, y, n):
    """Nombre de vrais compromis parmi les n couples au score le plus élevé."""
    import numpy as np

    return int(y[np.argsort(-score, kind="stable")[:n]].sum())


@app.cell
def _(np, test):
    # Référence la plus simple : classer les couples par la seule variable clé.
    # Beaucoup de couples ont la même valeur : un bruit minuscule (graine fixe)
    # départage les égalités au hasard plutôt que dans l'ordre du fichier.
    _tie_break = np.random.default_rng(0).random(test.height) * 1e-6
    score_max_src = test["max_src_users"].to_numpy() + _tie_break
    score_max_src_ntlm = test["max_src_users"].to_numpy() * (test["ntlm_share"].to_numpy() > 0) + _tie_break
    return score_max_src, score_max_src_ntlm


@app.cell
def _(
    pl,
    score_iforest,
    score_kmeans,
    score_max_src,
    score_max_src_ntlm,
    score_rf,
    y_test,
):
    pl.DataFrame([
        {"methode": name, **{f"top_{n}": found_in_top(s, y_test, n) for n in (50, 100, 500, 2000)}}
        for name, s in [
            ("Random Forest", score_rf),
            ("Isolation Forest", score_iforest),
            ("k-means", score_kmeans),
            ("max_src_users seul", score_max_src),
            ("max_src_users si NTLM", score_max_src_ntlm),
        ]
    ])
    return


@app.cell
def _(mo):
    mo.md("""
    Ce qu'on lit :

    - **Random Forest** est nettement devant : 9 attaques dans ses 50 premières
      alertes, et 38 sur 47 (81 %) dans les 2 000 premières (environ 130 par jour).
    - **Isolation Forest et k-means** font beaucoup moins bien. C'est la leçon de
      l'étape 4 : ce qui est **rare** dans ce réseau (les comptes comme U6836 ou
      U1718) n'est pas ce qui est **malveillant**. Sans labels, on trouve l'étrange,
      pas l'attaquant.
    - **`max_src_users` seul ne trouve presque rien**, même combiné à NTLM. Les
      machines les plus partagées du réseau sont des serveurs légitimes (jusqu'à
      114 comptes par jour) ; la machine de l'attaquant, avec 20 à 30 comptes, est
      dans la moyenne. La variable n'est utile que **combinée** aux autres (nombre
      de machines source, nouveauté, historique du compte) : c'est exactement ce
      que la forêt apporte par rapport à une seule variable.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 7. Ce qu'ont apporté les nouvelles variables

    Le choix a été fait sur la validation (section 3). Pour information, voici
    l'effet mesuré sur le test, une seule fois, avec les deux modèles entraînés
    sur les jours 1 à 14.

    La première version du projet n'avait que les 12 variables "de base" (étape 3).
    En analysant ses erreurs, on a ajouté le partage de la machine source et des
    variables relatives à l'historique du compte. Même forêt, mêmes jours, seules
    les variables changent :
    """)
    return


@app.cell
def _(BASE_FEATURES, pl, score_rf, test, train, y_test):
    _rf_base = train_forest(train.select(BASE_FEATURES).to_numpy(), train["compromised"].to_numpy())
    _score_base = _rf_base.predict_proba(test.select(BASE_FEATURES).to_numpy())[:, 1]

    gain = pl.DataFrame([
        {"variables": name, **{f"top_{n}": found_in_top(s, y_test, n) for n in (50, 100, 500, 2000)}}
        for name, s in [("12 variables (avant)", _score_base), ("19 variables (après)", score_rf)]
    ])
    gain
    return (gain,)


@app.cell
def _(alt, gain, lanl, pl):
    _long = gain.unpivot(index="variables", variable_name="liste", value_name="attaques").with_columns(
        pl.col("liste").str.replace("top_", "").cast(pl.Int64).alias("n")
    ).with_columns(pl.format("{} premières", pl.col("n")).alias("liste"))
    _x = alt.X(
        "liste:N",
        title="Alertes examinées (les plus suspectes de la période de test)",
        sort=["50 premières", "100 premières", "500 premières", "2000 premières"],
        axis=alt.Axis(labelAngle=0),
    )
    _y = alt.Y("attaques:Q", title="Attaques attrapées (sur 47)", scale=alt.Scale(domain=[0, 47]))
    _color = alt.Color(
        "variables:N",
        scale=alt.Scale(domain=["12 variables (avant)", "19 variables (après)"], range=["#2a78d6", "#eb6834"]),
        legend=alt.Legend(title=None, orient="top"),
    )
    _base = alt.Chart(_long).encode(_x, _y, xOffset=alt.XOffset("variables:N", sort=["12 variables (avant)", "19 variables (après)"]))
    _bars = _base.mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, stroke="white", strokeWidth=2).encode(
        _color, tooltip=["variables:N", "liste:N", "attaques:Q"]
    )
    _labels = _base.mark_text(dy=-8, color="#52514e").encode(text="attaques:Q")
    gain_chart = (_bars + _labels).properties(
        width=480, height=300, title="Random Forest : effet des nouvelles variables"
    ).configure_axis(gridOpacity=0.4)

    lanl.FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    gain_chart.save(str(lanl.FIGURES_DIR / "gain_nouvelles_variables.png"), scale_factor=2)
    gain_chart
    return


@app.cell
def _(mo):
    mo.md("""
    Le gain est net à tous les niveaux, surtout en tête de liste : là où un
    analyste regarde en premier. C'est souvent ainsi qu'on progresse en détection :
    moins en changeant d'algorithme qu'en trouvant la bonne variable, ici
    "depuis quelle machine, et combien d'autres comptes l'utilisent".
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 8. Contrôle du biais "compte actif = suspect"

    À l'étape 4, on a vu que les comptes compromis sont plus actifs que la moyenne.
    On ré-entraîne la forêt **sans les variables de volume** (`n_events`,
    `n_logons`, `n_network`, `n_fails`, `events_ratio`). Si les résultats
    s'effondrent, le modèle reposait surtout sur "ce compte est très actif"
    plutôt que sur un vrai comportement d'attaque.
    """)
    return


@app.cell
def _(FEATURES, pl, score_rf, test, train, y_test):
    _volume = ["n_events", "n_logons", "n_network", "n_fails", "events_ratio"]
    _features_no_volume = [f for f in FEATURES if f not in _volume]
    _rf_no_volume = train_forest(train.select(_features_no_volume).to_numpy(), train["compromised"].to_numpy())
    _score_no_volume = _rf_no_volume.predict_proba(test.select(_features_no_volume).to_numpy())[:, 1]

    pl.DataFrame([
        {"modele": name, **{f"top_{n}": found_in_top(s, y_test, n) for n in (50, 100, 500, 2000)}}
        for name, s in [("avec volume", score_rf), ("sans volume", _score_no_volume)]
    ])
    return


@app.cell
def _(mo):
    mo.md("""
    Résultats quasi identiques avec ou sans les variables de volume : le modèle
    ne s'appuie pas sur "compte actif = suspect". Avec seulement les 12 variables
    de base, le volume pesait davantage ; les nouvelles variables l'ont rendu inutile.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 9. Un cas d'école : U8170, jour 15

    Dans la première version, U8170 (compromis) et U9085 (normal) étaient
    **identiques** sur les 12 variables de base : ce jour-là, leur seule activité
    est une connexion NTLM vers une machine nouvelle. Pour U8170, c'est la
    connexion de la red team. Aucun modèle ne pouvait les séparer.

    Avec les nouvelles variables, la différence apparaît : U8170 s'est connecté
    depuis une machine partagée par 20 comptes ce jour-là, U9085 depuis un poste
    qui ne sert qu'à lui. U8170 devient le couple le plus suspect de tout le test.
    """)
    return


@app.cell
def _(dataset, pl, score_rf, test):
    _scores = test.select("user", "day").with_columns(score_rf=pl.Series(score_rf))
    dataset.filter(pl.col("user").is_in(["U8170", "U9085"]) & (pl.col("day") == 15)).select(
        "user", "day", "n_events", "n_new_dst_pc", "ntlm_share", "max_src_users", "compromised"
    ).join(_scores, on=["user", "day"])
    return


@app.cell
def _(alt, dataset, lanl, pl):
    _vars = {
        # "|" = retour à la ligne dans les titres de colonnes
        "n_logons": "Connexions|dans la journée",
        "ntlm_share": "Part de|connexions NTLM",
        "n_new_dst_pc": "Machines cibles|jamais vues",
        "max_src_users": "Comptes sur la|machine source",
    }
    _comptes = {"U8170": "U8170 (compromis)", "U9085": "U9085 (normal)"}
    _data = (
        dataset.filter(pl.col("user").is_in(list(_comptes)) & (pl.col("day") == 15))
        .select("user", *[pl.col(v).cast(pl.Float64) for v in _vars])
        .unpivot(index="user", variable_name="variable", value_name="valeur")
        .with_columns(
            texte=pl.when(pl.col("variable") == "ntlm_share")
            .then(pl.format("{} %", (pl.col("valeur") * 100).round(0).cast(pl.Int64)))
            .otherwise(pl.col("valeur").cast(pl.Int64).cast(pl.String)),
            variable=pl.col("variable").replace_strict(_vars),
            compte=pl.col("user").replace_strict(_comptes),
        )
    )
    _order = list(_comptes.values())
    _x = alt.X("compte:N", title=None, sort=_order, axis=alt.Axis(labels=False, ticks=False))
    _y = alt.Y("valeur:Q", title=None, axis=None)
    _bars = alt.Chart().mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
        _x,
        _y,
        alt.Color(
            "compte:N",
            scale=alt.Scale(domain=_order, range=["#eb6834", "#2a78d6"]),
            legend=alt.Legend(title=None, orient="top"),
        ),
        tooltip=[alt.Tooltip("compte:N", title="Compte"), alt.Tooltip("texte:N", title="Valeur")],
    )
    _text = alt.Chart().mark_text(dy=-8, color="#52514e", fontSize=13).encode(_x, _y, text="texte:N")

    comparison_chart = (
        alt.layer(_bars, _text, data=_data)
        .properties(width=110, height=200)
        .facet(
            column=alt.Column("variable:N", title=None, sort=list(_vars.values()), header=alt.Header(labelFontSize=12, labelExpr="split(datum.label, '|')")),
            title="Jour 15 : deux comptes identiques, sauf la machine source",
        )
        .resolve_scale(y="independent")
        .configure_view(stroke=None)
    )
    comparison_chart.save(str(lanl.FIGURES_DIR / "u8170_vs_u9085.png"), scale_factor=2)
    comparison_chart
    return


@app.cell
def _(mo):
    mo.md("""
    ## 10. Export des scores

    Les scores de toutes les méthodes sur les jours de test sont enregistrés dans
    `data/scores_test.parquet` pour l'évaluation de l'étape 6.
    """)
    return


@app.cell
def _(
    lanl,
    pl,
    score_iforest,
    score_kmeans,
    score_max_src,
    score_rf,
    score_rule_1,
    score_rule_2,
    test,
):
    scores = test.select("user", "day", "compromised", "n_redteam_events").with_columns(
        score_rule_1=pl.Series(score_rule_1),
        score_rule_2=pl.Series(score_rule_2),
        score_rf=pl.Series(score_rf),
        score_iforest=pl.Series(score_iforest),
        score_kmeans=pl.Series(score_kmeans),
        score_max_src=pl.Series(score_max_src),
    )
    lanl.DATA_DIR.mkdir(exist_ok=True)
    scores.write_parquet(lanl.SCORES)
    scores.sort("score_rf", descending=True).head(10)
    return


if __name__ == "__main__":
    app.run()
