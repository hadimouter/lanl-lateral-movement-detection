import marimo

__generated_with = "0.25.2"
app = marimo.App(width="medium")


@app.cell
def _():
    import altair as alt
    import marimo as mo
    import numpy as np
    import polars as pl
    from sklearn.metrics import average_precision_score

    import lanl

    return alt, average_precision_score, lanl, mo, np, pl


@app.cell
def _():
    # Couleurs des séries (palette catégorielle validée, ordre fixe)
    COLORS = {
        "Random Forest": "#2a78d6",
        "Isolation Forest": "#eb6834",
        "k-means": "#1baf7a",
    }
    INK = "#52514e"  # texte secondaire, pour les règles et la ligne du hasard
    TEST_DAYS = 15
    return COLORS, INK, TEST_DAYS


@app.cell
def _(mo):
    mo.md("""
    # 06 - Évaluation

    On mesure maintenant, sur les 15 jours de test, ce que valent les méthodes
    de l'étape 5.

    ## 1. Le vocabulaire

    Quand une méthode lève (ou non) une alerte sur un couple (utilisateur, jour),
    il y a quatre cas :

    | | vraiment compromis | vraiment normal |
    |---|---|---|
    | **alerte** | vrai positif (VP) : attaque attrapée | faux positif (FP) : fausse alerte |
    | **pas d'alerte** | faux négatif (FN) : attaque ratée | vrai négatif (VN) |

    Trois mesures en découlent :

    - **Rappel** = VP / (VP + FN) : sur toutes les attaques, quelle part a-t-on attrapée ?
      *La question du RSSI : "est-ce qu'on voit les intrusions ?"*
    - **Précision** = VP / (VP + FP) : sur toutes les alertes, quelle part est une vraie attaque ?
      *La question de l'analyste SOC : "est-ce que je perds mon temps ?"*
    - **F1** : un compromis entre les deux (leur moyenne harmonique). Il n'est
      élevé que si rappel ET précision le sont.

    Les deux premières tirent en sens opposé : alerter sur tout donne 100 % de
    rappel et une précision nulle ; n'alerter sur rien, l'inverse.

    **Pourquoi jamais l'accuracy** (part de bonnes réponses) ? Une "méthode" qui ne
    lève jamais d'alerte a raison sur tous les couples normaux :
    """)
    return


@app.cell
def _(lanl, pl):
    scores = pl.read_parquet(lanl.SCORES)
    y = scores["compromised"].to_numpy()

    pl.DataFrame({
        "methode": ["ne jamais alerter"],
        "accuracy": [f"{100 * (1 - y.mean()):.2f} %"],
        "rappel": ["0 %"],
        "attaques_attrapees": [f"0 sur {y.sum()}"],
    })
    return scores, y


@app.cell
def _(mo):
    mo.md("""
    99,96 % de bonnes réponses, zéro attaque détectée. L'accuracy ne dit rien
    quand les attaques sont si rares.
    """)
    return


@app.function
def metrics(alert, y):
    """Rappel, précision, F1 et compteurs pour un vecteur d'alertes (0/1)."""
    alert = alert.astype(bool)
    y = y.astype(bool)
    tp = int((alert & y).sum())
    fp = int((alert & ~y).sum())
    fn = int((~alert & y).sum())
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"VP": tp, "FP": fp, "FN": fn, "rappel": recall, "precision": precision, "F1": f1}


@app.cell
def _(mo):
    mo.md("""
    ## 2. Les règles

    Une règle dit oui ou non : elle donne **un seul point** de fonctionnement.
    """)
    return


@app.cell
def _(TEST_DAYS, pl, scores, y):
    pl.DataFrame([
        {
            "regle": name,
            "alertes_par_jour": round(int(scores[col].sum()) / TEST_DAYS),
            **metrics(scores[col].to_numpy(), y),
        }
        for name, col in [
            ("règle 1 : machine jamais vue + NTLM", "score_rule_1"),
            ("règle 2 : machine partagée >= 10 + NTLM", "score_rule_2"),
        ]
    ]).with_columns(pl.col("rappel", "precision", "F1").round(3))
    return


@app.cell
def _(mo):
    mo.md("""
    La règle 2 voit 8 attaques sur 10 (rappel 0,81), mais 99 alertes sur 100
    sont fausses (précision 0,01). Une équipe SOC ne peut pas traiter 246 alertes
    par jour pour en trouver 2 ou 3 vraies.

    ## 3. Les modèles : tout dépend du seuil

    Un modèle donne un score entre 0 et 1, pas un oui/non. C'est à nous de choisir
    un **seuil** : alerte si score >= seuil. Seuil haut = peu d'alertes, précises,
    mais on rate des attaques. Seuil bas = on attrape plus, mais on se noie.

    Déplace le curseur pour voir l'effet sur le Random Forest :
    """)
    return


@app.cell
def _(mo):
    threshold = mo.ui.slider(0.01, 0.99, step=0.01, value=0.30, label="Seuil du Random Forest", show_value=True)
    threshold
    return (threshold,)


@app.cell
def _(TEST_DAYS, mo, scores, threshold, y):
    _alert = scores["score_rf"].to_numpy() >= threshold.value
    _m = metrics(_alert, y)
    mo.md(f"""
    | | vraiment compromis | vraiment normal |
    |---|---|---|
    | **alerte** | {_m["VP"]} VP | {_m["FP"]} FP |
    | **pas d'alerte** | {_m["FN"]} FN | {len(y) - _m["VP"] - _m["FP"] - _m["FN"]} VN |

    **{_alert.sum() / TEST_DAYS:.0f} alertes par jour** · rappel **{_m["rappel"]:.2f}** ·
    précision **{_m["precision"]:.2f}** · F1 **{_m["F1"]:.2f}**
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 4. La courbe précision / rappel

    Pour comparer les méthodes sans choisir de seuil, on les fait tous défiler :
    chaque point de la courbe est un seuil possible, avec son rappel (en abscisse)
    et sa précision (en ordonnée). Plus la courbe est **haute et à droite**,
    meilleure est la méthode. Les règles sont des points isolés.

    La ligne pointillée est le **hasard** : alerter au hasard donne une précision
    égale à la proportion d'attaques, 0,04 %.
    """)
    return


@app.function
def curve_at_k(score, y, n_days, n_points=300):
    """Rappel et précision si on alerte sur les k couples les plus suspects, pour k de 1 à tous."""
    import numpy as np
    import polars as pl

    order = np.argsort(-score, kind="stable")
    hits = np.cumsum(y[order])
    ks = np.unique(np.geomspace(1, len(y), n_points).astype(int))
    return pl.DataFrame({
        "k": ks,
        "alertes_par_jour": ks / n_days,
        "seuil": score[order][ks - 1],
        "rappel": hits[ks - 1] / y.sum(),
        "precision": hits[ks - 1] / ks,
    })


@app.cell
def _(TEST_DAYS, pl, scores, y):
    curves = pl.concat([
        curve_at_k(scores[col].to_numpy(), y, TEST_DAYS).with_columns(pl.lit(name).alias("methode"))
        for name, col in [
            ("Random Forest", "score_rf"),
            ("Isolation Forest", "score_iforest"),
            ("k-means", "score_kmeans"),
        ]
    ])
    rule_points = pl.DataFrame([
        {"methode": label, **{k: v for k, v in metrics(scores[col].to_numpy(), y).items() if k in ("rappel", "precision")}}
        for label, col in [("Règle 1", "score_rule_1"), ("Règle 2", "score_rule_2")]
    ])
    return curves, rule_points


@app.cell
def _(COLORS, INK, alt, curves, lanl, rule_points, y):
    _color = alt.Color(
        "methode:N",
        scale=alt.Scale(domain=list(COLORS), range=list(COLORS.values())),
        legend=alt.Legend(title=None, orient="top"),
    )
    _x = alt.X("rappel:Q", title="Rappel (part des attaques attrapées)", scale=alt.Scale(domain=[0, 1]))
    _y = alt.Y("precision:Q", title="Précision (part des alertes justes)", scale=alt.Scale(domain=[0, 1]))
    _tooltip = [
        alt.Tooltip("methode:N", title="Méthode"),
        alt.Tooltip("rappel:Q", format=".2f"),
        alt.Tooltip("precision:Q", title="précision", format=".3f"),
        alt.Tooltip("alertes_par_jour:Q", title="alertes / jour", format=".0f"),
    ]
    _lines = alt.Chart(curves).mark_line(strokeWidth=2).encode(_x, _y, _color, tooltip=_tooltip)
    _hover = alt.Chart(curves).mark_point(size=80, opacity=0).encode(_x, _y, tooltip=_tooltip)
    _rules = alt.Chart(rule_points).mark_point(shape="diamond", size=120, filled=True, color=INK).encode(
        _x, _y, tooltip=[alt.Tooltip("methode:N", title="Règle"), alt.Tooltip("rappel:Q", format=".2f"), alt.Tooltip("precision:Q", title="précision", format=".3f")]
    )
    _rule_labels = _rules.mark_text(align="left", dx=10, dy=-8, color=INK).encode(text="methode:N")
    _random = alt.Chart(alt.Data(values=[{"r": 0, "p": float(y.mean())}, {"r": 1, "p": float(y.mean())}])).mark_line(
        strokeDash=[4, 4], color=INK, strokeWidth=1
    ).encode(x="r:Q", y="p:Q")

    pr_chart = (_lines + _hover + _rules + _rule_labels + _random).properties(
        width=560, height=360, title="Précision et rappel selon le seuil, jours de test"
    ).configure_axis(gridOpacity=0.4)
    lanl.FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    pr_chart.save(str(lanl.FIGURES_DIR / "courbe_precision_rappel.png"), scale_factor=2)
    pr_chart
    return


@app.cell
def _(mo):
    mo.md("""
    Pour résumer une courbe en un chiffre : la **précision moyenne** (*average
    precision*, AP), l'aire sous la courbe. Le hasard vaut 0,0004 ; on compare
    chaque méthode à ce niveau.
    """)
    return


@app.cell
def _(average_precision_score, pl, scores, y):
    _random = y.mean()
    pl.DataFrame([
        {
            "methode": name,
            "precision_moyenne": round(average_precision_score(y, scores[col].to_numpy()), 4),
            "fois_mieux_que_le_hasard": round(average_precision_score(y, scores[col].to_numpy()) / _random),
        }
        for name, col in [
            ("Random Forest", "score_rf"),
            ("Isolation Forest", "score_iforest"),
            ("k-means", "score_kmeans"),
            ("max_src_users seul", "score_max_src"),
        ]
    ])
    return


@app.cell
def _(mo):
    mo.md("""
    Le Random Forest est environ 380 fois meilleur que le hasard, les méthodes
    non supervisées 10 à 20 fois. La variable clé seule (`max_src_users`) ne fait
    que 8 fois mieux : utilisée seule, elle fait remonter les serveurs partagés
    légitimes. Seule la forêt, qui la combine aux autres, donne des alertes exploitables.

    ## 5. Choisir un seuil comme une équipe SOC : le budget d'alertes

    En pratique, on ne choisit pas un seuil abstrait mais un **budget** :
    "mon équipe peut examiner 10 alertes par jour". On prend alors, **chaque jour**,
    les 10 couples les plus suspects de ce jour-là : c'est ce que ferait un SOC qui
    trie ses alertes au quotidien.

    **Marges d'erreur.** Avec seulement 47 journées compromises, réparties sur 37
    comptes, un pourcentage seul est fragile. Entre crochets, l'intervalle de
    confiance à 95 %, obtenu par *bootstrap* : on refait le calcul 1 000 fois en
    tirant les comptes au hasard (avec remise), et on garde la fourchette qui
    contient 95 % des résultats. On tire des comptes et non des journées, parce
    que les journées d'un même compte ne sont pas indépendantes.
    """)
    return


@app.function
def per_day_alerts(score, days, k):
    """Alerte sur les k couples au score le plus élevé de chaque jour."""
    import numpy as np

    alert = np.zeros(len(score), dtype=bool)
    for d in np.unique(days):
        idx = np.flatnonzero(days == d)
        alert[idx[np.argsort(-score[idx], kind="stable")[:k]]] = True
    return alert


@app.cell
def _(average_precision_score, np, scores, y):
    _days = scores["day"].to_numpy()
    _users = scores["user"].to_numpy()
    _rf = scores["score_rf"].to_numpy()
    BUDGETS = (5, 10, 20, 50, 100, 250)
    budget_alerts = {k: per_day_alerts(_rf, _days, k) for k in BUDGETS}

    # Bootstrap par compte : on tire 1 000 fois les comptes avec remise
    _order = np.argsort(_users, kind="stable")
    _, _starts = np.unique(_users[_order], return_index=True)
    _rows_of_account = np.split(_order, _starts[1:])
    _rng = np.random.default_rng(0)
    _samples = {"ap": []} | {(k, m): [] for k in BUDGETS for m in ("rappel", "precision")}
    for _ in range(1000):
        _idx = np.concatenate([_rows_of_account[i] for i in _rng.integers(0, len(_rows_of_account), len(_rows_of_account))])
        _yb = y[_idx]
        if _yb.sum() == 0:
            continue
        _samples["ap"].append(average_precision_score(_yb, _rf[_idx]))
        for k in BUDGETS:
            _tp = (budget_alerts[k][_idx] & (_yb == 1)).sum()
            _samples[(k, "rappel")].append(_tp / _yb.sum())
            _samples[(k, "precision")].append(_tp / max(budget_alerts[k][_idx].sum(), 1))
    ci = {key: (np.percentile(v, 2.5), np.percentile(v, 97.5)) for key, v in _samples.items()}
    return budget_alerts, ci


@app.cell
def _(budget_alerts, ci, pl, scores, y):
    _n_accounts = scores.filter(pl.col("compromised") == 1)["user"].n_unique()
    _rows = []
    for _k, _alert in budget_alerts.items():
        _m = metrics(_alert, y)
        _found = scores.filter(pl.Series(_alert) & (pl.col("compromised") == 1))["user"].n_unique()
        _rows.append({
            "alertes_par_jour": _k,
            "attaques_attrapees": f"{_m['VP']} / {int(y.sum())}",
            "rappel [IC 95 %]": f"{_m['rappel']:.2f} [{ci[(_k, 'rappel')][0]:.2f} ; {ci[(_k, 'rappel')][1]:.2f}]",
            "precision [IC 95 %]": f"{_m['precision']:.3f} [{ci[(_k, 'precision')][0]:.3f} ; {ci[(_k, 'precision')][1]:.3f}]",
            "comptes_detectes": f"{_found} / {_n_accounts}",
        })
    pl.DataFrame(_rows)
    return


@app.cell
def _(ci, mo):
    mo.md(f"""
    Précision moyenne du Random Forest : 0,157, intervalle de confiance à 95 %
    [{ci["ap"][0]:.3f} ; {ci["ap"][1]:.3f}].
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    Lecture :

    - Avec **10 alertes par jour**, l'équipe attrape 3 journées compromises sur 10,
      et environ 1 alerte sur 11 est une vraie attaque. C'est exploitable.
    - Avec **100 alertes par jour**, on monte à 2 sur 3, mais 47 alertes sur 48
      sont fausses.
    - Les fourchettes sont larges : à 10 alertes par jour, le vrai rappel se situe
      quelque part entre 15 % et 42 %. Ces chiffres permettent de comparer des
      méthodes, pas d'annoncer un taux précis.
    - La dernière colonne compte les **comptes** compromis détectés au moins un
      jour. Pour un SOC, c'est souvent ce qui compte : repérer le compte volé une
      fois suffit à lancer l'enquête, pas besoin de l'attraper chaque jour.

    Comparé à la règle 2 (version du notebook 05 : 246 alertes par jour, 38 attaques
    sur 47), la forêt attrape **autant** d'attaques à volume égal (250 alertes par
    jour, 38 sur 47). Son avantage n'est pas de détecter plus, mais de **classer** :
    on peut réduire le volume d'alertes en gardant les plus suspectes, selon la
    taille de l'équipe.

    La même information, en courbe. Attention, la courbe utilise un classement sur
    toute la période (les N alertes les plus fortes des 15 jours, ramenées à une
    moyenne par jour), pas un tri jour par jour : ses valeurs sont un peu plus
    élevées que le tableau.
    """)
    return


@app.cell
def _(COLORS, alt, curves, lanl, pl):
    _rf = (
        curves.filter((pl.col("methode") == "Random Forest") & (pl.col("alertes_par_jour") >= 0.5))
        .unpivot(index="alertes_par_jour", on=["rappel", "precision"], variable_name="mesure", value_name="valeur")
        .with_columns(pl.col("mesure").replace({"precision": "précision"}))
    )
    _x = alt.X(
        "alertes_par_jour:Q",
        title="Alertes par jour, en moyenne sur 15 jours (échelle logarithmique)",
        scale=alt.Scale(type="log"),
        axis=alt.Axis(values=[1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 5000], format="d"),
    )
    _y = alt.Y("valeur:Q", title=None, scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format=".0%"))
    _color = alt.Color(
        "mesure:N",
        scale=alt.Scale(domain=["rappel", "précision"], range=[COLORS["Random Forest"], COLORS["Isolation Forest"]]),
        legend=alt.Legend(title=None, orient="top"),
    )
    _tooltip = [
        alt.Tooltip("mesure:N", title="Mesure"),
        alt.Tooltip("valeur:Q", title="Valeur", format=".1%"),
        alt.Tooltip("alertes_par_jour:Q", title="alertes / jour", format=".1f"),
    ]
    _lines = alt.Chart(_rf).mark_line(strokeWidth=2).encode(_x, _y, _color, tooltip=_tooltip)
    _hover = alt.Chart(_rf).mark_point(size=80, opacity=0).encode(_x, _y, tooltip=_tooltip)
    budget_chart = (_lines + _hover).properties(
        width=560, height=320, title="Random Forest : rappel et précision selon le budget d'alertes"
    ).configure_axis(gridOpacity=0.4)
    budget_chart.save(str(lanl.FIGURES_DIR / "budget_alertes.png"), scale_factor=2)
    budget_chart
    return


@app.cell
def _(mo):
    mo.md("""
    Le croisement des deux courbes montre le compromis : chaque alerte
    supplémentaire par jour fait monter le rappel et baisser la précision.

    **Le meilleur F1** est obtenu vers 4 alertes par jour en moyenne (F1 environ 0,22). Mais
    attention : ce seuil "optimal" est choisi en regardant les résultats du test,
    il est donc un peu optimiste. En production, on fixe le budget à l'avance,
    selon les moyens de l'équipe.
    """)
    return


@app.cell
def _(np, scores, y):
    _score = scores["score_rf"].to_numpy()
    _order = np.argsort(-_score, kind="stable")
    _hits = np.cumsum(y[_order])
    _k = np.arange(1, len(y) + 1)
    _f1 = 2 * _hits / (_k + y.sum())
    _best = int(_f1.argmax())
    {
        "alertes_au_total": _best + 1,
        "alertes_par_jour": round((_best + 1) / 15, 1),
        "F1": round(float(_f1[_best]), 3),
        "attaques_attrapees": int(_hits[_best]),
    }
    return


@app.cell
def _(mo):
    mo.md("""
    ## 6. Le délai de détection

    La question d'un RSSI : un compte volé, on le repère au bout de combien de
    jours ? Pour chaque compte compromis pendant le test, on compare son premier
    jour compromis **de la période de test** et le premier jour où la forêt lève
    une alerte sur une de ses journées compromises (budget par jour).

    Attention : 29 de ces 37 comptes étaient déjà compromis avant le jour 15,
    pendant l'entraînement. Le délai mesuré part donc du début de la période de
    test, pas du vrai début de la compromission : c'est un délai "à partir du
    moment où le détecteur est en service", pas un délai depuis l'intrusion.
    """)
    return


@app.cell
def _(budget_alerts, pl, scores):
    _first = scores.filter(pl.col("compromised") == 1).group_by("user").agg(premier_jour=pl.col("day").min())
    _rows = []
    for _k in (10, 50):
        _detected = (
            scores.with_columns(alerte=pl.Series(budget_alerts[_k]))
            .filter(pl.col("alerte") & (pl.col("compromised") == 1))
            .group_by("user")
            .agg(jour_detection=pl.col("day").min())
        )
        _d = _first.join(_detected, on="user", how="left").with_columns(
            delai=pl.col("jour_detection") - pl.col("premier_jour")
        )
        _rows.append({
            "alertes_par_jour": _k,
            "comptes_compromis": _d.height,
            "detectes_le_jour_meme": int((_d["delai"] == 0).sum()),
            "detectes_plus_tard": int((_d["delai"] > 0).sum()),
            "delai_max_jours": _d["delai"].max(),
            "jamais_detectes": _d["delai"].null_count(),
        })
    pl.DataFrame(_rows)
    return


@app.cell
def _(mo):
    mo.md("""
    Quand la forêt détecte un compte, c'est presque toujours **dès son premier
    jour compromis** de la période de test. Mais une bonne partie des comptes
    n'est jamais détectée : ce sont les comptes utilisés discrètement (section
    suivante). Le modèle détecte vite les grosses vagues d'attaque, pas les
    usages isolés.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## 7. Ce que chaque méthode attrape et rate

    On fixe un budget de **50 alertes par jour** (tri jour par jour) pour les trois
    modèles, et on regarde, pour chacune des 47 journées compromises, qui l'a attrapée.
    """)
    return


@app.cell
def _(lanl, pl, scores):
    def _top(col):
        return pl.Series(per_day_alerts(scores[col].to_numpy(), scores["day"].to_numpy(), 50))

    caught = (
        scores.with_columns(
            rf=_top("score_rf"),
            iforest=_top("score_iforest"),
            kmeans=_top("score_kmeans"),
            regle_2=pl.col("score_rule_2") == 1,
        )
        .filter(pl.col("compromised") == 1)
        .join(pl.read_parquet(lanl.dataset_path()), on=["user", "day"])
    )
    caught.group_by("rf", "regle_2", "iforest", "kmeans").len("nb_journees").sort("nb_journees", descending=True)
    return (caught,)


@app.cell
def _(mo):
    mo.md("""
    Chaque ligne est une combinaison : par exemple `rf = true, regle_2 = true,
    iforest = false` compte les journées attrapées par la forêt et la règle 2,
    mais pas par Isolation Forest.

    - La forêt attrape 26 journées, dont 23 aussi vues par la règle 2.
    - La règle 2 en voit 15 de plus que la forêt, mais avec ses 246 alertes par jour
      (version du notebook 05), cinq fois plus que les 50 de la forêt.
    - Isolation Forest et k-means n'apportent qu'une seule journée que personne
      d'autre ne voit.
    - 5 journées échappent à toutes les méthodes.

    Les journées que **la forêt rate** :
    """)
    return


@app.cell
def _(caught, pl):
    caught.filter(~pl.col("rf")).select(
        "user",
        "day",
        "n_redteam_events",
        "n_events",
        "max_src_users",
        "ntlm_share",
        "n_new_src_pc",
        "n_src_pc",
        "regle_2",
    ).sort("max_src_users")
    return


@app.cell
def _(mo):
    mo.md("""
    Ce qu'on y voit :

    - Les attaques ratées sont toutes **discrètes** : une à cinq connexions
      red team dans la journée, noyées dans l'activité normale du compte
      (des centaines d'événements, jusqu'à 100 000 pour U66).
    - **Premier groupe** (6 journées, `max_src_users` à 1 ou 2) : ce sont les jours calmes de
      l'attaque (21, 22, 28, 29), où la red team n'utilise qu'un ou deux comptes.
      Sa machine n'est alors pas "partagée" : le signal le plus fort du modèle
      n'existe que pendant les grosses vagues. Une seule connexion NTLM
      au milieu de centaines d'événements ne se voit pas.
    - **Second groupe** (15 journées, jours 15, 26 et 27, machine partagée par 17
      à 29 comptes) : la règle 2 les attrape, la forêt les classe trop bas pour
      entrer dans les 50 alertes du jour. Leur part NTLM est minuscule (une
      connexion NTLM perdue dans des centaines) et leur profil ressemble à celui
      des utilisateurs légitimes des serveurs partagés.

    C'est la limite de l'approche par (utilisateur, jour) : une seule connexion
    malveillante au milieu d'une journée chargée change à peine les compteurs
    du jour. Pour aller plus loin, il faudrait descendre à l'échelle de la
    connexion individuelle, ou suivre les chemins entre machines (graphe).
    """)
    return


if __name__ == "__main__":
    app.run()
