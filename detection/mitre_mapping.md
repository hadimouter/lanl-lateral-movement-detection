# Mapping MITRE ATT&CK

Ce que fait l'attaquant dans les données LANL : il réutilise des identifiants de
comptes utilisateurs volés, en NTLM, depuis quelques machines qu'il contrôle, pour
se connecter à des centaines d'autres machines. Toutes les connexions red team du
jeu de données sont des connexions réseau (`Network`) réussies, en NTLM.

## Techniques

| Technique | Nom | Ce qu'on observe dans les logs | Variables du modèle | Règle Sentinel |
|---|---|---|---|---|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Des comptes légitimes utilisés par quelqu'un d'autre : nouvelles machines source, machine source partagée par des dizaines de comptes | `max_src_users`, `n_new_src_pc`, `n_src_pc`, `src_ratio` | les deux règles |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Use Alternate Authentication Material: Pass the Hash | Authentification NTLM d'un compte qui utilise habituellement Kerberos | `ntlm_share`, `past_ntlm_share` | les deux règles (condition NTLM) |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Remote Services: SMB/Windows Admin Shares | Connexions réseau (type `Network`, événement 4624 type 3) vers de nombreuses machines | `n_dst_pc`, `n_new_dst_pc`, `n_network`, `dst_ratio` | `shared_source_ntlm` |

Une authentification NTLM est compatible avec T1550.002, mais ne la prouve pas :
beaucoup d'applications légitimes utilisent NTLM, et le jeu de données LANL ne précise
pas les techniques employées par la red team. Les signaux ci-dessus sont des indices
à combiner, pas des preuves isolées.

Tactiques couvertes : Lateral Movement (TA0008), Defense Evasion (TA0005),
et Initial Access / Persistence au sens de T1078.

## Ce que le projet ne couvre pas

- **T1021.001 Remote Desktop Protocol** : la variable `n_rdp` existe mais ne sert
  presque pas au modèle (la red team LANL n'utilise pas RDP).
- **T1110 Brute Force / password spraying** : les taux d'échec ne distinguent pas
  les comptes compromis dans ces données. Les comptes qui échouent massivement
  (U6836, U1718) ne sont pas dans la red team.
- **Le vol initial des identifiants** (T1003 OS Credential Dumping) : invisible
  dans des logs d'authentification seuls, il faudrait les logs des postes (EDR).

## Correspondance des champs LANL vers Windows / Sentinel

| LANL (`auth.txt`) | Windows (événement 4624) | Table `SecurityEvent` |
|---|---|---|
| `src_user` / `dst_user` | Compte cible | `TargetUserName`, `TargetDomainName` |
| `src_pc` | Poste source | `IpAddress` (le `WorkstationName` est déclaré par le client en NTLM, donc falsifiable) |
| `dst_pc` | Machine qui enregistre l'événement | `Computer` |
| `auth_type` | Package d'authentification | `AuthenticationPackageName` (NTLM, Kerberos, Negotiate) |
| `logon_type` | Type de logon | `LogonType` (3 = Network, 10 = RemoteInteractive) |
| `result` | Succès / échec | événement 4624 (succès) / 4625 (échec) |

Les règles du dossier `sentinel/` sont la traduction directe des règles 1 et 2 du
notebook `05_detection.py`. Leur logique est rejouée sur les données LANL dans
`07_restitution.py` pour vérifier qu'elle donne les mêmes résultats.
