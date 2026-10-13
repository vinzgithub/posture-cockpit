# SMTP / STARTTLS — protocole de validation (PR #8)

> **Statut : préparation uniquement.** Aucun déploiement ni activation dans les scans standards.
> Validation ciblée sur l'instance de validation :8081, uniquement après décision explicite de déploiement.

## Portée et prérequis

- Tester exclusivement un domaine public dont les serveurs MX autorisent ce type de vérification.
- Le domaine doit être normalisé ; les MX sont récupérés par DNS pour **ce domaine audité**.
- Ne pas viser un périmètre interne, une adresse IP littérale, une IP privée/réservée ni un hôte absent des MX DNS.
- Vérifier en amont la politique de sortie et l'autorisation des connexions TCP/25 ; un blocage réseau est un échec de mesure, **pas** une preuve d'absence de STARTTLS.
- Prévoir une limite de 1 à 2 MX maximum par essai, 1 connexion par MX, sans nouvelle tentative, avec budget partagé du scan et délais de 5 s par sonde (20 s maximum).
- Les messages autorisés sont la réception du bandeau puis `EHLO` et, si proposé, `STARTTLS`. **Jamais** `MAIL FROM`, `RCPT TO`, `DATA`, authentification ni livraison de mail.
- Préserver la séparation validation/production : ne pas activer la sonde dans les scans standards, les scores, la persistance ou les rapports.

## Matrice de validation

| ID | Scénario | Résultat attendu |
|---|---|---|
| V01 | Option SMTP absente / désactivée | Aucune recherche DNS ni connexion SMTP supplémentaire |
| V02 | Domaine malformé, URL non normalisée | Refus avant interrogation DNS |
| V03 | Périmètre interne | Refus avant interrogation DNS et socket |
| V04 | Hôte ne figurant pas dans les MX DNS du domaine | Refus avant résolution de l'adresse du MX |
| V05 | MX avec IP privée, réservée ou mélange public/privé | Refus intégral, aucune socket |
| V06 | MX public et STARTTLS non annoncé | Observation « non annoncé », sans tentative TLS |
| V07 | STARTTLS annoncé mais refusé (`454`) | Observation « annoncé, non accepté » |
| V08 | STARTTLS accepté (`220`), certificat vérifié | TLS vérifié, protocole et métadonnées de certificat |
| V09 | Certificat invalide / nom de serveur différent / absent | Échec de vérification TLS, jamais un succès |
| V10 | Réponse SMTP tronquée, caractères de contrôle ou ligne trop longue | Erreur bornée ; connexion fermée |
| V11 | Silence serveur / délai dépassé | Abandon dans le délai ; connexion fermée |
| V12 | Quota épuisé | Refus avant nouvelle socket ; aucune répétition |
| V13 | Plusieurs MX | Au plus `max_hosts` hôtes, valeur plafonnée à 5 |
| V14 | Audit standard exécuté sur validation | Aucun changement de score, rapport ou trafic SMTP |

## État de couverture automatisée (13 octobre 2026)

Les tests cités utilisent des flux simulés. « Couvert » signifie que le comportement est exercé en CI, **pas** qu'un MX public a été interrogé en conditions réelles.

| ID | Couverture actuelle | Tests de référence / reste à vérifier |
|---|---|---|
| V01 | Couvert | `test_smtp_engine_observations_are_explicitly_disabled_by_default` |
| V02 | Couvert | `test_smtp_engine_refuses_unnormalized_domain_before_dns` |
| V03 | Couvert | `test_smtp_engine_refuses_internal_perimeter_before_dns` |
| V04 | Couvert | `test_smtp_domain_probe_refuses_undeclared_mx_before_address_dns` |
| V05 | Couvert | `test_refuses_unsafe_smtp_destinations`, `test_live_network_smtp_rejects_mixed_public_private_addresses` |
| V06 | Couvert | `test_no_tls_handshake_without_starttls_advertisement` |
| V07 | Couvert | `test_smtp_starttls_refusal_is_not_a_success` |
| V08 | Couvert (simulation) | `test_verified_starttls_handshake_uses_mx_hostname`, `test_certificate_details_from_der` ; vrai serveur à vérifier |
| V09 | Partiel | `test_verified_starttls_reports_certificate_failure`, `test_starttls_missing_or_invalid_certificate_is_not_verified`, `test_verified_starttls_missing_ssl_object_is_failure` ; ajouter un échec de vérification du nom MX spécifiquement simulé |
| V10 | Couvert | `test_smtp_reply_rejects_oversized_or_incomplete_data`, `test_smtp_reply_rejects_noncanonical_or_control_bytes` |
| V11 | Couvert | `test_smtp_reply_timeout_closes_writer`, `test_smtp_connection_timeout_consumes_one_budget_and_never_retries` |
| V12 | Couvert | `test_probe_refuses_exhausted_budget_before_socket`, `test_live_network_smtp_reuses_dns_and_connection_budget` |
| V13 | Couvert | `test_smtp_engine_observations_respect_dns_mx_and_host_limit`, `test_smtp_engine_caps_observations_at_five_mx` |
| V14 | Partiel | `test_standard_scan_does_not_invoke_smtp_probe` ; absence d'impact réel sur score, rapport et réseau à confirmer sur validation |

**Bilan : 12 scénarios couverts en simulation et 2 partiellement couverts.** Aucun des 14 scénarios n'a été validé par un essai réseau réel depuis :8081.

## Séquence

1. Vérifier la CI de la PR #8 : lint, typage, tests Python et construction Docker.
2. Rejouer d'abord V01–V14 avec réseaux simulés dans les tests automatisés.
3. Après approbation spécifique, déployer **uniquement** sur :8081 et vérifier le bon fonctionnement habituel sans activer SMTP.
4. Après autorisation explicite d'essai réseau TCP/25 sur le domaine choisi, exécuter au plus un essai opt-in borné, puis relever : MX, IP publique épinglée, EHLO, annonce STARTTLS, réponse SMTP, résultat TLS, durée et erreurs.
5. Vérifier les journaux, l'absence d'envoi de courriel, l'absence de modification du score et le retour à l'état inactif.
6. Ne proposer la fusion ni une activation plus large qu'après revue des résultats, des textes/i18n et du modèle de reporting.

## Conditions d'arrêt

Stopper les essais en cas de destination inattendue, contournement des limites réseau, socket persistante, dépassement du quota, erreur de classification TLS ou trafic SMTP non prévu.

## Limites connues

- Le moteur expose un point d'entrée explicite `smtp_observations(..., enabled=True)` ; les audits ordinaires ne l'invoquent pas.
- Les résultats SMTP ne figurent pas encore dans les scores ni les rapports.
- Le contrôle TLS actuel exige une chaîne de confiance et un nom MX valides ; une session SMTP opportuniste peut négocier TLS avec un certificat non vérifiable. Distinguer « TLS accepté » et « certificat vérifié ».
- Ce protocole est un plan de validation : il **ne démontre pas** à lui seul l'ouverture de TCP/25 ou le bon fonctionnement sur un vrai MX.
