# Renforcer la méthodologie de sécurité du code généré

La littérature donne un principe directeur assez précis : les défauts documentés ne sont pas répartis uniformément, ils se concentrent là où (a) il n'y a pas d'oracle non-LLM dans la boucle et (b) l'attention humaine est diluée. La question méthodologique n'est donc pas « plus d'audit » mais « où placer l'oracle externe et l'attention humaine rare ». Traduction de chaque mécanisme identifié en ajustement concret.

## Casser la boucle de dégradation itérative

C'est le résultat IEEE-ISTAS qui frappe le plus directement une architecture Red/Blue : une boucle d'agents qui « améliore » du code peut converger vers quelque chose qui *paraît* corrigé sans l'être, et le nombre de vulnérabilités peut même augmenter. La parade n'est pas de supprimer la boucle mais de lui imposer un critère de terminaison *externe et non-LLM*.

Concrètement : le compte de findings (Semgrep, cargo-audit, tests) doit décroître de façon monotone d'une itération à l'autre, et la boucle s'interrompt avec un flag humain si une itération réintroduit un finding. La sortie du Blue agent est toujours un *candidat*, jamais une vérité — ce qui termine la boucle, c'est l'analyseur, pas le jugement du modèle.

## Ne jamais laisser le modèle noter sa propre sécurité

Le faux sentiment de sécurité de Perry s'applique au niveau de l'agent comme au niveau du dev. La confiance du Red agent (« j'ai audité, c'est clean ») est un signal nul, pas une preuve. Deux mesures :

- Isoler complètement le contexte de génération de celui d'audit (contexte vierge, sans accès à l'affirmation « ce code est sûr »).
- Donner au Red agent un cadrage strictement adversarial — « suppose que ce code est vulnérable, trouve l'exploit » plutôt que « relis ». Le framing « review » produit de la complaisance ; le framing « exploit » produit des findings.

## Ensemble d'analyseurs, pas Semgrep seul

L'étude LLM-CSEC montre que même avec CodeQL + Snyk + CodeShield *et* un prompt « génère du code sécurisé », la génération médiane contient encore plusieurs vulnérabilités haute sévérité. Semgrep est nécessaire, pas suffisant.

Pour le versant Rust de STREAM, empiler :

- `cargo-audit` (base RustSec, supply chain)
- `cargo-geiger` (cartographie des blocs `unsafe`)
- clippy avec les lints de sécurité
- `miri` pour l'UB dans l'`unsafe`

Point important de PromSec dans la littérature : mettre l'analyseur *dans* la boucle de génération (findings réinjectés comme contraintes) est plus efficace que le post-hoc.

## Le crypto est l'angle mort, et c'est le cœur de menace

La misuse cryptographique (CWE-780) est une classe de vulnérabilité dominante dans les études *et* la moins bien attrapée par le pattern-matching SAST — exactement ce que les LLM se trompent subtilement à produire et que Semgrep rate.

Pour une V2 crypto destinée à des activistes face à des adversaires étatiques, la règle devrait être : **aucune primitive cryptographique écrite par le modèle.** Le LLM câble des briques auditées (RustCrypto, `dalek` pour les courbes, `ring`), mais la logique de protocole — le ratchet, le key schedule, la gestion des nonces, le zeroize des secrets en mémoire — passe par revue humaine et, vu le threat model, idéalement par vérification formelle du cœur.

Le state machine du ratchet est un bon candidat pour ProVerif/Tamarin au niveau protocole, ou Hax/Verus au niveau Rust. C'est là que concentrer l'attention humaine rare : sur le crypto, sur les frontières de confiance (parsing d'entrées, IPC, réseau), et sur le gate de merge des diffs sensibles — pas étalée sur tout le code.

## Le piège de la fidélité du port

La parité byte-exact Kotlin→Rust est excellente contre les régressions, mais elle signifie qu'on reproduit *fidèlement les vulnérabilités du Tella d'origine*. **Parité ≠ sécurité.**

- Auditer la base Kotlin originale *indépendamment* du port, et traiter la migration comme une occasion de corriger, pas seulement de mirrorer.
- Ajouter du differential fuzzing entre les deux implémentations (`cargo-fuzz`/libFuzzer sur les mêmes entrées) : ça valide la parité *et* trouve des crashes qu'aucune des deux suites de tests ne couvre.
- Les 148 tests sont un plancher de couverture, pas une garantie — du property-based testing (`proptest`) sur les parseurs, désérialiseurs et frontières crypto vaut plus que 100 tests d'exemple de plus.

## Propagation des correctifs et taille des diffs

Le churn/duplication de GitClear a un corollaire sécurité : un clone propage une vulnérabilité en N exemplaires, et un fix appliqué à une instance en rate les copies. Quand le Blue agent corrige, il doit grep les clones du pattern dans tout le code et propager.

Côté DORA : les petits batchs ne sont pas qu'une question de delivery — un PR généré de 2000 lignes est inauditable, et la revue dégénère en rubber-stamp (le mécanisme de Perry au niveau du PR). Plafonner la taille des diffs d'agent rend la revue réelle et facilite le bisect quand une vuln remonte plus tard.

## Supply chain et hallucination de dépendances

Spécifique au threat model : les LLM suggèrent parfois des crates inexistantes ou typosquattées (le « slopsquatting » — des noms de paquets hallucinés que des attaquants enregistrent ensuite). Vérifier que chaque dépendance suggérée existe et est la canonique.

Puisque la parité byte-exact est déjà visée, l'étendre vers des builds reproductibles : pour une app activiste, permettre aux utilisateurs de vérifier que le binaire correspond au source est une propriété de sécurité de premier ordre, pas un détail.

## Méta-point

La méthodologie réduit la surface, elle ne la ferme pas. La littérature est unanime sur un point : le contrôle qualité humain reste ce que les systèmes automatiques ne répliquent pas. La valeur ajoutée n'est pas d'automatiser davantage, mais de placer chirurgicalement le jugement humain sur le crypto et les frontières de confiance, là où SAST est le plus faible et le blast radius le plus grand.

Pour une V2 crypto à ce niveau d'enjeu, considérer aussi un audit externe indépendant du protocole — aucune boucle Red/Blue, aussi bien conçue soit-elle, ne remplace un œil adversarial humain qui n'a pas écrit le code.
