# M-06 — Un plan 10 sites ne peut pas être lié à un domaine unique

**Destinataire : Antigravity (backend `rgaa-audit-backend`)**
**Date : 29/10/2026 — auteur : Hermes**
**Priorité : P0 — bloque la vente du plan Agence**

---

## 1. Le problème

M-05 signe la clé avec le domaine saisi au checkout. C'est correct pour **Solo** (1 site).
C'est **faux pour Agence** (10 sites) : une agence gère plusieurs sites clients et ne sait pas,
au moment de payer, lesquels elle auditera dans l'année.

Avec la règle M-05 appliquée telle quelle, une clé Agence signée `domain: "client.fr"` est refusée
par le plugin sur tout autre domaine (`wrong_domain` → retour en version gratuite). Un pack à 399 €
fonctionnerait donc sur **un seul site**.

## 2. La règle attendue

Le plugin gère déjà les deux cas (`RgaaAudit_License::domain_allowed()`) :

```
domain = "*"   → accepté sur n'importe quel host, le quota serveur fait la limite
domain = "x.fr" → n'accepte que x.fr
domain = ""     → refusé (no_domain)
```

Le quota est déjà appliqué côté serveur par `/v1/activate` (vérifié le 29/10/2026 : 10 domaines
acceptés, 11ᵉ → `409 {"error":"quota_exceeded","activations":10,"sites":10}`).

**Donc : un plan multi-sites se signe `domain: "*"`.**

## 3. Le changement

Dans le handler webhook, au moment de construire le payload :

```js
const sitesCount = mapped.sites;
const declared   = normalizeDomain(rawDomain || '');

// Un pack multi-sites ne peut pas être lié à un domaine unique : il se consomme
// sur les sites du client au fil de l'année. La limite est le quota `sites`,
// appliqué par /v1/activate, plus la détection de partage du dashboard.
const domain = sitesCount > 1 ? '*' : declared;

if (!domain) {   // '*' est truthy, donc ce test ne vise que Solo
  db.markEventFailed(eventId, 'missing_domain');
  return res.status(422).json({ error: 'missing_domain' });
}
```

Et on continue de stocker la valeur déclarée pour le support :

```
domain      = '*'            ← ce qui est signé dans la clé
domain_raw  = 'client.fr'    ← domaine principal déclaré, informatif
```

**Le champ Polar reste obligatoire sur les deux produits** : pour Agence il devient « domaine
principal », utile au support, mais il ne lie plus la clé. Ne pas le retirer — il évite d'avoir à
créer un second formulaire de paiement.

## 4. Ce qu'il ne faut pas faire

- **Ne pas** signer une clé Agence avec le domaine déclaré « et compter sur le quota » : le plugin
  refuse hors ligne tout host différent, le quota ne serait jamais atteint.
- **Ne pas** émettre 10 clés distinctes pour un pack : ingérable pour le client comme pour le support
  (10 emails, 10 révocations, 10 renouvellements).
- **Ne pas** renoncer au quota : c'est le seul garde-fou. `sites` doit rester signé dans le payload.

## 5. Critères d'acceptation

| # | Entrée | Attendu |
|---|---|---|
| 1 | `order.paid` produit **Agence** (`6ae706ed…`) avec `domain: "client.fr"` | clé signée `"domain":"*"`, `"sites":10`, base `domain='*'`, `domain_raw='client.fr'` |
| 2 | Même clé sur 10 domaines via `/v1/activate` | `200` × 10, compteur `n/10` |
| 3 | 11ᵉ domaine | `409 quota_exceeded` |
| 4 | La clé reste acceptée par `/v1/updates` après le `409` | `200` (le quota n'invalide pas la licence) |
| 5 | `order.paid` produit **Solo** (`e6ad51d6…`) avec `domain: "client.fr"` | clé signée `"domain":"client.fr"` — comportement M-05 inchangé |
| 6 | Produit Solo sans domaine | `422 missing_domain` — inchangé |
| 7 | Renouvellement d'une Agence | clé re-signée `"domain":"*"`, `sites` conservé, `expires` prolongé |

## 6. Limite assumée, à écrire noir sur blanc

Avec `*`, une clé Agence fonctionne hors ligne sur un nombre illimité de sites : le quota n'est
appliqué que lorsque le site appelle le serveur. C'est le compromis retenu, pour trois raisons :

1. un client doit pouvoir travailler si le serveur de licences est injoignable ;
2. l'abus est **visible** : onglet « Alertes de partage » (`getSharedLicenses()`) et compteur
   d'activations par licence ;
3. la révocation est immédiate via la CRL, et les CGV limitent le droit d'usage à 10 sites.

Évolution possible si le besoin d'une contrainte hors ligne se confirme : payload
`"domains": ["a.fr","b.fr", …]` et `in_array()` dans le plugin. Cela suppose une modification du
plugin, du backend et du parcours d'ajout de domaine — à planifier, pas à improviser.
