# Central Vault — coffre-fort chiffré, zéro connaissance

Coffre-fort local pour tes documents sensibles, avec sauvegarde déportée sur GitHub.
**GitHub ne voit jamais que des fichiers chiffrés illisibles.** Ta phrase secrète ne quitte jamais ton ordinateur.

## Sécurité

| Composant | Choix | Pourquoi |
|---|---|---|
| Dérivation de clé | **Argon2id** (3 passes, 64 Mo) | Résistant aux attaques par force brute sur GPU |
| Chiffrement | **XChaCha20-Poly1305** (libsodium) | Chiffrement authentifié : toute altération est détectée |
| Aléa | CSPRNG du système | Source matérielle éprouvée. Une interface `secureRandom()` permet de brancher une source physique (type lampe à lave) plus tard |
| Phrase secrète | Jamais stockée, jamais transmise | Perdue = coffre définitivement perdu. C'est le prix du zéro-connaissance |

## Installation (Mac)

1. Installe Node.js : https://nodejs.org (version LTS)
2. Puis dans le Terminal :

```bash
git clone https://github.com/lucas84dlct/central-vault.git
cd central-vault
npm install
npm link        # rend la commande `vault` disponible partout
```

## Utilisation

```bash
vault init              # une seule fois — crée ~/CentralVault
vault add monavis.pdf   # chiffre et range un document
vault list              # liste le coffre (demande la phrase)
vault get monavis.pdf -o ~/Desktop/monavis.pdf   # déchiffre
vault remove monavis.pdf
```

## Sauvegarde déportée (GitHub)

Le coffre vit dans `~/CentralVault/`. Rends-le un dépôt git une seule fois :

```bash
cd ~/CentralVault
git init && git add -A && git commit -m "init vault"
# crée le repo privé sur github.com puis :
git remote add origin https://github.com/lucas84dlct/<ton-repo-prive>.git
git push -u origin main
```

Ensuite, après chaque ajout : `vault sync` (commit + push des blobs chiffrés).
Sur un autre Mac : clone le repo dans `~/CentralVault`, puis `vault list` avec ta phrase secrète.

## Règles d'or

1. **Phrase secrète** : longue (une phrase de 4-5 mots), unique, jamais réutilisée ailleurs. Pas de récupération possible.
2. **Le manifest.json contient les noms de fichiers en clair.** Si ça te gêne, renomme avant d'ajouter.
3. Un fichier déchiffré existe en clair sur ton disque — supprime-le après usage.
4. Teste ta phrase régulièrement avec `vault list`.
