# bitwarden-to-protonpass

[English](README.md) | **Français**

Script PowerShell hors ligne qui convertit un export JSON **Bitwarden** en export **Proton Pass**, **passkeys comprises**.

L'import Bitwarden natif de Proton Pass reprend les identifiants, mais **pas les passkeys**. Ce script génère un ZIP au format d'export Proton Pass. On l'importe ensuite avec l'importeur « Proton Pass », qui, lui, conserve les passkeys.

> Projet communautaire indépendant, non affilié à Proton ni à Bitwarden, ni soutenu par eux.

> [!CAUTION]
> L'export Bitwarden et le ZIP généré contiennent **tous tes secrets en clair** (mots de passe, clés privées des passkeys, TOTP).
> Ne les mets jamais dans un dossier synchronisé (OneDrive, Dropbox…), un dépôt Git, un ticket ou une conversation.
> Supprime-les définitivement (Maj+Suppr) une fois l'import vérifié.
> **Ne supprime rien de Bitwarden** avant d'avoir testé tes passkeys importantes dans Proton Pass.

## Prérequis

- **PowerShell 7 ou plus récent** (`pwsh`). Testé sous Windows ; macOS et Linux devraient fonctionner mais n'ont pas été testés.
  Installation : https://learn.microsoft.com/powershell/scripting/install/installing-powershell
- Rien d'autre : pas de module à installer, aucun accès réseau.

## Utilisation

### 1. Exporter depuis Bitwarden

Exporte ton coffre Bitwarden au format **`.json`** non chiffré.

⚠️ Pas « .json (Chiffré) » : le script ne lit pas les exports chiffrés.

### 2. Convertir

```powershell
pwsh -File .\bitwarden-to-protonpass.ps1 -InputPath .\bitwarden_export.json
```

Le script crée `bitwarden_export.protonpass.zip` à côté du fichier d'entrée.

| Option | Effet |
|---|---|
| `-OutputPath <chemin>` | Choisit le nom du ZIP de sortie. |
| `-VaultName <nom>` | Nom du coffre créé dans Proton Pass (par défaut `Bitwarden`). |
| `-PasskeysOnly` | Ne convertit que les logins qui ont une passkey. Ces logins risquent d'apparaître en double si tu importes aussi le reste avec l'importeur Bitwarden natif de Proton. |
| `-Force` | Écrase le ZIP de sortie s'il existe déjà. |

### 3. Lire les avertissements

Le script affiche un avertissement pour **chaque élément qu'il ne peut pas reprendre tel quel**, avec le nom de l'élément. Il termine par un récapitulatif. Les messages sont en anglais :

```
Logins: 120  Notes: 4  Passkeys converted: 11  Passkeys failed: 0

=== SUMMARY: 3 warning(s) ===
  - [Exemple] raw TOTP secret converted with default settings (SHA1, 6 digits, 30 s): check that the codes match.
  - [Banque] card not converted: import it another way (Proton's built-in Bitwarden importer or by hand).
  - [Hebergeur] non-web URL dropped: ftp://ftp.example.net
```

| Message | Signification |
|---|---|
| `PASSKEY NOT CONVERTED` | Passkey non convertie : garde-la dans Bitwarden. |
| `ITEM NOT CONVERTED` | Élément non converti : garde-le dans Bitwarden. |
| `untested case, check that signing in…` | Convertie, mais cas inhabituel (compteur > 0) : teste la connexion sur le site. |
| `raw TOTP secret converted…` | Secret TOTP brut transformé en `otpauth://` avec les réglages par défaut : compare les codes. |
| `TOTP in '…://' format copied as-is` | TOTP d'un format spécial (Steam…) recopié tel quel : Proton ne le gère peut-être pas. |
| `non-web URL dropped` | URL non web (`androidapp://`, `ftp://`…) ignorée. |
| `card / identity / SSH key not converted` | Carte, identité ou clé SSH non convertie. |
| `linked field … dropped` | Champ lié ignoré (n'existe pas dans Proton). |
| `item is in the Bitwarden trash` | Élément de la corbeille Bitwarden, ignoré. |

En cas d'échec d'une passkey ou d'un élément, le récapitulatif l'indique **en rouge** et le script se termine avec le code `2`.

### 4. Importer dans Proton Pass

Dans l'import de Proton Pass, choisis **Proton Pass** comme source (pas Bitwarden), puis sélectionne le ZIP généré.

Les éléments arrivent dans un nouveau coffre.

### 5. Vérifier avant de supprimer quoi que ce soit

1. Connecte-toi avec une passkey **peu importante**, puis avec tes passkeys importantes. Les voir apparaître dans Proton Pass ne suffit pas : il faut que la connexion au site fonctionne.
2. Compare les codes TOTP de Proton Pass et de Bitwarden au même moment.
3. Supprime ensuite l'export JSON et le ZIP (Maj+Suppr).

## Ce qui est converti

| Bitwarden | Proton Pass |
|---|---|
| Login : nom, identifiant, mot de passe, notes, favori | Login (l'identifiant va dans *e-mail* s'il en a la forme, sinon dans *nom d'utilisateur*) |
| Passkeys (`fido2Credentials`) | Passkeys attachées au login |
| TOTP (`otpauth://…` ou secret brut) | TOTP (un secret brut est converti en `otpauth://` SHA1 / 6 chiffres / 30 s) |
| URLs `http(s)://` ou sans schéma | URLs du login |
| Champs personnalisés texte / masqué / booléen | Champs supplémentaires texte / masqué |
| Notes sécurisées | Notes |

**Non converti (avec un avertissement) :** cartes bancaires, identités et clés SSH (à importer avec l'importeur Bitwarden natif de Proton ou à la main), URLs non web (`androidapp://`, `ftp://`…), champs liés, éléments de la corbeille, pièces jointes, historique des mots de passe.

Tous les éléments vont dans un seul coffre : les dossiers Bitwarden ne sont pas recréés.

## Passkeys : limites connues

- Seules les passkeys **ECDSA P-256 (ES256)** sont prises en charge. Bitwarden ne crée que ce type.
- Une passkey **sans `userHandle`** ne peut pas être stockée par Proton Pass : elle est ignorée et signalée.

## Statut des tests

| Vérification | Résultat |
|---|---|
| Encodage d'une passkey comparé à un vrai export Proton Pass | Identique à l'octet près |
| Aller-retour Proton → Bitwarden (synthétique) → Proton | Identique à l'octet près |
| L'importeur « Proton Pass » conserve les passkeys d'un export Proton | Oui |
| Connexion réelle avec des passkeys Bitwarden importées (identifiants au format GUID) | Oui |
| Connexion réelle avec une passkey marquée non « discoverable » dans Bitwarden | Oui |

Si tu rencontres un problème, ouvre une *issue* en copiant les messages d'avertissement. Ils ne contiennent pas de secret, mais **ne joins jamais ton export**.

## Comment ça marche

Dans un export Proton Pass, chaque passkey est stockée dans `content` :

```
content (base64)
 └─ MessagePack { c: <octets>, v: 1 }
     └─ MessagePack { key, cid, rid, uhd, cnt, ext, udn, un }
         └─ key = clé COSE EC2 / ES256 : crv = 1, x, y, d (clé privée P-256)
```

Particularité : Proton encode les octets en **tableau d'entiers** MessagePack, et non en type `bin`.

Le script fait ceci :

1. Il lit la clé privée PKCS#8 de Bitwarden (`keyValue`) et en extrait `d`, `x` et `y`.
2. Il décode `credentialId` (`b64.…` ou GUID) et `userHandle`.
3. Il reconstruit ce double encodage MessagePack exactement comme Proton Pass.
4. Il écrit `Proton Pass/data.json` directement dans le ZIP, sans fichier temporaire en clair.

Le format a été compris grâce à [protonpass-to-bitwarden](https://github.com/zimm3rmann/protonpass-to-bitwarden), qui fait la conversion inverse.

## Licence

[GPL-3.0-or-later](LICENSE)
