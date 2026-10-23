# bitwarden-to-protonpass

**English** | [Français](README.fr.md)

Offline PowerShell script that converts a **Bitwarden** JSON export into a **Proton Pass** export, **including passkeys**.

Proton Pass's built-in Bitwarden importer brings over your logins but **not your passkeys**. This script produces a ZIP in the Proton Pass export format. You then import it with the "Proton Pass" importer, which does keep passkeys.

> Independent community project, not affiliated with or endorsed by Proton or Bitwarden.

> [!CAUTION]
> The Bitwarden export and the generated ZIP contain **all your secrets in plaintext** (passwords, passkey private keys, TOTP seeds).
> Never put them in a synced folder (OneDrive, Dropbox…), a Git repository, an issue or a chat.
> Delete them permanently (Shift+Delete) once the import is verified.
> **Do not delete anything from Bitwarden** until you have tested your important passkeys in Proton Pass.

## Requirements

- **PowerShell 7 or newer** (`pwsh`). Tested on Windows; macOS and Linux should work but are untested.
  Install: https://learn.microsoft.com/powershell/scripting/install/installing-powershell
- Nothing else: no modules to install, no network access.

## Usage

### 1. Export from Bitwarden

Export your Bitwarden vault in the unencrypted **`.json`** format.

⚠️ Not ".json (Encrypted)": the script cannot read encrypted exports.

### 2. Convert

```powershell
pwsh -File .\bitwarden-to-protonpass.ps1 -InputPath .\bitwarden_export.json
```

The script creates `bitwarden_export.protonpass.zip` next to the input file.

| Option | Effect |
|---|---|
| `-OutputPath <path>` | Sets the output ZIP name. |
| `-VaultName <name>` | Name of the vault created in Proton Pass (default `Bitwarden`). |
| `-PasskeysOnly` | Converts only the logins that have a passkey. Those logins may end up duplicated if you also import everything else with Proton's built-in Bitwarden importer. |
| `-Force` | Overwrites the output ZIP if it already exists. |

### 3. Read the warnings

The script prints a warning for **every item it cannot carry over as-is**, with the item's name. It ends with a recap:

```
Logins: 120  Notes: 4  Passkeys converted: 11  Passkeys failed: 0

=== SUMMARY: 3 warning(s) ===
  - [Example] raw TOTP secret converted with default settings (SHA1, 6 digits, 30 s): check that the codes match.
  - [Bank] card not converted: import it another way (Proton's built-in Bitwarden importer or by hand).
  - [Hosting] non-web URL dropped: ftp://ftp.example.net
```

If a passkey or an item fails, the recap shows it **in red** and the script exits with code `2`.

### 4. Import into Proton Pass

In Proton Pass's import screen, choose **Proton Pass** as the source (not Bitwarden), then select the generated ZIP.

Items land in a new vault.

### 5. Verify before deleting anything

1. Sign in with a **low-stakes** passkey first, then with your important ones. Seeing them in Proton Pass is not enough: signing in to the site has to work.
2. Compare the TOTP codes in Proton Pass and Bitwarden at the same moment.
3. Then delete the JSON export and the ZIP (Shift+Delete).

## What gets converted

| Bitwarden | Proton Pass |
|---|---|
| Login: name, username, password, notes, favorite | Login (the username goes into *email* if it looks like one, otherwise into *username*) |
| Passkeys (`fido2Credentials`) | Passkeys attached to the login |
| TOTP (`otpauth://…` or raw secret) | TOTP (a raw secret becomes `otpauth://` SHA1 / 6 digits / 30 s) |
| `http(s)://` URLs or URLs without a scheme | Login URLs |
| Custom fields: text / hidden / boolean | Extra fields: text / hidden |
| Secure notes | Notes |

**Not converted (with a warning):** cards, identities and SSH keys (import them with Proton's built-in Bitwarden importer or by hand), non-web URLs (`androidapp://`, `ftp://`…), linked fields, trashed items, attachments, password history.

Everything goes into a single vault: Bitwarden folders are not recreated.

## Passkeys: known limits

- Only **ECDSA P-256 (ES256)** passkeys are supported. That is the only type Bitwarden creates.
- A passkey **without a `userHandle`** cannot be stored by Proton Pass: it is skipped and reported.

## Test status

| Check | Result |
|---|---|
| Passkey encoding compared with a real Proton Pass export | Byte-for-byte identical |
| Round trip Proton → Bitwarden (synthetic) → Proton | Byte-for-byte identical |
| The "Proton Pass" importer keeps passkeys from a Proton export | Yes |
| Real sign-in with imported Bitwarden passkeys (GUID credential IDs) | Yes |
| Real sign-in with a passkey marked non-discoverable in Bitwarden | Yes |

If you run into a problem, open an *issue* and paste the warning messages. They contain no secrets, but **never attach your export**.

## How it works

In a Proton Pass export, each passkey is stored in `content`:

```
content (base64)
 └─ MessagePack { c: <bytes>, v: 1 }
     └─ MessagePack { key, cid, rid, uhd, cnt, ext, udn, un }
         └─ key = COSE EC2 / ES256 key: crv = 1, x, y, d (P-256 private key)
```

One quirk: Proton encodes bytes as a MessagePack **array of integers**, not as the `bin` type.

The script does the following:

1. It reads Bitwarden's PKCS#8 private key (`keyValue`) and extracts `d`, `x` and `y`.
2. It decodes `credentialId` (`b64.…` or GUID) and `userHandle`.
3. It rebuilds the nested MessagePack encoding exactly the way Proton Pass does.
4. It writes `Proton Pass/data.json` straight into the ZIP, with no plaintext temporary file.

The format was worked out thanks to [protonpass-to-bitwarden](https://github.com/zimm3rmann/protonpass-to-bitwarden), which does the reverse conversion.

## License

[GPL-3.0-or-later](LICENSE)
