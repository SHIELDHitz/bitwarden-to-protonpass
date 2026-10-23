<#
.SYNOPSIS
  Converts an unencrypted Bitwarden JSON export into a Proton Pass ZIP export,
  including passkeys (fido2Credentials), so it can be imported with the
  "Proton Pass" importer.

.EXAMPLE
  pwsh -File .\bitwarden-to-protonpass.ps1 -InputPath .\bitwarden_export.json
  pwsh -File .\bitwarden-to-protonpass.ps1 -InputPath .\bitwarden_export.json -PasskeysOnly

.NOTES
  Converts login items (with passkeys, TOTP, URLs, custom fields) and secure
  notes. Other item types are skipped and counted in the summary. Everything
  runs offline; the plaintext data.json is built in memory and written only
  inside the output ZIP.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$InputPath,
  [string]$OutputPath,
  [string]$VaultName = 'Bitwarden',
  # Only convert login items that carry at least one passkey.
  [switch]$PasskeysOnly,
  [switch]$Force
)

# Version 1 still catches undefined variables; missing JSON properties read as $null.
Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

# --- MessagePack encoding, matching what Proton Pass emits -------------------
# Proton serializes Vec<u8> as an array of integers (not bin) and always uses
# the smallest MessagePack marker for lengths and integers.

function Add-MpInt([Collections.Generic.List[byte]]$Out, [int64]$Value) {
  if ($Value -ge 0) {
    if ($Value -le 0x7f) { $Out.Add([byte]$Value) }
    elseif ($Value -le 0xff) { $Out.Add(0xcc); $Out.Add([byte]$Value) }
    elseif ($Value -le 0xffff) { $Out.Add(0xcd); $Out.Add([byte](($Value -shr 8) -band 0xff)); $Out.Add([byte]($Value -band 0xff)) }
    elseif ($Value -le 0xffffffffL) { $Out.Add(0xce); for ($s = 24; $s -ge 0; $s -= 8) { $Out.Add([byte](($Value -shr $s) -band 0xff)) } }
    else { $Out.Add(0xcf); for ($s = 56; $s -ge 0; $s -= 8) { $Out.Add([byte](($Value -shr $s) -band 0xff)) } }
  } else {
    if ($Value -ge -32) { $Out.Add([byte](256 + $Value)) }
    elseif ($Value -ge -128) { $Out.Add(0xd0); $Out.Add([byte](256 + $Value)) }
    else { throw "negative integer $Value is not supported" }
  }
}

function Add-MpLength([Collections.Generic.List[byte]]$Out, [int]$Count, [int]$FixBase, [int]$FixMax, [byte]$Marker16, [byte]$Marker32) {
  if ($Count -le $FixMax) { $Out.Add([byte]($FixBase + $Count)) }
  elseif ($Count -le 0xffff) { $Out.Add($Marker16); $Out.Add([byte](($Count -shr 8) -band 0xff)); $Out.Add([byte]($Count -band 0xff)) }
  else { $Out.Add($Marker32); for ($s = 24; $s -ge 0; $s -= 8) { $Out.Add([byte](($Count -shr $s) -band 0xff)) } }
}

function Add-MpArrayHeader($Out, [int]$Count) { Add-MpLength $Out $Count 0x90 15 0xdc 0xdd }
function Add-MpMapHeader($Out, [int]$Count) { Add-MpLength $Out $Count 0x80 15 0xde 0xdf }
function Add-MpNil($Out) { $Out.Add(0xc0) }

function Add-MpStr([Collections.Generic.List[byte]]$Out, [string]$Value) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
  $n = $bytes.Length
  if ($n -le 31) { $Out.Add([byte](0xa0 + $n)) }
  elseif ($n -le 0xff) { $Out.Add(0xd9); $Out.Add([byte]$n) }
  elseif ($n -le 0xffff) { $Out.Add(0xda); $Out.Add([byte](($n -shr 8) -band 0xff)); $Out.Add([byte]($n -band 0xff)) }
  else { throw 'string too long' }
  $Out.AddRange($bytes)
}

function Add-MpOptionalStr($Out, [string]$Value) {
  if ([string]::IsNullOrEmpty($Value)) { Add-MpNil $Out } else { Add-MpStr $Out $Value }
}

function Add-MpBytes([Collections.Generic.List[byte]]$Out, [byte[]]$Value) {
  Add-MpArrayHeader $Out $Value.Length
  foreach ($b in $Value) { Add-MpInt $Out $b }
}

# Writes {"t": <tag>, "c": <content>} where content is produced by $WriteContent.
function Add-MpTagged($Out, [string]$Tag, [scriptblock]$WriteContent) {
  Add-MpMapHeader $Out 2
  Add-MpStr $Out 't'; Add-MpStr $Out $Tag
  Add-MpStr $Out 'c'; & $WriteContent
}

# Builds the base64 "content" field of a Proton passkey from raw P-256 key material.
function New-ProtonPasskeyContent {
  param(
    [byte[]]$D, [byte[]]$X, [byte[]]$Y,
    [byte[]]$CredentialId, [string]$RpId, [byte[]]$UserHandle,
    [Nullable[uint32]]$Counter, [string]$UserDisplayName, [string]$UserName
  )
  $inner = [Collections.Generic.List[byte]]::new()
  Add-MpMapHeader $inner 8

  Add-MpStr $inner 'key'
  Add-MpMapHeader $inner 6
  Add-MpStr $inner 'kty'; Add-MpTagged $inner 'assign' { Add-MpStr $inner 'EC2' }
  Add-MpStr $inner 'kid'; Add-MpArrayHeader $inner 0
  Add-MpStr $inner 'alg'; Add-MpTagged $inner 'assign' { Add-MpStr $inner 'ES256' }
  Add-MpStr $inner 'kops'; Add-MpArrayHeader $inner 0
  Add-MpStr $inner 'biv'; Add-MpArrayHeader $inner 0
  Add-MpStr $inner 'par'
  Add-MpArrayHeader $inner 4
  # COSE crv (-1) = 1 (P-256), stored as a little-endian i128.
  Add-MpArrayHeader $inner 2
  Add-MpTagged $inner 'int' { Add-MpInt $inner -1 }
  Add-MpTagged $inner 'int' { Add-MpMapHeader $inner 1; Add-MpStr $inner 'inner'; Add-MpBytes $inner ([byte[]](@(1) + @(0) * 15)) }
  foreach ($param in @(@(-2, $X), @(-3, $Y), @(-4, $D))) {
    Add-MpArrayHeader $inner 2
    Add-MpTagged $inner 'int' { Add-MpInt $inner $param[0] }
    Add-MpTagged $inner 'bytes' { Add-MpBytes $inner $param[1] }
  }

  Add-MpStr $inner 'cid'; Add-MpBytes $inner $CredentialId
  Add-MpStr $inner 'rid'; Add-MpStr $inner $RpId
  Add-MpStr $inner 'uhd'; Add-MpBytes $inner $UserHandle
  Add-MpStr $inner 'cnt'; if ($null -eq $Counter) { Add-MpNil $inner } else { Add-MpInt $inner $Counter }
  Add-MpStr $inner 'ext'; Add-MpMapHeader $inner 1; Add-MpStr $inner 'hmac_secret'; Add-MpNil $inner
  Add-MpStr $inner 'udn'; Add-MpOptionalStr $inner $UserDisplayName
  Add-MpStr $inner 'un'; Add-MpOptionalStr $inner $UserName

  $outer = [Collections.Generic.List[byte]]::new()
  Add-MpMapHeader $outer 2
  Add-MpStr $outer 'c'; Add-MpBytes $outer $inner.ToArray()
  Add-MpStr $outer 'v'; Add-MpInt $outer 1
  [Convert]::ToBase64String($outer.ToArray())
}

# --- Bitwarden field decoding -------------------------------------------------

function ConvertFrom-Base64Url([string]$Value) {
  $s = $Value.Replace('-', '+').Replace('_', '/')
  switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } 1 { throw 'invalid base64url length' } }
  , [Convert]::FromBase64String($s)
}

function ConvertTo-Base64Url([byte[]]$Bytes) {
  [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# Bitwarden stores credential IDs either as "b64.<base64url>" or as a GUID
# whose hex digits are the raw bytes in written order.
function ConvertFrom-BitwardenCredentialId([string]$Value) {
  if ($Value.StartsWith('b64.')) { return ConvertFrom-Base64Url $Value.Substring(4) }
  $hex = $Value.Replace('-', '')
  if ($hex -notmatch '^[0-9a-fA-F]{32}$') { throw 'unrecognized credentialId format' }
  , [byte[]]@(for ($i = 0; $i -lt 32; $i += 2) { [Convert]::ToByte($hex.Substring($i, 2), 16) })
}

function Get-P256KeyMaterial([string]$KeyValue) {
  $ecdsa = [Security.Cryptography.ECDsa]::Create()
  try {
    $read = 0
    $ecdsa.ImportPkcs8PrivateKey([byte[]](ConvertFrom-Base64Url $KeyValue), [ref]$read)
    $p = $ecdsa.ExportParameters($true)
    if ($p.Curve.Oid.Value -ne '1.2.840.10045.3.1.7') { throw "unsupported curve $($p.Curve.Oid.FriendlyName)" }
    @{ D = $p.D; X = $p.Q.X; Y = $p.Q.Y }
  } finally { $ecdsa.Dispose() }
}

function ConvertTo-Epoch($Date, [int64]$Fallback) {
  if ([string]::IsNullOrEmpty($Date)) { return $Fallback }
  [DateTimeOffset]::Parse([string]$Date, [Globalization.CultureInfo]::InvariantCulture).ToUnixTimeSeconds()
}

function New-ProtonId { ConvertTo-Base64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(64)) | ForEach-Object { $_ + '==' } }

function Convert-Passkey($Cred, [int64]$ItemEpoch) {
  if ($Cred.keyAlgorithm -ne 'ECDSA' -or $Cred.keyCurve -ne 'P-256') { throw "unsupported key $($Cred.keyAlgorithm)/$($Cred.keyCurve)" }
  if ([string]::IsNullOrEmpty($Cred.userHandle)) { throw 'missing userHandle' }
  if ([string]::IsNullOrEmpty($Cred.rpId)) { throw 'missing rpId' }
  $key = Get-P256KeyMaterial $Cred.keyValue
  $cid = ConvertFrom-BitwardenCredentialId $Cred.credentialId
  $uhd = ConvertFrom-Base64Url $Cred.userHandle
  $counter = if ($Cred.counter -and [uint32]$Cred.counter -gt 0) { [uint32]$Cred.counter } else { $null }
  $rpName = if ($Cred.rpName) { $Cred.rpName } else { $Cred.rpId }

  [ordered]@{
    keyId           = ConvertTo-Base64Url $cid
    content         = New-ProtonPasskeyContent -D $key.D -X $key.X -Y $key.Y -CredentialId $cid -RpId $Cred.rpId `
                        -UserHandle $uhd -Counter $counter -UserDisplayName $Cred.userDisplayName -UserName $Cred.userName
    domain          = $Cred.rpId
    rpId            = $Cred.rpId
    rpName          = $rpName
    userName        = [string]$Cred.userName
    userDisplayName = [string]$Cred.userDisplayName
    userId          = [Convert]::ToBase64String($uhd)
    createTime      = ConvertTo-Epoch $Cred.creationDate $ItemEpoch
    note            = ''
    credentialId    = [Convert]::ToBase64String($cid)
    userHandle      = [Convert]::ToBase64String($uhd)
  }
}

function Convert-Url([string]$Uri) {
  if ([string]::IsNullOrWhiteSpace($Uri)) { return $null }
  if ($Uri -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') { return $(if ($Uri -match '^https?://') { $Uri } else { $null }) }
  "https://$Uri"
}

function Convert-Totp([string]$Totp, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Totp) -or $Totp -match '^[a-zA-Z]+://') { return [string]$Totp }
  $secret = ($Totp -replace '\s', '').ToUpperInvariant()
  "otpauth://totp/$([Uri]::EscapeDataString($Label))?secret=$secret&algorithm=SHA1&digits=6&period=30"
}

function Convert-Fields($Fields) {
  $out = @()
  foreach ($f in @($Fields)) {
    if ($null -eq $f -or $f.type -eq 3) { continue }  # 3 = linked field, nothing to carry over
    $out += [ordered]@{
      fieldName = [string]$f.name
      type      = $(if ($f.type -eq 1) { 'hidden' } else { 'text' })
      data      = [ordered]@{ content = [string]$f.value }
    }
  }
  , $out
}

function Get-Prop($Object, [string]$Name) {
  if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { $Object.$Name } else { $null }
}

# Every warning is shown immediately and repeated in the final recap.
$script:Warnings = [Collections.Generic.List[string]]::new()
function Add-ConversionWarning([string]$ItemName, [string]$Message) {
  $text = "[$ItemName] $Message"
  $script:Warnings.Add($text)
  Write-Warning $text
}

# --- Main ---------------------------------------------------------------------

if ($MyInvocation.InvocationName -eq '.') { return }  # dot-sourced: expose functions only

$InputPath = (Resolve-Path -LiteralPath $InputPath).Path
if (-not $OutputPath) { $OutputPath = [IO.Path]::ChangeExtension($InputPath, '.protonpass.zip') }
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $OutputPath) {
  if (-not $Force) { throw "$OutputPath already exists (use -Force to overwrite)" }
  Remove-Item -LiteralPath $OutputPath
}

$bw = Get-Content -Raw -LiteralPath $InputPath -Encoding utf8 | ConvertFrom-Json
if ((Get-Prop $bw 'encrypted') -eq $true) { throw 'This Bitwarden export is encrypted. Export again as "JSON" (not "JSON (Encrypted)").' }

$shareId = New-ProtonId
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$items = [Collections.Generic.List[object]]::new()
$stats = [ordered]@{ logins = 0; notes = 0; passkeys = 0; passkeyErrors = 0; itemErrors = 0; skippedTypes = @{}; skippedDeleted = 0; droppedUrls = 0 }

$typeNames = @{ '1' = 'login'; '2' = 'note'; '3' = 'card'; '4' = 'identity'; '5' = 'SSH key' }

foreach ($bi in @($bw.items)) {
  $name = [string]$bi.name
  try {
  if (Get-Prop $bi 'deletedDate') {
    $stats.skippedDeleted++
    Add-ConversionWarning $name 'item is in the Bitwarden trash: skipped.'
    continue
  }
  $created = ConvertTo-Epoch (Get-Prop $bi 'creationDate') $now
  $modified = ConvertTo-Epoch (Get-Prop $bi 'revisionDate') $created
  $login = Get-Prop $bi 'login'
  $creds = @(Get-Prop $login 'fido2Credentials' | Where-Object { $_ })

  if ($bi.type -eq 1) {
    if ($PasskeysOnly -and $creds.Count -eq 0) { continue }
    $passkeys = @()
    foreach ($c in $creds) {
      try {
        $passkeys += Convert-Passkey $c $created
        $stats.passkeys++
        # Converted, but these cases were never verified against a real Proton import.
        if ($c.counter -and [uint32]$c.counter -gt 0) {
          Add-ConversionWarning $name "passkey $($c.rpId) has counter = $($c.counter): untested case, check that signing in to the site works."
        }
      } catch {
        $stats.passkeyErrors++
        Add-ConversionWarning $name "PASSKEY NOT CONVERTED ($($c.rpId)): $($_.Exception.Message). Keep it in Bitwarden."
      }
    }
    $urls = @()
    foreach ($u in @(Get-Prop $login 'uris' | Where-Object { $_ })) {
      $url = Convert-Url $u.uri
      if ($url) { if ($urls -notcontains $url) { $urls += $url } }
      elseif ($u.uri) { $stats.droppedUrls++; Add-ConversionWarning $name "non-web URL dropped: $($u.uri)" }
    }
    $username = [string](Get-Prop $login 'username')
    $isEmail = $username -match '^[^@\s]+@[^@\s]+\.[^@\s]+$'
    $totp = [string](Get-Prop $login 'totp')
    if ($totp -and $totp -notmatch '^[a-zA-Z]+://') {
      Add-ConversionWarning $name 'raw TOTP secret converted with default settings (SHA1, 6 digits, 30 s): check that the codes match.'
    } elseif ($totp -and $totp -notmatch '^otpauth://') {
      Add-ConversionWarning $name "TOTP in '$($totp.Split(':')[0])://' format copied as-is: Proton may not support it."
    }
    $type = 'login'
    $content = [ordered]@{
      itemEmail    = $(if ($isEmail) { $username } else { '' })
      password     = [string](Get-Prop $login 'password')
      totpUri      = Convert-Totp $totp $(if ($username) { "$($bi.name):$username" } else { $bi.name })
      passkeys     = $passkeys
      itemUsername = $(if ($isEmail) { '' } else { $username })
      autofillUrls = @($urls | ForEach-Object { [ordered]@{ url = $_; mode = 0 } })
      urls         = $urls
    }
    $stats.logins++
  } elseif ($bi.type -eq 2 -and -not $PasskeysOnly) {
    $type = 'note'
    $content = [ordered]@{}
    $stats.notes++
  } else {
    if (-not $PasskeysOnly) {
      $stats.skippedTypes[[string]$bi.type] = 1 + [int]$stats.skippedTypes[[string]$bi.type]
      $label = if ($typeNames[[string]$bi.type]) { $typeNames[[string]$bi.type] } else { "type $($bi.type)" }
      Add-ConversionWarning $name "$label not converted: import it another way (Proton's built-in Bitwarden importer or by hand)."
    }
    continue
  }

  foreach ($f in @(Get-Prop $bi 'fields' | Where-Object { $_ -and $_.type -eq 3 })) {
    Add-ConversionWarning $name "linked field '$($f.name)' dropped (not supported by Proton)."
  }

  $items.Add([ordered]@{
    itemId               = New-ProtonId
    shareId              = $shareId
    folderId             = $null
    data                 = [ordered]@{
      metadata         = [ordered]@{
        name     = [string]$bi.name
        note     = [string](Get-Prop $bi 'notes')
        itemUuid = -join ([Security.Cryptography.RandomNumberGenerator]::GetBytes(4) | ForEach-Object { $_.ToString('x2') })
      }
      extraFields      = Convert-Fields (Get-Prop $bi 'fields')
      platformSpecific = [ordered]@{ android = [ordered]@{ allowedApps = @() } }
      type             = $type
      content          = $content
    }
    state                = 1
    aliasEmail           = $null
    contentFormatVersion = 8
    createTime           = $created
    modifyTime           = $modified
    pinned               = [bool](Get-Prop $bi 'favorite')
    shareCount           = 0
    files                = @()
  })
  } catch {
    $stats.itemErrors++
    Add-ConversionWarning $name "ITEM NOT CONVERTED: $($_.Exception.Message). Keep it in Bitwarden."
  }
}

$export = [ordered]@{
  version = '1.42.0'
  userId  = ''
  vaults  = [ordered]@{
    $shareId = [ordered]@{
      name        = $VaultName
      description = 'Imported from Bitwarden'
      display     = [ordered]@{ color = 0; icon = 0 }
      folders     = @()
      items       = $items.ToArray()
    }
  }
}

$json = $export | ConvertTo-Json -Depth 32 -Compress
$zip = [IO.Compression.ZipFile]::Open($OutputPath, [IO.Compression.ZipArchiveMode]::Create)
try {
  $writer = [IO.StreamWriter]::new($zip.CreateEntry('Proton Pass/data.json').Open(), [Text.UTF8Encoding]::new($false))
  try { $writer.Write($json) } finally { $writer.Dispose() }
} finally { $zip.Dispose() }

Write-Host ''
Write-Host "Written: $OutputPath"
Write-Host "Logins: $($stats.logins)  Notes: $($stats.notes)  Passkeys converted: $($stats.passkeys)  Passkeys failed: $($stats.passkeyErrors)"
if ($stats.droppedUrls) { Write-Host "Non-web URLs dropped: $($stats.droppedUrls)" }
if ($stats.skippedDeleted) { Write-Host "Trashed items skipped: $($stats.skippedDeleted)" }
if ($stats.skippedTypes.Count) {
  Write-Host ('Not converted: ' + (($stats.skippedTypes.GetEnumerator() | ForEach-Object { "$($_.Value) x $(if ($typeNames[$_.Key]) { $typeNames[$_.Key] } else { "type $($_.Key)" })" }) -join ', '))
}

Write-Host ''
if ($script:Warnings.Count) {
  Write-Host "=== SUMMARY: $($script:Warnings.Count) warning(s) ===" -ForegroundColor Yellow
  foreach ($w in $script:Warnings) { Write-Host "  - $w" -ForegroundColor Yellow }
} else {
  Write-Host '=== No warnings: everything was converted ===' -ForegroundColor Green
}
if ($stats.passkeyErrors) {
  Write-Host "WARNING: $($stats.passkeyErrors) passkey(s) were NOT converted. Do not delete them from Bitwarden." -ForegroundColor Red
}
if ($stats.itemErrors) {
  Write-Host "WARNING: $($stats.itemErrors) item(s) were NOT converted (see 'ITEM NOT CONVERTED' above)." -ForegroundColor Red
}
Write-Host ''
Write-Warning 'The ZIP contains your secrets in plaintext. Delete it (and the Bitwarden JSON) once the import is verified.'
if ($stats.passkeyErrors -or $stats.itemErrors) { exit 2 }
