<#
WebConfigProtector.ps1
Version: v1.3
Author: Christer Obbarius (Sunne Kommun)

Description:
A secure PowerShell tool that encrypts and decrypts sensitive sections 
(connectionStrings and appSettings) in ASP.NET web.config files using 
ProtectedConfiguration (aspnet_regiis). Includes metadata injection, 
bitness-handling, safety backups, FAT reminder, pre-flight checks, 
and full logging.

Repository: https://github.com/Obbelix/WebConfigProtector
License: MIT License

Copyright © 
Christer Obbarius – All rights reserved except as granted by MIT License
#>

#=========================
# Config
#=========================
$ToolName    = "WebConfigProtector"
$ToolVersion = "v1.2"
$SectionsAll = @("connectionStrings","appSettings")
$LogDir  = "C:\Temp"
$LogFile = Join-Path $LogDir "WebConfigProtection.log"

#=========================
# Helpers
#=========================
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

function Write-Log {
    param([string]$Message, [ValidateSet("INFO","WARN","ERROR")] [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$ts [$Level] $Message"
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

function Finish-And-Close {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")] [string]$Level = "INFO",
        [int]$ExitCode = 0
    )
    Write-Log $Message $Level
    Write-Host "`n✅ $Message" -ForegroundColor Green
    Write-Host "⏳ This window will close automatically in 10 seconds..." -ForegroundColor Cyan
    for ($i = 10; $i -gt 0; $i--) {
        Write-Host "Closing in $i ..." -ForegroundColor DarkYellow
        Start-Sleep -Seconds 1
    }
    exit $ExitCode
}

function Test-SectionExists {
    param([string]$ConfigPath, [string]$SectionName)
    try {
        [xml]$xml = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
        return ($xml.configuration.$SectionName -ne $null)
    } catch {
        Write-Log "Failed to parse XML: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-SectionEncrypted {
    param([string]$ConfigPath, [string]$SectionName)
    try {
        [xml]$xml = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
        $node = $xml.configuration.$SectionName
        if ($null -eq $node) { return $false }
        $raw = $node.OuterXml
        return ($raw -match '<EncryptedData' -or $raw -match 'configProtectionProvider' -or $raw -match 'ProtectedConfigurationProvider')
    } catch {
        Write-Log "Failed to inspect encryption: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Sanitize-ForFileName {
    param([string]$Text)
    # Replace characters invalid for filenames
    return ($Text -replace '[:\\/*?"<>|]', '_')
}

function New-BackupFile {
    param([string]$ConfigPath, [string]$BitnessLabel)
    $server = $env:COMPUTERNAME
    $safePath = Sanitize-ForFileName -Text $ConfigPath
    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $name = "${server}_${safePath}_${stamp}_${BitnessLabel}.bak"
    return (Join-Path $LogDir $name)
}

function Get-AspPath-FromBitChoice {
    param([ValidateSet('BIT64','BIT32')] [string]$Bitness)
    if ($Bitness -eq 'BIT64') { return "$env:WinDir\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe" }
    else { return "$env:WinDir\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe" }
}

function Other-Bitness {
    param([ValidateSet('BIT64','BIT32')] [string]$Bitness)
    if ($Bitness -eq 'BIT64') { 'BIT32' } else { 'BIT64' }
}

function Invoke-AspNetRegIis {
    param([string]$ExePath, [string]$Arguments)
    Write-Log "Using aspnet_regiis: $ExePath"
    Write-Log "Args: $Arguments"
    $outFile = Join-Path $env:TEMP "aspnet_regiis_out.txt"
    $errFile = Join-Path $env:TEMP "aspnet_regiis_err.txt"
    if (Test-Path $outFile) { Remove-Item $outFile -Force }
    if (Test-Path $errFile) { Remove-Item $errFile -Force }

    $p = Start-Process -FilePath $ExePath -ArgumentList $Arguments -Wait -NoNewWindow -PassThru `
         -RedirectStandardOutput $outFile -RedirectStandardError $errFile

    $stdout = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { "" }
    $stderr = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { "" }

    if ($stdout) { Write-Log "aspnet_regiis STDOUT:`n$stdout".Trim() }
    if ($stderr) { Write-Log "aspnet_regiis STDERR:`n$stderr".Trim() }

    Write-Log "aspnet_regiis exit code: $($p.ExitCode)"
    [pscustomobject]@{
        ExitCode = $p.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

# ---------- Metadata comment utilities ----------
# We write a single-line comment immediately ABOVE each section:
# <!-- WCP-META: Section=connectionStrings; EncryptedWith=BIT64; Machine=MYHOST; User=DOMAIN\user; Timestamp=2025-10-27 16:45:18; Tool=WebConfigProtector v1.2 -->
$MetaPrefix = "WCP-META:"

function Add-SectionMetadataComment {
    param(
        [string]$ConfigPath,
        [string]$SectionName,
        [string]$Bitness
    )
    try {
        [xml]$xml = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
        $node = $xml.configuration.$SectionName
        if ($null -eq $node) { return $false }

        $machine = $env:COMPUTERNAME
        $user    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $ts      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $text    = "$MetaPrefix Section=$SectionName; EncryptedWith=$Bitness; Machine=$machine; User=$user; Timestamp=$ts; Tool=$ToolName $ToolVersion"

        # Insert comment immediately before the section element
        $comment = $xml.CreateComment($text)
        $null = $xml.configuration.InsertBefore($comment, $node)
        $xml.Save($ConfigPath)
        Write-Log "Metadata comment added above <$SectionName>."
        return $true
    } catch {
        Write-Log "Failed adding metadata comment above <$SectionName>: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Get-SectionMetadata {
    param([string]$ConfigPath, [string]$SectionName)
    try {
        [xml]$xml = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
        $conf = $xml.configuration
        if ($null -eq $conf) { return $null }

        # Find the exact section node, then walk siblings backward to the nearest preceding comment
        $node = $conf.$SectionName
        if ($null -eq $node) { return $null }

        # Gather preceding sibling comments until a non-comment sibling encountered
        $prev = $node.PreviousSibling
        while ($prev -ne $null) {
            if ($prev.NodeType -eq [System.Xml.XmlNodeType]::Comment) {
                $txt = $prev.Value.Trim()
                if ($txt -like "$MetaPrefix*") {
                    # Parse key=value; pairs
                    $kv = $txt.Substring($MetaPrefix.Length).Trim()
                    $map = @{}
                    foreach ($part in $kv.Split(';')) {
                        $p = $part.Trim()
                        if ($p -match '^\s*([^=]+)\s*=\s*(.+)\s*$') {
                            $map[$matches[1]] = $matches[2]
                        }
                    }
                    return $map
                }
            } elseif ($prev.NodeType -ne [System.Xml.XmlNodeType]::Whitespace) {
                break
            }
            $prev = $prev.PreviousSibling
        }
        return $null
    } catch {
        Write-Log "Failed reading metadata for <$SectionName>: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Remove-SectionMetadataComment {
    param([string]$ConfigPath, [string]$SectionName)
    try {
        [xml]$xml = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
        $node = $xml.configuration.$SectionName
        if ($null -eq $node) { return $false }

        $removed = $false
        $prev = $node.PreviousSibling
        while ($prev -ne $null) {
            if ($prev.NodeType -eq [System.Xml.XmlNodeType]::Comment) {
                $txt = $prev.Value.Trim()
                if ($txt -like "$MetaPrefix*") {
                    $toRemove = $prev
                    $prev = $prev.PreviousSibling
                    $null = $xml.configuration.RemoveChild($toRemove)
                    $removed = $true
                    continue
                }
            } elseif ($prev.NodeType -ne [System.Xml.XmlNodeType]::Whitespace) {
                break
            }
            $prev = $prev.PreviousSibling
        }

        if ($removed) {
            $xml.Save($ConfigPath)
            Write-Log "Metadata comment removed above <$SectionName>."
        }
        return $removed
    } catch {
        Write-Log "Failed removing metadata for <$SectionName>: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Pause-For-BackupReminder {
    param([string]$BackupPath)

    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host "⚠️  HIGH SECURITY REMINDER – PROTECT YOUR BACKUP FILE! ⚠️" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host (" Backup file created: {0}" -f $BackupPath) -ForegroundColor White
    Write-Host ""
    Write-Host "This backup contains UNENCRYPTED SECRETS (Connection strings, etc.)" -ForegroundColor White
    Write-Host ""
    Write-Host "✅ REQUIRED ACTIONS BEFORE YOU CONSIDER THIS SECURE:" -ForegroundColor Cyan
    Write-Host "  1️⃣ Move the backup file to a SECURE, RESTRICTED location" -ForegroundColor White
    Write-Host "  2️⃣ DELETE the file from its original location" -ForegroundColor White
    Write-Host "  3️⃣ EMPTY the RECYCLE BIN afterwards" -ForegroundColor Red
    Write-Host ""
    Write-Host "🚫 If the Recycle Bin is not emptied, the secrets are STILL RECOVERABLE!" -ForegroundColor Red
    Write-Host ""
    Write-Host "---------------------------------------------------------------" -ForegroundColor Yellow

    $null = Read-Host "Type OK (or press Enter) to continue"
    Write-Log "User acknowledged security reminder regarding backup handling."
}

#=========================
# Input: web.config path
#=========================
$webConfig = Read-Host "Enter full path to web.config (e.g. C:\inetpub\wwwroot\myapp\web.config)"
$webConfig = $webConfig.Trim('"')  # handle quoted paste

if (-not (Test-Path -LiteralPath $webConfig)) {
    $dir  = Split-Path -Path $webConfig -Parent
    $file = Split-Path -Path $webConfig -Leaf
    if (Test-Path -LiteralPath $dir) {
        $resolved = Get-ChildItem -LiteralPath $dir -Filter $file | Select-Object -First 1
        if ($resolved) { $webConfig = $resolved.FullName }
    }
}
if (-not (Test-Path -LiteralPath $webConfig)) {
    Finish-And-Close "web.config not found: $webConfig" "ERROR" 1
}

$sitePath = Split-Path -Path $webConfig -Parent
Write-Log "Selected web.config: `"$webConfig`""
Write-Log "Physical application folder: `"$sitePath`""

#=========================
# Action: Encrypt or Decrypt
#=========================
Write-Host "`nChoose action:" -ForegroundColor Cyan
Write-Host "1) Encrypt"
Write-Host "2) Decrypt"
Write-Host "3) Cancel"
$choice = Read-Host "Enter choice (1,2,3)"

switch ($choice) {
    '1' { $Action = "Encrypt"; Write-Log "User selected: Encrypt" }
    '2' { $Action = "Decrypt"; Write-Log "User selected: Decrypt" }
    '3' { Finish-And-Close "Canceled by user." "INFO" 0 }
    default { Finish-And-Close "Invalid selection. Exiting." "ERROR" 1 }
}

#=========================
# Sections: which to process
#=========================
Write-Host "`nSelect section(s) to process:" -ForegroundColor Cyan
Write-Host "1) connectionStrings"
Write-Host "2) appSettings"
Write-Host "3) Both (connectionStrings + appSettings)"
$secChoice = Read-Host "Enter choice (1,2,3)"

switch ($secChoice) {
    '1' { $TargetSections = @("connectionStrings"); Write-Log "Target sections: connectionStrings" }
    '2' { $TargetSections = @("appSettings"); Write-Log "Target sections: appSettings" }
    '3' { $TargetSections = $SectionsAll; Write-Log "Target sections: connectionStrings, appSettings" }
    default { Finish-And-Close "Invalid section selection. Exiting." "ERROR" 1 }
}

#=========================
# Preflight: verify selected sections exist at all + detailed logging
#=========================
$existingSections = @()
$missingSections  = @()

foreach ($sec in $TargetSections) {
    if (Test-SectionExists -ConfigPath $webConfig -SectionName $sec) {
        Write-Log "<$sec> section exists in web.config."
        $existingSections += $sec
    } else {
        Write-Log "<$sec> section does NOT exist in web.config." "WARN"
        $missingSections  += $sec
    }
}

if ($existingSections.Count -eq 0) {
    # Nothing to do → do NOT create a backup, exit gracefully with countdown
    Finish-And-Close "None of the selected sections exist in this web.config. Nothing to do." "WARN" 0
}

if ($missingSections.Count -gt 0) {
    Write-Log ("These selected sections were missing and will be skipped: <{0}>" -f ($missingSections -join '>, <')) "WARN"
}

# Continue processing only existing ones
$TargetSections = $existingSections
Write-Log ("Processing these sections: <{0}>" -f ($TargetSections -join '>, <'))

#=========================
# Bitness: x64 or x86 (64-bit default)
#=========================
Write-Host "`nSelect Application Pool bitness:" -ForegroundColor Cyan
Write-Host "1) 64-bit App Pool (default)"
Write-Host "2) 32-bit App Pool"
$bitChoiceInput = Read-Host "Enter choice (1 or 2) [Default=1]"

if ([string]::IsNullOrWhiteSpace($bitChoiceInput) -or $bitChoiceInput -eq '1') {
    $Bitness = 'BIT64'
    Write-Log "Assuming default: 64-bit App Pool."
}
elseif ($bitChoiceInput -eq '2') {
    $Bitness = 'BIT32'
    Write-Log "User selected: 32-bit App Pool."
}
else {
    Write-Log "Invalid selection. Defaulting to 64-bit App Pool." "WARN"
    $Bitness = 'BIT64'
}

$asp = Get-AspPath-FromBitChoice -Bitness $Bitness
if (-not (Test-Path -LiteralPath $asp)) {
    Write-Log "aspnet_regiis.exe not found at: $asp" "ERROR"
    Finish-And-Close "Required .NET Framework missing. Cannot continue." "ERROR" 1
}
Write-Log "Using aspnet_regiis: $asp"


#=========================
# Backup (bitness-tagged filename)
#=========================
$backupFile = New-BackupFile -ConfigPath $webConfig -BitnessLabel $Bitness
Write-Log "Backing up to $backupFile"
Copy-Item -LiteralPath $webConfig -Destination $backupFile -Force

#=========================
# DECRYPT: auto-detect from metadata (safer UX)
#=========================
if ($Action -eq "Decrypt") {
    foreach ($Section in $TargetSections) {
        $meta = Get-SectionMetadata -ConfigPath $webConfig -SectionName $Section
        if ($meta -and $meta.ContainsKey("EncryptedWith")) {
            $encWith = $meta["EncryptedWith"]
            if ($encWith -and $encWith -ne $Bitness) {
                Write-Log "Metadata indicates <$Section> was encrypted with $encWith, current selection is $Bitness." "WARN"
                $ans = Read-Host "Switch to $encWith for decrypt? (Y/N)"
                if ($ans -match '^(y|yes)$') {
                    $Bitness = $encWith
                    $asp = Get-AspPath-FromBitChoice -Bitness $Bitness
                    if (-not (Test-Path -LiteralPath $asp)) {
                        Write-Log "aspnet_regiis for $Bitness not found at $asp; continuing with previous selection." "WARN"
                    } else {
                        Write-Log "Switched to $Bitness for decrypt based on metadata."
                    }
                }
                break
            }
        }
    }
}

#=========================
# Process sections
#=========================
$anyWorked = $false
$anySkipped = $false
$anyError = $false

foreach ($Section in $TargetSections) {
    $hasSection = Test-SectionExists -ConfigPath $webConfig -SectionName $Section
    if (-not $hasSection) {
        Write-Log "Section <$Section> is missing in this web.config. Skipping." "WARN"
        $anySkipped = $true
        continue
    }
    $isEncrypted = Test-SectionEncrypted -ConfigPath $webConfig -SectionName $Section

    if ($Action -eq "Encrypt" -and $isEncrypted) {
        Write-Log "Section <$Section> already encrypted. Skipping." "WARN"
        $anySkipped = $true
        continue
    }
    if ($Action -eq "Decrypt" -and -not $isEncrypted) {
        Write-Log "Section <$Section> is not encrypted. Skipping." "WARN"
        $anySkipped = $true
        continue
    }

    # If ENCRYPT: pre-write metadata comment (so it stays with the file in future)
    if ($Action -eq "Encrypt") {
        $null = Add-SectionMetadataComment -ConfigPath $webConfig -SectionName $Section -Bitness $Bitness
    }

    $args = if ($Action -eq "Encrypt") { "-pef `"$Section`" `"$sitePath`"" } else { "-pdf `"$Section`" `"$sitePath`"" }
    $res = Invoke-AspNetRegIis -ExePath $asp -Arguments $args

    if ($res.ExitCode -ne 0) {
        Write-Log "aspnet_regiis failed for <$Section> (exit $($res.ExitCode))." "ERROR"
        $anyError = $true
        continue
    }

    # Post-check verify
    $nowEncrypted = Test-SectionEncrypted -ConfigPath $webConfig -SectionName $Section
    if ($Action -eq "Encrypt" -and -not $nowEncrypted) {
        Write-Log "Command reported success, but <$Section> does not look encrypted. Inspect file manually." "WARN"
        $anySkipped = $true
        continue
    }
    if ($Action -eq "Decrypt" -and $nowEncrypted) {
        Write-Log "Command reported success, but <$Section> still looks encrypted. Inspect file manually." "WARN"
        $anySkipped = $true
        continue
    }

    # If DECRYPT: remove metadata comment for safety
    if ($Action -eq "Decrypt") {
        $null = Remove-SectionMetadataComment -ConfigPath $webConfig -SectionName $Section
    }

    Write-Log "$Action completed and verified for <$Section> using $Bitness."
    $anyWorked = $true
}

#=========================
# Final outcome + FAT reminder + countdown
#=========================
if ($anyError) {
    Finish-And-Close "Done with errors. See $LogFile" "ERROR" 1
} else {

    # ⚠️ Only when ENCRYPTING and something changed: show big backup reminder
    if ($Action -eq "Encrypt" -and $anyWorked) {
        Pause-For-BackupReminder -BackupPath $backupFile
    }

    if ($anyWorked -and -not $anySkipped) {
        Finish-And-Close "All selected sections processed successfully. Log: $LogFile" "INFO" 0
    } elseif ($anyWorked -and $anySkipped) {
        Finish-And-Close "Some sections processed; some skipped/warned. See $LogFile" "WARN" 0
    } else {
        Finish-And-Close "Nothing changed (all sections already in desired state or missing). Log: $LogFile" "WARN" 0
    }
}
