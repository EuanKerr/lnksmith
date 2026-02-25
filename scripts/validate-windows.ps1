#Requires -Version 5.1

# validate_lnk.ps1 -- Validate .lnk files using Windows Shell COM objects.
#
# Usage:
#   powershell.exe -ExecutionPolicy Bypass -File validate_lnk.ps1 <file.lnk> [file2.lnk ...]
#   powershell.exe -ExecutionPolicy Bypass -File validate_lnk.ps1 -LnkDir <directory>
#
# Uses WScript.Shell (the same API Windows Explorer uses) to parse the LNK,
# so this is ground truth for whether the shortcut will actually work.

[CmdletBinding(DefaultParameterSetName = 'ByFile')]
param(
    [Parameter(ParameterSetName = 'ByDir', Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$LnkDir,

    [Parameter(ParameterSetName = 'ByFile', Position = 0, ValueFromRemainingArguments)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Files
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-LnkFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [__ComObject]$Shell
    )

    $fullPath = (Resolve-Path -LiteralPath $Path).Path
    $fileName = Split-Path -Leaf $fullPath
    $result = @{ File = $fileName; Path = $fullPath; Errors = @(); Warnings = @() }

    try {
        $lnk = $Shell.CreateShortcut($fullPath)
    }
    catch {
        $result.Errors += "FATAL: Shell could not parse LNK: $_"
        return $result
    }

    $result.TargetPath    = $lnk.TargetPath
    $result.Arguments     = $lnk.Arguments
    $result.WorkingDir    = $lnk.WorkingDirectory
    $result.IconLocation  = $lnk.IconLocation
    $result.Description   = $lnk.Description
    $result.Hotkey        = $lnk.Hotkey
    $result.WindowStyle   = $lnk.WindowStyle
    $result.RelativePath  = $lnk.RelativePath

    if ([string]::IsNullOrEmpty($lnk.TargetPath)) {
        $result.Errors += 'TargetPath is EMPTY (shell could not resolve target)'
    }
    elseif (-not (Test-Path -LiteralPath $lnk.TargetPath -ErrorAction SilentlyContinue)) {
        $result.Warnings += "TargetPath '$($lnk.TargetPath)' does not exist on this machine"
    }

    if (-not [string]::IsNullOrEmpty($lnk.IconLocation)) {
        $iconPath = ($lnk.IconLocation -split ',')[0].Trim()
        if ($iconPath -ne '' -and -not (Test-Path -LiteralPath $iconPath -ErrorAction SilentlyContinue)) {
            $result.Warnings += "Icon source '$iconPath' does not exist on this machine"
        }
    }

    return $result
}

function Format-LnkResult {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Result
    )

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host "FILE: $($Result.File)" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan

    if ($Result.Errors.Count -gt 0) {
        foreach ($e in $Result.Errors) {
            Write-Host "  [ERROR]  $e" -ForegroundColor Red
        }
        return
    }

    $props = @(
        @('TargetPath',   $Result.TargetPath),
        @('Arguments',    $Result.Arguments),
        @('WorkingDir',   $Result.WorkingDir),
        @('Description',  $Result.Description),
        @('IconLocation', $Result.IconLocation),
        @('Hotkey',       $Result.Hotkey),
        @('WindowStyle',  $Result.WindowStyle),
        @('RelativePath', $Result.RelativePath)
    )

    foreach ($p in $props) {
        $label = $p[0].PadRight(16)
        $value = if ([string]::IsNullOrEmpty($p[1])) { '(empty)' } else { $p[1] }
        Write-Host "  $label $value"
    }

    foreach ($w in $Result.Warnings) {
        Write-Host "  [WARN]   $w" -ForegroundColor Yellow
    }

    if ($Result.Errors.Count -eq 0) {
        Write-Host '  [OK]     Shell parsed successfully' -ForegroundColor Green
    }
}

# --- Main ---
Write-Host ''
Write-Host 'LNK Validator -- WScript.Shell COM (ground truth)' -ForegroundColor White

$lnkFiles = @()
if ($PSCmdlet.ParameterSetName -eq 'ByDir') {
    $lnkFiles = @(Get-ChildItem -LiteralPath $LnkDir -Filter '*.lnk' | Sort-Object Name | Select-Object -ExpandProperty FullName)
}
elseif ($Files.Count -gt 0) {
    $lnkFiles = $Files
}
else {
    Write-Host 'Usage: validate_lnk.ps1 <file.lnk> [...]  or  -LnkDir <directory>' -ForegroundColor Red
    exit 1
}

if ($lnkFiles.Count -eq 0) {
    Write-Host 'No .lnk files found.' -ForegroundColor Red
    exit 1
}

$Shell = New-Object -ComObject WScript.Shell
try {
    $failed = 0
    foreach ($f in $lnkFiles) {
        $r = Test-LnkFile -Path $f -Shell $Shell
        Format-LnkResult -Result $r
        if ($r.Errors.Count -gt 0) { $failed++ }
    }
}
finally {
    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($Shell)
}

Write-Host ''
if ($failed -gt 0) {
    Write-Host "  $failed file(s) had errors." -ForegroundColor Red
    exit 1
}
else {
    Write-Host "  All $($lnkFiles.Count) file(s) validated OK." -ForegroundColor Green
}
