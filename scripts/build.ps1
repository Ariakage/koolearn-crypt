# Build the koolearn-video-crypt-skill command-line tools.
#
# Usage:
#   .\scripts\build.ps1                       # build for the host platform
#   .\scripts\build.ps1 -All                  # cross-compile every supported target
#   .\scripts\build.ps1 -GOOS windows -GOARCH amd64
#   .\scripts\build.ps1 -Out dist
#
# Binaries are written to <Out>\<goos>-<goarch>\ . The tools are pure Go with no
# cgo and no third-party dependencies, so cross-compiling needs nothing else.
[CmdletBinding()]
param(
  [switch]$All,
  [string]$GOOS,
  [string]$GOARCH,
  [string]$Out = "bin"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Write-Error "go is not installed or not in PATH (need Go 1.23+)"
  exit 1
}

$Cmds = @("vodexport", "hlsget", "vodkey")

function Build-One([string]$goos, [string]$goarch) {
  $ext = if ($goos -eq "windows") { ".exe" } else { "" }
  $dest = Join-Path $Out "$goos-$goarch"
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  foreach ($cmd in $Cmds) {
    Write-Host ("  {0,-9} {1}/{2}" -f $cmd, $goos, $goarch)
    $env:GOOS = $goos
    $env:GOARCH = $goarch
    $env:CGO_ENABLED = "0"
    go build -trimpath -ldflags "-s -w" -o (Join-Path $dest "$cmd$ext") "./cmd/$cmd"
  }
  Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
}

if ($All) {
  foreach ($t in @(@("windows", "amd64"), @("windows", "arm64"), @("darwin", "amd64"), @("darwin", "arm64"))) {
    Build-One $t[0] $t[1]
  }
} elseif ($GOOS) {
  if (-not $GOARCH) { $GOARCH = (go env GOARCH) }
  Build-One $GOOS $GOARCH
} else {
  Build-One (go env GOOS) (go env GOARCH)
}

Write-Host "done -> $Out/"
