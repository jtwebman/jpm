# Install jpm: irm https://getjpm.sh/install.ps1 | iex
# $env:JPM_VERSION picks a release (default: latest); $env:JPM_INSTALL moves it (default: ~\.jpm\bin).
$ErrorActionPreference = "Stop"

$repo = "jtwebman/jpm"
$dir = if ($env:JPM_INSTALL) { $env:JPM_INSTALL } else { Join-Path $HOME ".jpm\bin" }
$cpu = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
$asset = "jpm-windows-$cpu.exe"
$base = if ($env:JPM_VERSION) { "https://github.com/$repo/releases/download/$env:JPM_VERSION" } else { "https://github.com/$repo/releases/latest/download" }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "jpm: downloading $asset"
  Invoke-WebRequest "$base/$asset" -OutFile "$tmp\jpm.exe" -UseBasicParsing
  Invoke-WebRequest "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS" -UseBasicParsing
  $line = Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match " $([regex]::Escape($asset))$" }
  $want = if ($line) { ($line -split " ")[0] } else { "" }
  $have = (Get-FileHash "$tmp\jpm.exe" -Algorithm SHA256).Hash.ToLower()
  if (-not $want -or $want -ne $have) { throw "jpm: checksum mismatch for $asset" }

  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Move-Item -Force "$tmp\jpm.exe" "$dir\jpm.exe"
  Copy-Item -Force "$dir\jpm.exe" "$dir\jpx.exe"
  Write-Host "jpm: installed $(& "$dir\jpm.exe" --version) to $dir\jpm.exe"

  $path = [Environment]::GetEnvironmentVariable("Path", "User")
  if (($path -split ";") -notcontains $dir) {
    [Environment]::SetEnvironmentVariable("Path", "$dir;$path", "User")
    Write-Host "jpm: added $dir to your user PATH; open a new terminal to use it"
  }
} finally {
  Remove-Item -Recurse -Force $tmp
}
