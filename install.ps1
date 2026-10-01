# Install jpm: irm https://getjpm.sh/install.ps1 | iex
# $env:JPM_VERSION picks a release (default: latest); $env:JPM_INSTALL moves it (default: ~\.jpm\bin).
# In a script block: `iex` runs in the caller's session, which should keep its own preferences.
& {
  $ErrorActionPreference = "Stop"
  # Windows PowerShell 5.1 redraws its progress bar per chunk, slowing a download many times over.
  $ProgressPreference = "SilentlyContinue"
  # Older .NET defaults offer TLS 1.0 only, which GitHub refuses.
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $repo = "jtwebman/jpm"
  # A full path: a relative one on PATH would find whatever the current directory holds.
  $dir = if ($env:JPM_INSTALL) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($env:JPM_INSTALL) } else { Join-Path $HOME ".jpm\bin" }
  $cpu = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") { "arm64" } else { "x64" }
  $asset = "jpm-windows-$cpu.exe"
  # A tag's name: no `/` to lead the url to another repository's release.
  if ($env:JPM_VERSION -and $env:JPM_VERSION -notmatch '^[A-Za-z0-9._+-]+$') { throw "jpm: JPM_VERSION must be a release tag, such as v0.1.0, not $env:JPM_VERSION" }
  $base = if ($env:JPM_VERSION) { "https://github.com/$repo/releases/download/$env:JPM_VERSION" } else { "https://github.com/$repo/releases/latest/download" }

  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Write-Host "jpm: downloading $asset"
    Invoke-WebRequest "$base/$asset" -OutFile "$tmp\jpm.exe" -UseBasicParsing
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS" -UseBasicParsing
    $line = Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match " \*?$([regex]::Escape($asset))$" }
    $want = if ($line) { ($line -split " ")[0] } else { "" }
    $have = (Get-FileHash "$tmp\jpm.exe" -Algorithm SHA256).Hash.ToLower()
    if (-not $want -or $want -ne $have) { throw "jpm: checksum mismatch for $asset" }

    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # A running jpm.exe (a `jpm run dev`) cannot be replaced, but it can be renamed out of the way;
    # the old copies go on a later install, once nothing runs them.
    Remove-Item -Force "$dir\*.old" -ErrorAction SilentlyContinue
    foreach ($name in "jpm.exe", "jpx.exe") {
      if (Test-Path "$dir\$name") {
        try { Remove-Item -Force "$dir\$name" } catch { Move-Item -Force "$dir\$name" "$dir\$name.$([System.Guid]::NewGuid()).old" }
      }
    }
    Move-Item -Force "$tmp\jpm.exe" "$dir\jpm.exe"
    Copy-Item -Force "$dir\jpm.exe" "$dir\jpx.exe"
    Write-Host "jpm: installed $(& "$dir\jpm.exe" --version) to $dir\jpm.exe"

    # The raw value, `%USERPROFILE%` and all: [Environment]'s would come back expanded and be
    # written back as plain text.
    $key = Get-Item HKCU:\Environment
    $path = $key.GetValue("Path", "", "DoNotExpandEnvironmentNames")
    $entries = @($path -split ";" | Where-Object { $_ })
    if ($entries -notcontains $dir) {
      $kind = if ($path) { $key.GetValueKind("Path") } else { "ExpandString" }
      Set-ItemProperty HKCU:\Environment -Name Path -Type $kind -Value ((@($dir) + $entries) -join ";")
      # Tell running programs (Explorer, so new terminals) that the environment changed.
      [Environment]::SetEnvironmentVariable("JPM_INSTALL_TMP", "1", "User")
      [Environment]::SetEnvironmentVariable("JPM_INSTALL_TMP", $null, "User")
      Write-Host "jpm: added $dir to your user PATH; open a new terminal to use it"
    }
  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}
