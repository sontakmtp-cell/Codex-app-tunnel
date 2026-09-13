param([switch]$DoctorOnly)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$exe = Join-Path $root 'amd64\tunnel-client.exe'
$bridge = Join-Path $root 'local-bridge\server.py'
$config = Join-Path $root 'local-bridge\config.json'
$tunnelFile = Join-Path $root 'tunnel-id-coding.txt'
$envFile = Join-Path $root '.env'
$profileDir = Join-Path $root '.tunnel-client'

if (-not [Environment]::Is64BitOperatingSystem) { throw 'Bo khoi dong nay can Windows 64-bit.' }
if (-not (Test-Path -LiteralPath $exe)) { throw "Khong tim thay: $exe" }
if (-not (Test-Path -LiteralPath $bridge)) { throw "Khong tim thay: $bridge" }
if (-not (Test-Path -LiteralPath $config)) { throw "Khong tim thay: $config" }
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { throw 'Chua cai uv.' }

try {
    $settings = Get-Content -Raw -Encoding UTF8 -LiteralPath $config | ConvertFrom-Json
} catch {
    throw "JSON khong hop le trong $config. Viet duong dan bang dau /, vi du D:/AI/New folder."
}
$workspace = [string]$settings.workspace_root
# Windows PowerShell 5.1 does not provide Path.IsPathFullyQualified.
$isAbsolute = $workspace -match '^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+(?:[\\/]|$))'
if (-not $isAbsolute -or -not (Test-Path -LiteralPath $workspace -PathType Container)) {
    throw "Hay sua workspace_root trong $config thanh thu muc project that."
}

$pidFile = Join-Path $profileDir 'chatgpt-coding.pid'
if (-not $DoctorOnly -and (Test-Path -LiteralPath $pidFile)) {
    $savedTunnelPid = 0
    if ([int]::TryParse((Get-Content -LiteralPath $pidFile -Raw).Trim(), [ref]$savedTunnelPid)) {
        $runningTunnel = Get-CimInstance Win32_Process -Filter "ProcessId=$savedTunnelPid" -ErrorAction SilentlyContinue
        if ($runningTunnel -and $runningTunnel.ExecutablePath -eq $exe -and $runningTunnel.CommandLine -match '--profile\s+chatgpt-coding(?:\s|$)') {
            Write-Output "Tunnel coding da chay, PID $savedTunnelPid."
            exit 0
        }
    }
}

$tunnelId = (Get-Content -Raw -LiteralPath $tunnelFile).Trim()
if ($tunnelId -notmatch '^tunnel_[A-Za-z0-9]+$' -or $tunnelId -eq 'tunnel_REPLACE_ME') {
    throw "Hay ghi tunnel ID that vao $tunnelFile."
}

$key = $env:CONTROL_PLANE_API_KEY
if ([string]::IsNullOrWhiteSpace($key) -and (Test-Path -LiteralPath $envFile)) {
    $line = Get-Content -LiteralPath $envFile | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') } | Select-Object -First 1
    if ($line) {
        $key = if ($line.Contains('=')) { ($line -split '=', 2)[1].Trim().Trim('"') } else { $line.Trim().Trim('"') }
    }
}
if ([string]::IsNullOrWhiteSpace($key) -or -not $key.StartsWith('sk-')) {
    throw 'Can CONTROL_PLANE_API_KEY hoac API key trong .env.'
}
$env:CONTROL_PLANE_API_KEY = $key

Set-Location -LiteralPath $root
# tunnel-client parses shell-style escapes; single quotes also survive PowerShell 5.1.
$bridgeArg = $bridge.Replace('\', '/').Replace("'", "'\''")
$configArg = $config.Replace('\', '/').Replace("'", "'\''")
$mcpCommand = "uv run --with mcp==1.30.0 --python 3.13 '$bridgeArg' --config '$configArg'"

& uv run --with mcp==1.30.0 --python 3.13 $bridge --self-test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& uv run --with mcp==1.30.0 --python 3.13 $bridge --config $config --doctor
$runtimeDoctorCode = $LASTEXITCODE
if ($runtimeDoctorCode -ne 0) {
    Write-Warning 'Bo chay Codex chua dat kiem tra quyen. Search/Git/task se bi khoa; xem diff va hoan tac van dung duoc.'
}

& $exe init --force --sample sample_mcp_stdio_local --profile chatgpt-coding --profile-dir $profileDir --tunnel-id $tunnelId --mcp-command $mcpCommand --health-listen-addr '127.0.0.1:0'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $exe doctor --profile chatgpt-coding --profile-dir $profileDir --explain --mcp.stdio-send-initialized-notification
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($DoctorOnly) { exit $runtimeDoctorCode }

$healthFile = Join-Path $profileDir 'chatgpt-coding-health.url'
& $exe run --profile chatgpt-coding --profile-dir $profileDir --mcp.stdio-send-initialized-notification --mcp.connection-max-ttl '24h' --health.url-file $healthFile --pid.file $pidFile
exit $LASTEXITCODE
