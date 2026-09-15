param(
    [switch]$DoctorOnly,
    [string]$ProjectPath
)
$ErrorActionPreference = 'Stop'

trap {
    Write-Host "`nLOI: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host 'Nhan Enter de dong cua so'
    exit 1
}

function Exit-Script([int]$Code) {
    if ($Code -ne 0) { Write-Host "`nScript dung voi ma loi $Code." -ForegroundColor Red }
    Read-Host 'Nhan Enter de dong cua so'
    exit $Code
}

$root = $PSScriptRoot
$exe = Join-Path $root 'amd64\tunnel-client.exe'
$bridge = Join-Path $root 'local-bridge\server.py'
$config = Join-Path $root 'local-bridge\config.json'
$projectPathFile = Join-Path $root 'local-bridge\project-path.txt'
$projectProfiles = Join-Path $root 'local-bridge\project-profiles'
$tunnelFile = Join-Path $root 'tunnel-id-coding.txt'
$envFile = Join-Path $root '.env'
$profileDir = Join-Path $root '.tunnel-client'

# Explorer can keep an old PATH after tools are installed or upgraded.
$pathParts = @(
    $env:Path -split ';'
    [Environment]::GetEnvironmentVariable('Path', 'User') -split ';'
    [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';'
) | Where-Object { $_ } | Select-Object -Unique
$env:Path = $pathParts -join ';'

$codexRg = Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'OpenAI\Codex\bin') -Filter 'rg.exe' -File -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($codexRg) { $env:Path = "$($codexRg.DirectoryName);$env:Path" }

$uvCommand = Get-Command uv -ErrorAction SilentlyContinue
$uvPath = if ($uvCommand) { $uvCommand.Source } else { Join-Path $env:USERPROFILE '.local\bin\uv.exe' }

if (-not [Environment]::Is64BitOperatingSystem) { throw 'Bo khoi dong nay can Windows 64-bit.' }
if (-not (Test-Path -LiteralPath $exe)) { throw "Khong tim thay: $exe" }
if (-not (Test-Path -LiteralPath $bridge)) { throw "Khong tim thay: $bridge" }
if (-not (Test-Path -LiteralPath $config)) { throw "Khong tim thay: $config" }
if (-not (Test-Path -LiteralPath $uvPath -PathType Leaf)) { throw "Khong tim thay uv.exe: $uvPath" }

try {
    $settings = Get-Content -Raw -Encoding UTF8 -LiteralPath $config | ConvertFrom-Json
} catch {
    throw "JSON khong hop le trong $config. Viet duong dan bang dau /, vi du D:/AI/New folder."
}
$configuredWorkspace = [string]$settings.workspace_root
$requestedProjectPath = $ProjectPath
if ([string]::IsNullOrWhiteSpace($ProjectPath)) {
    if ($configuredWorkspace -eq '${PROJECT_ROOT}') {
        if (-not (Test-Path -LiteralPath $projectPathFile -PathType Leaf)) {
            throw "Khong tim thay $projectPathFile. Hay ghi mot duong dan project vao file nay."
        }
        $ProjectPath = (Get-Content -Raw -Encoding UTF8 -LiteralPath $projectPathFile).Trim()
    } else {
        $ProjectPath = $configuredWorkspace
    }
}
$workspace = $ProjectPath.Trim()
$explicitProjectPath = -not [string]::IsNullOrWhiteSpace($requestedProjectPath)
if ($explicitProjectPath -and $configuredWorkspace -ne '${PROJECT_ROOT}') {
    throw '-ProjectPath chi hoat dong khi config.json dung ${PROJECT_ROOT}.'
}
# Windows PowerShell 5.1 does not provide Path.IsPathFullyQualified.
$isAbsolute = $workspace -match '^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+(?:[\\/]|$))'
if (-not $isAbsolute -or -not (Test-Path -LiteralPath $workspace -PathType Container)) {
    throw "Project khong ton tai: $workspace. Hay sua mot dong trong $projectPathFile hoac dung -ProjectPath."
}
$env:CODEX_BRIDGE_PROJECT_ROOT = $workspace

$tunnelId = (Get-Content -Raw -LiteralPath $tunnelFile).Trim()
if ($tunnelId -notmatch '^tunnel_[A-Za-z0-9]+$' -or $tunnelId -eq 'tunnel_REPLACE_ME') {
    throw "Hay ghi tunnel ID that vao $tunnelFile."
}

Set-Location -LiteralPath $root
# tunnel-client parses shell-style escapes; single quotes also survive PowerShell 5.1.
$uvArg = $uvPath.Replace('\', '/').Replace("'", "'\''")
$bridgeArg = $bridge.Replace('\', '/').Replace("'", "'\''")
$configArg = $config.Replace('\', '/').Replace("'", "'\''")
$mcpCommand = "'$uvArg' run --with mcp==2.2.0 --python 3.13 '$bridgeArg' --config '$configArg'"
$bridgeSources = @(
    Get-ChildItem -LiteralPath (Join-Path $root 'local-bridge') -Filter '*.py' -File
    Get-Item -LiteralPath (Join-Path $root 'local-bridge\panel.html')
)
$bridgeFingerprint = $bridgeSources |
    Sort-Object FullName |
    ForEach-Object {
        $_.FullName
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
$profileFingerprint = @(
    if (Test-Path -LiteralPath $projectProfiles -PathType Container) {
        Get-ChildItem -LiteralPath $projectProfiles -Filter '*.json' -File |
            Sort-Object FullName |
            ForEach-Object {
                $_.FullName
                (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
    }
) -join "`n"
$configFingerprint = @(
    (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
    $tunnelId
    $mcpCommand
    (Resolve-Path -LiteralPath $workspace).Path
    $bridgeFingerprint
    $profileFingerprint
) -join "`n"

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

$pidFile = Join-Path $profileDir 'chatgpt-coding.pid'
$fingerprintFile = Join-Path $profileDir 'chatgpt-coding.config.sha256'
if (-not $DoctorOnly -and (Test-Path -LiteralPath $pidFile)) {
    $savedTunnelPid = 0
    if ([int]::TryParse((Get-Content -LiteralPath $pidFile -Raw).Trim(), [ref]$savedTunnelPid)) {
        $runningTunnel = Get-CimInstance Win32_Process -Filter "ProcessId=$savedTunnelPid" -ErrorAction SilentlyContinue
        if ($runningTunnel -and $runningTunnel.ExecutablePath -eq $exe -and $runningTunnel.CommandLine -match '--profile\s+chatgpt-coding(?:\s|$)') {
            $savedFingerprint = if (Test-Path -LiteralPath $fingerprintFile) {
                (Get-Content -LiteralPath $fingerprintFile -Raw).Trim()
            } else { '' }
            if ($savedFingerprint -eq $configFingerprint) {
                Write-Output "Tunnel coding da chay, PID $savedTunnelPid."
                Exit-Script 0
            }

            Write-Output "Cau hinh bridge da doi; dang khoi dong lai tunnel PID $savedTunnelPid."
            & taskkill.exe /PID $savedTunnelPid /T /F | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Khong the dung tunnel cu PID $savedTunnelPid." }
            for ($i = 0; $i -lt 50; $i++) {
                if (-not (Get-Process -Id $savedTunnelPid -ErrorAction SilentlyContinue)) { break }
                Start-Sleep -Milliseconds 200
            }
            if (Get-Process -Id $savedTunnelPid -ErrorAction SilentlyContinue) {
                throw "Tunnel cu PID $savedTunnelPid chua dung; khong tao tunnel moi de tranh trung ket noi."
            }
        }
    }
}

& $uvPath run --with mcp==2.2.0 --python 3.13 $bridge --self-test
if ($LASTEXITCODE -ne 0) { Exit-Script $LASTEXITCODE }

& $uvPath run --with mcp==2.2.0 --python 3.13 $bridge --config $config --doctor
$runtimeDoctorCode = $LASTEXITCODE
if ($runtimeDoctorCode -ne 0) {
    Write-Warning 'Bo chay Codex chua dat kiem tra quyen. Search/Git/task se bi khoa; xem diff va hoan tac van dung duoc.'
}

& $exe init --force --sample sample_mcp_stdio_local --profile chatgpt-coding --profile-dir $profileDir --tunnel-id $tunnelId --mcp-command $mcpCommand --health-listen-addr '127.0.0.1:0'
if ($LASTEXITCODE -ne 0) { Exit-Script $LASTEXITCODE }

& $exe doctor --profile chatgpt-coding --profile-dir $profileDir --explain --mcp.stdio-send-initialized-notification
if ($LASTEXITCODE -ne 0) { Exit-Script $LASTEXITCODE }
if ($DoctorOnly) { Exit-Script $runtimeDoctorCode }

$healthFile = Join-Path $profileDir 'chatgpt-coding-health.url'
Set-Content -LiteralPath $fingerprintFile -Value $configFingerprint -Encoding ASCII
& $exe run --profile chatgpt-coding --profile-dir $profileDir --mcp.stdio-send-initialized-notification --mcp.connection-max-ttl '24h' --health.url-file $healthFile --pid.file $pidFile
Exit-Script $LASTEXITCODE
