$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$exe = Join-Path $root 'amd64\tunnel-client.exe'
$envFile = Join-Path $root '.env'
$tunnelFile = Join-Path $root 'tunnel-id.txt'
$profileDir = Join-Path $root '.tunnel-client'

if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -notin @('AMD64', 'x86')) {
    throw 'Bo khoi dong nay chi kem tunnel-client cho Windows AMD64.'
}
if (-not (Test-Path -LiteralPath $exe)) { throw "Khong tim thay: $exe" }
if (-not (Get-Command uvx -ErrorAction SilentlyContinue)) { throw 'Chua cai uv/uvx tren may nay.' }
if (-not (Test-NetConnection 127.0.0.1 -Port 9876 -InformationLevel Quiet)) {
    throw 'Blender MCP chua mo cong 9876. Trong Blender bam Start MCP Server.'
}

$line = Get-Content -LiteralPath $envFile | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') } | Select-Object -First 1
if (-not $line) { throw '.env dang rong.' }
$key = if ($line.Contains('=')) { ($line -split '=', 2)[1].Trim().Trim('"') } else { $line.Trim().Trim('"') }
$tunnelId = (Get-Content -Raw -LiteralPath $tunnelFile).Trim()
if (-not $key.StartsWith('sk-')) { throw 'API key trong .env khong hop le.' }
if (-not $tunnelId.StartsWith('tunnel_')) { throw 'Tunnel ID trong tunnel-id.txt khong hop le.' }

$env:CONTROL_PLANE_API_KEY = $key
& $exe init --force --sample sample_mcp_stdio_local --profile blender --profile-dir $profileDir --tunnel-id $tunnelId --mcp-command 'uvx --python 3.11 blender-mcp' --health-listen-addr '127.0.0.1:0'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $exe doctor --profile blender --profile-dir $profileDir
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $exe run --profile blender --profile-dir $profileDir
