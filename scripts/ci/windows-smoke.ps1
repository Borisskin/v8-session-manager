# Дымовая проверка в Windows: два настоящих .exe (служба обезличивания и менеджер сеансов)
# запускаются как процессы, а этот скрипт подключается к их именованным каналам как клиент
# и шлёт HTTP/1.1 — так же, как это делают сами службы друг другу.
#
# Проверяется: оба процесса поднимаются и слушают свои каналы; канал службы (A), канал
# менеджера (B) и административный канал (C) отвечают через настоящий именованный канал;
# повторная установка пароля отвергается; удалённое подключение по \\localhost\pipe\... не
# проходит. Чего здесь нет: чужая учётная запись (на раннере она одна) и обращения службы к
# менеджеру с настоящей 1С — это ручная приёмка.
#
# Использование: windows-smoke.ps1 -ServiceExe <путь> -ManagerExe <путь> -WorkDir <каталог>
param(
    [Parameter(Mandatory)] [string] $ServiceExe,
    [Parameter(Mandatory)] [string] $ManagerExe,
    [Parameter(Mandatory)] [string] $WorkDir
)
$ErrorActionPreference = 'Stop'

$ServiceExe = (Resolve-Path $ServiceExe).Path
$ManagerExe = (Resolve-Path $ManagerExe).Path
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path

$suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
$pipeService = "ci-smoke-service-$suffix"
$pipeManager = "ci-smoke-manager-$suffix"
$pipeControl = "ci-smoke-control-$suffix"

function Invoke-Pipe {
    param([string] $Name, [string] $Request, [string] $Server = '.')
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(
        $Server, $Name, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
    try {
        $client.Connect(5000)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Request)
        $client.Write($bytes, 0, $bytes.Length)
        $client.Flush()
        $reader = New-Object System.IO.StreamReader($client, [System.Text.Encoding]::UTF8)
        $task = $reader.ReadToEndAsync()
        if (-not $task.Wait(15000)) { throw "канал $Name не ответил за 15 с" }
        return $task.Result
    } finally {
        $client.Dispose()
    }
}

function Invoke-Http {
    param([string] $Name, [string] $Method, [string] $Path, [string] $Body = '')
    $length = [System.Text.Encoding]::UTF8.GetByteCount($Body)
    $request = "$Method $Path HTTP/1.1`r`nHost: local`r`nConnection: close`r`n" +
        "Content-Type: application/json`r`nContent-Length: $length`r`n`r`n$Body"
    $response = Invoke-Pipe -Name $Name -Request $request
    if ($response -notmatch '^HTTP/1\.1 (\d{3})') { throw "не HTTP-ответ от ${Name}: $response" }
    [pscustomobject]@{ Status = [int]$Matches[1]; Text = $response }
}

$results = New-Object System.Collections.Generic.List[string]
function Check {
    param([string] $Title, [bool] $Condition, [string] $Detail = '')
    $mark = if ($Condition) { 'OK  ' } else { 'FAIL' }
    $results.Add("$mark $Title $Detail")
    Write-Host "$mark $Title $Detail"
    if (-not $Condition) { $script:failed = $true }
}
$script:failed = $false

$managerConfig = Join-Path $WorkDir 'manager.yaml'
@"
workPath: '$WorkDir\state'
mcp:
  session_manager:
    bind_address: "127.0.0.1:14000"
    path: "/sessions"
  http:
    bind_address: "127.0.0.1:14001"
    path: "/mcp"
  metrics:
    bind_address: ""
masking:
  enabled: true
  socket_path: '\\.\pipe\$pipeService'
  internal_listen_path: '\\.\pipe\$pipeManager'
  service_expected_exe: '$ServiceExe'
"@ | Set-Content -Encoding utf8 $managerConfig

$env:MASKING_DATABASE_PATH = Join-Path $WorkDir 'service.sqlite3'
$env:MASKING_SOCKET_PATH = "\\.\pipe\$pipeService"
$env:MASKING_CONTROL_PATH = "\\.\pipe\$pipeControl"
$env:MASKING_MANAGER_SOCKET_PATH = "\\.\pipe\$pipeManager"
$env:MASKING_MANAGER_EXE = $ManagerExe
$env:MASKING_EXPECTED_ORIGIN = 'http://127.0.0.1:18787'
$env:MASKING_HUMAN_BIND = '127.0.0.1:18787'

$processes = @()
try {
    $service = Start-Process -FilePath $ServiceExe -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $WorkDir 'service.out.log') `
        -RedirectStandardError (Join-Path $WorkDir 'service.err.log')
    $processes += $service
    $manager = Start-Process -FilePath $ManagerExe -ArgumentList @('--config', $managerConfig) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $WorkDir 'manager.out.log') `
        -RedirectStandardError (Join-Path $WorkDir 'manager.err.log')
    $processes += $manager

    # Ожидание готовности: оба канала должны ответить.
    $ready = $false
    for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
        Start-Sleep -Milliseconds 500
        if ($service.HasExited -or $manager.HasExited) { break }
        try {
            $a = Invoke-Http -Name $pipeService -Method GET -Path '/internal/v1/health/live'
            $b = Invoke-Http -Name $pipeManager -Method POST -Path '/internal/v1/tools/call' -Body '{}'
            $ready = $true
        } catch { }
    }
    Check 'оба процесса запущены и каналы отвечают' $ready
    Check 'служба не завершилась' (-not $service.HasExited)
    Check 'менеджер не завершился' (-not $manager.HasExited)
    if (-not $ready) { throw 'каналы не поднялись' }

    # Канал A (служба): живость через настоящий именованный канал.
    $r = Invoke-Http -Name $pipeService -Method GET -Path '/internal/v1/health/live'
    Check 'канал A: health/live отвечает 200' ($r.Status -eq 200) "(статус $($r.Status))"

    # Канал B (менеджер): запрос от доверенной (той же) учётной записи доходит до обработчика.
    # Неизвестный инструмент даёт 404 method_not_found, а чужому — 403 forbidden.
    $body = '{"instance_id":"ras:x:y","name":"execute_query","arguments":{}}'
    $r = Invoke-Http -Name $pipeManager -Method POST -Path '/internal/v1/tools/call' -Body $body
    Check 'канал B: доверенный запрос доходит до обработчика (404, не 403)' ($r.Status -eq 404) "(статус $($r.Status))"
    Check 'канал B: ответ method_not_found' ($r.Text -match 'method_not_found')

    # Канал C: первоначальная установка пароля, как делает `masking-service admin bootstrap`.
    $password = 'Smoke-Password-123456'
    $line = (@{ password = $password } | ConvertTo-Json -Compress) + "`n"
    $first = Invoke-Pipe -Name $pipeControl -Request $line
    Check 'канал C: первая установка пароля успешна' ($first -match '"success"\s*:\s*true') "($($first.Trim()))"
    $second = Invoke-Pipe -Name $pipeControl -Request $line
    Check 'канал C: повторная установка пароля отвергнута' ($second -match '"success"\s*:\s*false') "($($second.Trim()))"

    # Удалённый доступ к каналам отвергнут.
    foreach ($name in @($pipeService, $pipeManager, $pipeControl)) {
        $remoteRejected = $false
        try {
            $remote = New-Object System.IO.Pipes.NamedPipeClientStream(
                'localhost', $name, [System.IO.Pipes.PipeDirection]::InOut)
            $remote.Connect(3000)
            $remote.Dispose()
        } catch { $remoteRejected = $true }
        Check "удалённое подключение к каналу $name отвергнуто" $remoteRejected
    }

    # Процессы живы до конца проверок: ни один не упал от запросов.
    Check 'служба жива после проверок' (-not $service.HasExited)
    Check 'менеджер жив после проверок' (-not $manager.HasExited)
} catch {
    Write-Host "ОШИБКА: $_"
    $script:failed = $true
} finally {
    foreach ($p in $processes) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force } }
    foreach ($log in 'service.out.log', 'service.err.log', 'manager.out.log', 'manager.err.log') {
        $path = Join-Path $WorkDir $log
        if (Test-Path $path) {
            Write-Host "----- $log -----"
            Get-Content $path -TotalCount 60
        }
    }
}

$results | ForEach-Object { Write-Host $_ }
if ($script:failed) { exit 1 }
Write-Host 'Дымовая проверка пройдена.'
