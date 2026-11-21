$projectRoot = Split-Path -Parent $PSScriptRoot
$environmentNames = @('FLASK_ENV', 'FLASK_DEBUG', 'DEV_LIVE_RELOAD', 'DEV_EXTERNAL_RELOAD', 'HOST', 'PORT')
$previousEnvironment = @{}
$sourceIdentifiers = @('GvpDevPythonChanged', 'GvpDevPythonCreated', 'GvpDevPythonRenamed', 'GvpDevPythonDeleted')
$serverProcess = $null
$watcher = $null
$subscriptions = @()

foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    $env:FLASK_ENV = 'development'
    $env:FLASK_DEBUG = '1'
    $env:DEV_LIVE_RELOAD = '1'
    $env:DEV_EXTERNAL_RELOAD = '1'
    $env:HOST = '127.0.0.1'
    $env:PORT = if ([string]::IsNullOrWhiteSpace($env:DEV_PORT)) { '5001' } else { $env:DEV_PORT }

    $logDirectory = Join-Path $projectRoot 'logs'
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    $stdoutPath = Join-Path $logDirectory 'dev-server.out.log'
    $stderrPath = Join-Path $logDirectory 'dev-server.err.log'
    $pythonPath = (Get-Command python -ErrorAction Stop).Source

    $watcher = [System.IO.FileSystemWatcher]::new($projectRoot, '*.py')
    $watcher.IncludeSubdirectories = $true
    $watcher.NotifyFilter = [System.IO.NotifyFilters]::LastWrite -bor [System.IO.NotifyFilters]::FileName
    $subscriptions += Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier $sourceIdentifiers[0]
    $subscriptions += Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier $sourceIdentifiers[1]
    $subscriptions += Register-ObjectEvent -InputObject $watcher -EventName Renamed -SourceIdentifier $sourceIdentifiers[2]
    $subscriptions += Register-ObjectEvent -InputObject $watcher -EventName Deleted -SourceIdentifier $sourceIdentifiers[3]
    $watcher.EnableRaisingEvents = $true

    function Start-DevServer {
        Start-Process -FilePath $pythonPath -ArgumentList @('app.py') -WorkingDirectory $projectRoot `
            -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    }

    Push-Location $projectRoot
    try {
        $serverProcess = Start-DevServer
        Write-Host "Development server: http://127.0.0.1:$env:PORT"
        Write-Host 'Template and static changes refresh the browser. Python changes restart the local app automatically.'
        Write-Host "Server logs: $stdoutPath and $stderrPath"

        while ($true) {
            $serverProcess.Refresh()
            if ($serverProcess.HasExited) {
                Write-Host 'The development server stopped. Check the error log shown above.'
                break
            }

            $eventRecord = Wait-Event -Timeout 1
            if (-not $eventRecord) { continue }
            if ($sourceIdentifiers -notcontains $eventRecord.SourceIdentifier) {
                Remove-Event -EventIdentifier $eventRecord.EventIdentifier -ErrorAction SilentlyContinue
                continue
            }

            $changedPath = $eventRecord.SourceEventArgs.FullPath
            Start-Sleep -Milliseconds 400
            foreach ($queuedEvent in @(Get-Event | Where-Object { $sourceIdentifiers -contains $_.SourceIdentifier })) {
                Remove-Event -EventIdentifier $queuedEvent.EventIdentifier -ErrorAction SilentlyContinue
            }

            $serverProcess.Refresh()
            if (-not $serverProcess.HasExited) {
                Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $serverProcess.Id -Timeout 5 -ErrorAction SilentlyContinue
            }
            Start-Sleep -Milliseconds 250
            $serverProcess = Start-DevServer
            Write-Host "Python change detected; app restarted for $changedPath"
        }
    }
    finally {
        if ($serverProcess) {
            $serverProcess.Refresh()
            if (-not $serverProcess.HasExited) {
                Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
            }
        }
        Pop-Location
    }
}
finally {
    if ($watcher) { $watcher.Dispose() }
    foreach ($subscription in $subscriptions) {
        Unregister-Event -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue
    }
    foreach ($queuedEvent in @(Get-Event -ErrorAction SilentlyContinue | Where-Object { $sourceIdentifiers -contains $_.SourceIdentifier })) {
        Remove-Event -EventIdentifier $queuedEvent.EventIdentifier -ErrorAction SilentlyContinue
    }
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
}
