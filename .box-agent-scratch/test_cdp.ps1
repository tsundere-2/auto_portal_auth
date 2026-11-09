$edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$tmp = "$env:TEMP\cdptest"
$p = Start-Process -FilePath $edge -ArgumentList "--remote-debugging-port=19222","--headless=new","--user-data-dir=$tmp","about:blank" -PassThru
Start-Sleep -Seconds 5
try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:19222/json/version' -TimeoutSec 5 -UseBasicParsing
    Write-Output "CDP OK:"
    Write-Output $r.Content
} catch {
    Write-Output ("CDP FAIL: " + $_.Exception.Message)
}
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Get-Process msedge -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.StartTime -gt (Get-Date).AddMinutes(-2) } | Stop-Process -Force -ErrorAction SilentlyContinue
