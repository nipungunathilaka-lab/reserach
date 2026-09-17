$ports = @(5173, 5001, 8000)
Write-Output "PORT`tSTATE`t`tPID`tPROCESS`t`tCOMMAND"
Write-Output "-------------------------------------------------------------------------------"
foreach ($port in $ports) {
    $conn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) {
        $pidNum = $conn.OwningProcess
        $proc = Get-Process -Id $pidNum -ErrorAction SilentlyContinue
        $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$pidNum" -ErrorAction SilentlyContinue
        $name = $proc.Name
        $cmd = $wmi.CommandLine
        Write-Output "$port`tOCCUPIED`t$pidNum`t$name`t$cmd"
    } else {
        Write-Output "$port`tFREE"
    }
}
