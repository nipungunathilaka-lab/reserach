# check_tee_capability.ps1
# Script to verify TEE capabilities natively

Write-Host "## TEE capability check"
Write-Host ""

try {
    $info = Get-ComputerInfo
    Write-Host "Windows version: $($info.WindowsVersion)"
    Write-Host "Windows build: $($info.OsBuildNumber)"
    Write-Host "OS Architecture: $($info.OsArchitecture)"
} catch {
    Write-Host "Windows version: UNKNOWN"
}

try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
    $vbsEnabled = if ($dg.VirtualizationBasedSecurityStatus -eq 2) { "YES" } else { "NO" }
    $hvciEnabled = if ($dg.CodeIntegrityPolicyEnforcementStatus -eq 2) { "YES" } else { "NO" }
    Write-Host "VBS enabled: $vbsEnabled"
    Write-Host "HVCI enabled: $hvciEnabled"
} catch {
    Write-Host "VBS enabled: UNKNOWN"
    Write-Host "HVCI enabled: UNKNOWN"
}

try {
    $tpm = Get-Tpm
    if ($tpm.TpmPresent) {
        Write-Host "TPM status: PRESENT ($($tpm.ManufacturerVersion))"
    } else {
        Write-Host "TPM status: NOT PRESENT"
    }
} catch {
    Write-Host "TPM status: UNKNOWN"
}

Write-Host "VBS Enclave supported: NO (Missing MSVC/CMake tooling)"
Write-Host "Native enclave binary: MISSING"
Write-Host "Enclave initialization: FAIL"
Write-Host "Enclave cryptographic self-test: FAIL"
Write-Host ""
Write-Host "FINAL:"
Write-Host "REAL_TEE_VERIFIED = NO"
