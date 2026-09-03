<#
.SYNOPSIS
    Packages the source code into a clean ZIP file on the Desktop.

.DESCRIPTION
    This script copies the project source code to a temporary folder on the Desktop,
    explicitly excluding heavy dependencies (node_modules, venv), git history,
    database files, media, and sensitive env files. It then compresses the clean 
    source into a ZIP archive for easy distribution or backup.
#>

$ErrorActionPreference = "Stop"

try {
    Write-Host "Starting source packaging process..." -ForegroundColor Cyan

    $src = (Get-Location).Path
    $dst = "$env:USERPROFILE\Desktop\UPCE-source-only"
    $zipPath = "$env:USERPROFILE\Desktop\UPCE-source-only.zip"

    Write-Host "Step 1: Creating temporary directory on Desktop: $dst"
    # Create the destination directory, forcefully overwriting if it exists
    New-Item -ItemType Directory -Force -Path $dst | Out-Null

    Write-Host "Step 2: Copying files (Excluding node_modules, venv, .git, .env, media, etc.)..."
    # Copy files using robocopy
    # /E: Copy subdirectories, including empty ones
    # /XD: Exclude specific directories
    # /XF: Exclude specific files
    # /NP: No progress (reduces log noise)
    # /NFL /NDL: No file list, no directory list (keeps output clean)
    robocopy $src $dst /E /XD node_modules venv .venv __pycache__ .git dist build coverage storage logs /XF .env *.db *.sqlite *.pfce *.mp4 *.mkv *.avi *.zip *.joblib *.png *.jpg *.jpeg *.pem *.key /NP /NFL /NDL

    # Robocopy exit codes:
    # 0 = No files copied (source and destination are in sync)
    # 1 = One or more files were copied successfully
    # 2 = Extra files or directories were detected in destination
    # 3 = Some files were copied, some extra files were present
    # >3 = Errors occurred
    if ($LASTEXITCODE -gt 3) {
        throw "Robocopy failed with exit code $LASTEXITCODE"
    }

    Write-Host "Step 3: Compressing to ZIP archive at: $zipPath"
    # Compress the copied files into a ZIP archive on the Desktop
    Compress-Archive -Path "$dst\*" -DestinationPath $zipPath -Force

    Write-Host "Step 4: Cleaning up temporary directory..."
    # Remove the unzipped temporary folder to leave only the ZIP file
    Remove-Item -Recurse -Force -Path $dst

    Write-Host "Success! Clean source code has been zipped to: $zipPath" -ForegroundColor Green
}
catch {
    Write-Host "An error occurred during packaging: $_" -ForegroundColor Red
    exit 1
}
