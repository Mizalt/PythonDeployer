# install_deployer.ps1
# Script for automated Python Deployer installation on Windows

# --- Configuration Variables ---
$DeployerRepoUrl = "https://github.com/Mizalt/PythonDeployer/archive/refs/heads/main.zip"
$DeployerZipName = "PythonDeployer.zip"
# Assuming the GitHub ZIP extracts to a folder named "PythonDeployer-main"
$DeployerDirName = "PythonDeployer-main"

$InstallPath = "C:\PythonDeployer"
$DataDir = "C:\deployer-data"
$NginxVersion = "1.29.1" # Target Nginx version (check if available on Chocolatey)
$PythonVersion = "3.12" # Target Python version
$DeployerServiceName = "PythonDeployer"
$NginxServiceName = "Nginx" # Name for the Nginx Windows service
$DeployerHttpPort = 7999
$CertificatesDir = Join-Path $DataDir "certs" # Directory for SSL certificates

# --- Administrator Rights Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run with Administrator privileges." -ForegroundColor Red
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    Exit
}

Write-Host "=== Starting Python Deployer automated installation ===" -ForegroundColor Green

# --- 1. Install Chocolatey (if not installed) ---
Write-Host "Checking for Chocolatey..." -ForegroundColor Cyan
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey not found. Installing..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072 # For TLS 1.2
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Error: Chocolatey failed to install. Please install manually and restart the script." -ForegroundColor Red
        Exit 1
    }
    Write-Host "Chocolatey successfully installed." -ForegroundColor Green
    Start-Sleep -Seconds 5 # Give system time to update PATH
} else {
    Write-Host "Chocolatey is already installed." -ForegroundColor Green
}

# --- 2. Ensure Python, Nginx, NSSM are available (intelligent checks) ---
Write-Host "Ensuring Python, Nginx, and NSSM are available..." -ForegroundColor Cyan

# --- Python ---
$PythonPath = $null
$WindowsAppsPythonStubPath = "C:\Users\User\AppData\Local\Microsoft\WindowsApps\python.exe"
$DefaultChocolateyPythonDir = "C:\Python$($PythonVersion.Replace('.', ''))" # e.g., C:\Python312
$DefaultChocolateyPythonExe = Join-Path $DefaultChocolateyPythonDir "python.exe"

# Function to verify if Python has pip
function Test-PythonHasPip {
    param([string]$PythonExePath)
    if (Test-Path $PythonExePath) {
        try {
            $pipCheck = & "$PythonExePath" -m pip --version 2>&1 | Out-String
            return $pipCheck -like "*pip*"
        } catch {
            return $false
        }
    }
    return $false
}

# 1. Try to find a non-stub Python in PATH with pip
$FoundPythonCmd = Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if ($FoundPythonCmd -and ($FoundPythonCmd -notlike "*Microsoft\WindowsApps*") -and (Test-PythonHasPip $FoundPythonCmd)) {
    Write-Host "Full Python installation with pip found in PATH at '$FoundPythonCmd'. Using this Python." -ForegroundColor Green
    $PythonPath = $FoundPythonCmd
} elseif (Test-Path $DefaultChocolateyPythonExe) { # Check if Chocolatey-installed Python already exists
    if (Test-PythonHasPip $DefaultChocolateyPythonExe) { # And if it has pip
        Write-Host "Full Python installation from Chocolatey at '$DefaultChocolateyPythonExe' with pip found. Using this Python." -ForegroundColor Green
        $PythonPath = $DefaultChocolateyPythonExe
        # Ensure its directory is in the current session's PATH
        if ($env:Path -notlike "*$DefaultChocolateyPythonDir*") {
            $env:Path = "$env:Path;$DefaultChocolateyPythonDir;$DefaultChocolateyPythonDir\Scripts"
            Write-Host "Added '$DefaultChocolateyPythonDir' and its Scripts to PATH for current session." -ForegroundColor Yellow
        }
    }
}

# If PythonPath is still null, it means no suitable Python was found automatically.
if (-not $PythonPath) {
    Write-Host "No suitable Python installation with pip automatically detected. Attempting to install Python $PythonVersion via Chocolatey." -ForegroundColor Yellow

    # Uninstall any previous partial Chocolatey install that might be causing MSI 1603
    Write-Host "Attempting to uninstall any existing Chocolatey Python to ensure clean install..." -ForegroundColor Yellow
    choco uninstall python --version $PythonVersion -y --limit-output -ErrorAction SilentlyContinue | Out-Null
    choco uninstall python3 --version $PythonVersion -y --limit-output -ErrorAction SilentlyContinue | Out-Null
    choco uninstall python312 --version $PythonVersion -y --limit-output -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Installing Python $PythonVersion via Chocolatey..." -ForegroundColor Yellow
    try {
        choco install python --version $PythonVersion -y --force
        if (Test-Path $DefaultChocolateyPythonExe) {
            $PythonPath = $DefaultChocolateyPythonExe
            Write-Host "Chocolatey Python $PythonVersion installed at '$PythonPath'." -ForegroundColor Green
            if ($env:Path -notlike "*$DefaultChocolateyPythonDir*") {
                $env:Path = "$env:Path;$DefaultChocolateyPythonDir;$DefaultChocolateyPythonDir\Scripts"
                Write-Host "Added '$DefaultChocolateyPythonDir' and its Scripts to PATH for current session." -ForegroundColor Yellow
            }
            # Explicitly ensure pip is present and updated for this Chocolatey-installed Python
            Write-Host "Ensuring pip is installed and up-to-date for '$PythonPath'..." -ForegroundColor Yellow
            & "$PythonPath" -m ensurepip --default-pip 2>&1 | Out-Null
            & "$PythonPath" -m pip install --upgrade pip 2>&1 | Out-Null
            if (-not (Test-PythonHasPip $PythonPath)) {
                Write-Host "Error: Python installed via Chocolatey, but pip is still not functional. Manual intervention may be required." -ForegroundColor Red
                Exit 1
            }
        } else {
            Write-Host "Error: Chocolatey Python installation completed, but '$DefaultChocolateyPythonExe' was not found." -ForegroundColor Red
            Write-Host "Please check your Chocolatey log for details." -ForegroundColor Red
            Exit 1
        }
    } catch {
        Write-Host "Error: Python installation via Chocolatey failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please ensure no conflicting Python installations or pending reboots exist." -ForegroundColor Red
        Exit 1
    }
}

# Final check to ensure we have a valid Python executable path AND pip
if (-not $PythonPath -or -not (Test-Path $PythonPath) -or -not (Test-PythonHasPip $PythonPath)) {
    Write-Host "Critical Error: A functional Python executable with pip could not be determined. Script cannot proceed." -ForegroundColor Red
    Exit 1
}
# --- END Python block ---


# --- Nginx ---
# Explicitly define Nginx's expected installation root from Chocolatey
$NginxChocolateyInstallRoot = Join-Path "C:\tools" "nginx-$NginxVersion" # e.g., C:\tools\nginx-1.29.1
$NginxExecutablePath = Join-Path $NginxChocolateyInstallRoot "nginx.exe"
$NginxPath = $null # Initialize NginxPath

if (Test-Path $NginxExecutablePath) {
    Write-Host "Nginx found at '$NginxExecutablePath'. Using existing Nginx installation." -ForegroundColor Green
    $NginxPath = $NginxExecutablePath
    # Ensure Nginx's root directory is in PATH for current session if Nginx was pre-existing
    if ($env:Path -notlike "*$NginxChocolateyInstallRoot*") {
        $env:Path = "$env:Path;$NginxChocolateyInstallRoot"
        Write-Host "Added '$NginxChocolateyInstallRoot' to PATH for current session (Nginx pre-check)." -ForegroundColor Yellow
    }
} else {
    Write-Host "Nginx not found at '$NginxExecutablePath'. Installing Nginx $NginxVersion via Chocolatey..." -ForegroundColor Yellow
    try {
        # Attempt to uninstall any existing Nginx to ensure a clean install of the target version.
        Write-Host "Attempting to uninstall any existing Chocolatey Nginx to ensure clean install..." -ForegroundColor Yellow
        choco uninstall nginx --version $NginxVersion -y --limit-output -ErrorAction SilentlyContinue | Out-Null

        choco install nginx --version $NginxVersion -y --force

        # Explicitly add Nginx's install directory to the PATH for the current PowerShell session.
        if ($env:Path -notlike "*$NginxChocolateyInstallRoot*") {
            $env:Path = "$env:Path;$NginxChocolateyInstallRoot"
            Write-Host "Added '$NginxChocolateyInstallRoot' to PATH for current session (Nginx install)." -ForegroundColor Yellow
        }

        # Verify Nginx path after installation and PATH update by checking the file directly
        if (Test-Path $NginxExecutablePath) {
            $NginxPath = $NginxExecutablePath
            Write-Host "Nginx confirmed at '$NginxPath' after installation." -ForegroundColor Green
        } else {
            Write-Host "Error: Nginx was installed, but 'nginx.exe' not found at '$NginxExecutablePath'. Please verify installation." -ForegroundColor Red
            Exit 1
        }

    } catch {
        Write-Host "Error: Nginx installation via Chocolatey failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please check if Nginx version $NginxVersion is available on Chocolatey." -ForegroundColor Red
        Exit 1
    }
}
# Final check for Nginx availability. $NginxPath should now hold the correct executable path.
if (-not $NginxPath) { Write-Host "Critical Error: Nginx executable not found after all attempts. Script cannot proceed." -ForegroundColor Red; Exit 1 }


# --- NSSM ---
$NssmPath = (Get-Command nssm -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
if ($NssmPath) {
    Write-Host "NSSM found at '$NssmPath'. Skipping Chocolatey install." -ForegroundColor Green
} else {
    Write-Host "NSSM not found. Installing NSSM via Chocolatey..." -ForegroundColor Yellow
    try {
        choco install nssm -y --force
        $NssmPath = (Get-Command nssm -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    } catch {
        Write-Host "Error: NSSM installation via Chocolatey failed: $($_.Exception.Message)" -ForegroundColor Red
        Exit 1
    }
    if (-not $NssmPath) { Write-Host "Error: NSSM not found after Chocolatey install. Please verify installation." -ForegroundColor Red; Exit 1 }
}

Write-Host "All required components are available:" -ForegroundColor Green
Write-Host "  Python: $PythonPath" -ForegroundColor Green
Write-Host "  Nginx: $NginxPath" -ForegroundColor Green
Write-Host "  NSSM: $NssmPath" -ForegroundColor Green

refreshenv # Final refresh for good measure, ensures system-wide PATH updates are considered

# --- 3. Download and Extract Python Deployer ---
Write-Host "Downloading Python Deployer..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
Set-Location $InstallPath

try {
    Invoke-WebRequest -Uri $DeployerRepoUrl -OutFile $DeployerZipName
    Expand-Archive -Path $DeployerZipName -DestinationPath $InstallPath -Force
    Remove-Item $DeployerZipName
    Write-Host "Python Deployer successfully downloaded and extracted to $InstallPath" -ForegroundColor Green
} catch {
    Write-Host "Error downloading/extracting Deployer: $($_.Exception.Message)" -ForegroundColor Red
    Exit 1
}

# --- CRITICAL FIX: Move contents of the extracted subfolder to the top level $InstallPath ---
$SourceDeployerPath = Join-Path $InstallPath $DeployerDirName
if (Test-Path $SourceDeployerPath) {
    Write-Host "Moving Deployer files from subfolder '$DeployerDirName' to top level '$InstallPath'..." -ForegroundColor Cyan

    # Move all items (files and subdirectories) from the source to the destination
    Get-ChildItem -Path $SourceDeployerPath -Force | ForEach-Object {
        Move-Item -LiteralPath $_.FullName -Destination $InstallPath -Force -ErrorAction SilentlyContinue
    }

    # Remove the now empty (or almost empty) source directory
    Remove-Item $SourceDeployerPath -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "Deployer files moved successfully." -ForegroundColor Green
} else {
    Write-Host "WARNING: Extracted Deployer subfolder '$SourceDeployerPath' not found. Assuming files are directly in '$InstallPath' (uncommon for GitHub ZIPs)." -ForegroundColor Yellow
}

# --- 4. Nginx Configuration: Main nginx.conf rewrite (interactive) ---
Write-Host "Configuring Nginx..." -ForegroundColor Cyan

$NginxChocolateyRoot = Split-Path -Parent $NginxPath # This should resolve to C:\tools\nginx-1.29.1
$NginxConfFile = Join-Path $NginxChocolateyRoot "conf\nginx.conf"
$NginxSitesDir = Join-Path $DataDir "nginx-sites"
New-Item -ItemType Directory -Force -Path $CertificatesDir | Out-Null # Ensure certs directory exists

Write-Host "WARNING: This script will OVERWRITE the main Nginx configuration file at '$NginxConfFile'." -ForegroundColor Red
Write-Host "         If you have custom Nginx settings in there, they will be lost." -ForegroundColor Red
$confirmOverwrite = Read-Host "Do you want to proceed and overwrite '$NginxConfFile' with a new Deployer-optimized configuration? (Y/N)"

if ($confirmOverwrite -eq 'Y' -or $confirmOverwrite -eq 'y') {
    $CertificatesDirForNginx = $CertificatesDir.Replace('\', '/')
    $NginxSitesDirForNginx = $NginxSitesDir.Replace('\', '/')

    $NginxDeployerConfContent = @"
# nginx.conf for Python Deployer
# This configuration is generated by the Python Deployer installer.

# Worker processes: number of CPU cores or slightly more
worker_processes  auto; # Use 'auto' to let Nginx determine optimal number

events {
    worker_connections  1024;
    # multi_accept on;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    gzip  on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml+rss text/javascript;

    # --- Server block for HTTP (Port 80) ---
    server {
        listen 80;
        server_name _;
        location / {
            proxy_pass http://127.0.0.1:$DeployerHttpPort;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto `$scheme;
            proxy_http_version 1.1;
            proxy_set_header Upgrade `$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 86400;
        }
    }

    # --- Include additional site configurations ---
    # This allows Deployer to manage other app's Nginx configs in this directory
    include "$NginxSitesDirForNginx/*.conf";

    # You can add more server blocks here for other applications managed by Deployer.
    # The Deployer itself will generate these files in C:/deployer-data/nginx-sites/
}
"@
    Write-Host "Overwriting Nginx main configuration file at '$NginxConfFile'..." -ForegroundColor Yellow
    Set-Content -Path $NginxConfFile -Value $NginxDeployerConfContent -Force
    Write-Host "Nginx.conf successfully overwritten." -ForegroundColor Green
} else {
    Write-Host "Skipping Nginx main configuration overwrite. Manual configuration may be required." -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path $NginxSitesDir | Out-Null # Ensure this directory exists


# --- 5. Configure Deployer's config.py ---
Write-Host "Configuring Deployer's config.py..." -ForegroundColor Cyan

$DeployerConfigPath = Join-Path $InstallPath "app\config.py"
if (Test-Path $DeployerConfigPath) {
    $ConfigContent = Get-Content $DeployerConfigPath -Raw

    $ConfigContent = $ConfigContent -replace 'DATA_DIR = Path\(`".+?"`\)', "DATA_DIR = Path(`"$DataDir`")"

    $ConfigContent = $ConfigContent -replace 'NGINX_DIR = Path\(`".+?"`\)', "NGINX_DIR = Path(`"$NginxChocolateyRoot`")"
    $ConfigContent = $ConfigContent -replace 'NGINX_MAIN_CONF_FILE = NGINX_DIR \/ "conf" \/ "nginx.conf"', "NGINX_MAIN_CONF_FILE = NGINX_DIR / `"conf`" / `"nginx.conf`""
    $ConfigContent = $ConfigContent -replace 'NGINX_RELOAD_CMD = f''.+?''', "NGINX_RELOAD_CMD = f'`"`$NGINX_DIR / `"nginx.exe`"`" -p `"`$NGINX_DIR`"`" -s reload'"

    $ConfigContent = $ConfigContent -replace 'NSSM_PATH = ".+?"', "NSSM_PATH = `"$($NssmPath.Replace('\', '/'))`"" # Use forward slashes
    $ConfigContent = $ConfigContent -replace 'NGINX_SITES_DIR = Path\(`".+?"`\)', "NGINX_SITES_DIR = Path(`"$NginxSitesDir`")"

    $ConfigContent = $ConfigContent -replace 'PYTHON_EXECUTABLES = {[^}]*}', "PYTHON_EXECUTABLES = {`n    `"Python $PythonVersion (System/Chocolatey)`": `"$($PythonPath.Replace('\', '/'))`"`n}"
    $ConfigContent = $ConfigContent -replace 'DEFAULT_PYTHON_EXECUTABLE = [^\r\n]*', "DEFAULT_PYTHON_EXECUTABLE = `"$($PythonPath.Replace('\', '/'))`""


    Set-Content -Path $DeployerConfigPath -Value $ConfigContent
    Write-Host "Deployer's config.py successfully configured." -ForegroundColor Green
} else {
    Write-Host "Error: Deployer's config.py not found at $DeployerConfigPath." -ForegroundColor Red
    Exit 1
}

# --- 6. Install Deployer's dependencies ---
Write-Host "Installing Deployer's dependencies..." -ForegroundColor Cyan
$DeployerPythonExecutable = $PythonPath
$DeployerRequirements = Join-Path $InstallPath "requirements.txt"

if (Test-Path $DeployerRequirements) {
    try {
        Write-Host "Upgrading pip and installing dependencies..." -ForegroundColor Yellow
        & "$DeployerPythonExecutable" -m pip install --upgrade pip
        & "$DeployerPythonExecutable" -m pip install -r "$DeployerRequirements"
        Write-Host "Deployer's dependencies successfully installed." -ForegroundColor Green
    } catch {
        Write-Host "Error installing Deployer's dependencies: $($_.Exception.Message)" -ForegroundColor Red
        Exit 1
    }
} else {
    Write-Host "WARNING: Deployer's requirements.txt not found. Skipping dependency installation." -ForegroundColor Yellow
}

# --- 7. (Optional) Create the first user ---
Write-Host "Creating the first Deployer user..." -ForegroundColor Cyan
try {
    Write-Host "Please enter username and password for the Deployer panel (interactively)." -ForegroundColor Yellow
    & "$DeployerPythonExecutable" "$InstallPath\create_user.py"
    Write-Host "Deployer user created." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to create user: $($_.Exception.Message). You can run 'python.exe $InstallPath\create_user.py' manually later." -ForegroundColor Yellow
}


# --- 8. Install Python Deployer as a Windows service using NSSM ---
Write-Host "Installing Python Deployer as a Windows service..." -ForegroundColor Cyan

$NssmExe = $NssmPath
# Determine Python's actual home directory
$PythonHomeDir = Split-Path $DeployerPythonExecutable -Parent # e.g., C:\Python312

try {
    Write-Host "Attempting to remove existing '$DeployerServiceName' service (if any)..." -ForegroundColor Yellow
    # Check if the service exists before trying to stop/remove, to avoid errors
    $Service = Get-Service -Name $DeployerServiceName -ErrorAction SilentlyContinue
    if ($Service) {
        if ($Service.Status -ne 'Stopped') {
            Stop-Service -InputObject $Service -Force -ErrorAction SilentlyContinue
            Write-Host "Service '$DeployerServiceName' stopped." -ForegroundColor Green
            Start-Sleep -Seconds 2 # Give it a moment to fully stop
        }
        & "$NssmExe" remove "$DeployerServiceName" confirm | Out-Null 2>&1
        Write-Host "Existing service '$DeployerServiceName' removed." -ForegroundColor Green
    } else {
        Write-Host "Service '$DeployerServiceName' not found, no need to remove." -ForegroundColor Green
    }


    Write-Host "Installing service '$DeployerServiceName'..." -ForegroundColor Yellow
    & "$NssmExe" install "$DeployerServiceName" "$DeployerPythonExecutable"
    & "$NssmExe" set "$DeployerServiceName" AppParameters "-m uvicorn app.main:app --host 127.0.0.1 --port $DeployerHttpPort" # If you have a logging.ini, consider adding: --log-config $(Join-Path $InstallPath 'logging.ini')"
    & "$NssmExe" set "$DeployerServiceName" AppDirectory "$InstallPath"
    & "$NssmExe" set "$DeployerServiceName" AppStdout "$DataDir\deployer_service.log"
    & "$NssmExe" set "$DeployerServiceName" AppStderr "$DataDir\deployer_service.log"
    & "$NssmExe" set "$DeployerServiceName" AppEnvironmentExtra "PYTHONUNBUFFERED=1;PYTHONHOME=$PythonHomeDir" # CRITICAL FIX: Add PYTHONHOME here
    & "$NssmExe" set "$DeployerServiceName" Description "Python Deployer - Web interface for managing Python applications"
    & "$NssmExe" set "$DeployerServiceName" DisplayName "Python Deployer"

    Write-Host "Starting service '$DeployerServiceName'..." -ForegroundColor Yellow
    & "$NssmExe" start "$DeployerServiceName"
    Write-Host "Python Deployer successfully installed and started as a Windows service!" -ForegroundColor Green
} catch {
    Write-Host "Error installing/starting Deployer service: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "You can try to start Deployer manually: '$DeployerPythonExecutable' -m uvicorn app.main:app --host 127.0.0.1 --port $DeployerHttpPort" -ForegroundColor Red
    Exit 1
}

# --- 9. Configure and Start Nginx Service ---
Write-Host "Configuring and starting Nginx service..." -ForegroundColor Cyan

# Create Nginx config for Deployer UI (e.g., C:\deployer-data\nginx-sites\deployer-main.conf)
$DeployerNginxConfFile = Join-Path $NginxSitesDir "deployer-main.conf"
$NginxDeployerConfigContent = @"
server {
    listen 80;
    server_name _; # Listen on all hostnames for now, or specify your public IP/domain

    location / {
        proxy_pass http://127.0.0.1:$DeployerHttpPort;
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto `$scheme;
        # Add WebSocket proxy headers
        proxy_http_version 1.1;
        proxy_set_header Upgrade `$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400; # Keep WebSocket connection open
    }
}
"@

# Note: The main Nginx config (nginx.conf) is being overwritten by interactive prompt in block 4.
# This config file (deployer-main.conf) will be included by the main config.
Write-Host "Creating Nginx config file for Deployer UI at '$DeployerNginxConfFile'..." -ForegroundColor Yellow
Set-Content -Path $DeployerNginxConfFile -Value $NginxDeployerConfigContent -Force
Write-Host "Nginx config for Deployer UI created." -ForegroundColor Green

# Install Nginx as a Windows service using NSSM
try {
    Write-Host "Attempting to remove existing '$NginxServiceName' service (if any)..." -ForegroundColor Yellow
    $NginxService = Get-Service -Name $NginxServiceName -ErrorAction SilentlyContinue
    if ($NginxService) {
        if ($NginxService.Status -ne 'Stopped') {
            Stop-Service -InputObject $NginxService -Force -ErrorAction SilentlyContinue
            Write-Host "Service '$NginxServiceName' stopped." -ForegroundColor Green
            Start-Sleep -Seconds 2
        }
        & "$NssmExe" remove "$NginxServiceName" confirm | Out-Null 2>&1
        Write-Host "Existing service '$NginxServiceName' removed." -ForegroundColor Green
    } else {
        Write-Host "Service '$NginxServiceName' not found, no need to remove." -ForegroundColor Green
    }

    Write-Host "Installing Nginx as service '$NginxServiceName'..." -ForegroundColor Yellow
    & "$NssmExe" install "$NginxServiceName" "$NginxPath"
    & "$NssmExe" set "$NginxServiceName" AppDirectory "$NginxChocolateyRoot" # Nginx's working directory
    & "$NssmExe" set "$NginxServiceName" AppParameters "-p `"$NginxChocolateyRoot`"" # Specify Nginx config path
    & "$NssmExe" set "$NginxServiceName" Description "Nginx web server for Python Deployer and managed applications"
    & "$NssmExe" set "$NginxServiceName" DisplayName "Nginx for Python Deployer"

    Write-Host "Starting Nginx service '$NginxServiceName'..." -ForegroundColor Yellow
    & "$NssmExe" start "$NginxServiceName"
    Write-Host "Nginx service successfully installed and started!" -ForegroundColor Green

} catch {
    Write-Host "Error installing/starting Nginx service: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "You can try to start Nginx manually by running 'nginx.exe' in '$NginxChocolateyRoot'." -ForegroundColor Red
    Exit 1
}

# --- Open Port 80 in Windows Firewall ---
Write-Host "Opening port 80 in Windows Firewall..." -ForegroundColor Cyan
try {
    # Check if a rule for port 80 already exists
    $FwRule = Get-NetFirewallRule -DisplayName "Python Deployer Nginx HTTP (Port 80)" -ErrorAction SilentlyContinue
    if (-not $FwRule) {
        New-NetFirewallRule -DisplayName "Python Deployer Nginx HTTP (Port 80)" `
                            -Direction Inbound `
                            -Action Allow `
                            -Protocol TCP `
                            -LocalPort 80 `
                            -Profile Any `
                            -Description "Allow HTTP traffic for Nginx serving Python Deployer UI"
        Write-Host "Firewall rule for Port 80 (HTTP) created successfully." -ForegroundColor Green
    } else {
        Write-Host "Firewall rule for Port 80 (HTTP) already exists." -ForegroundColor Green
        Set-NetFirewallRule -DisplayName "Python Deployer Nginx HTTP (Port 80)" -Enabled True -Action Allow -Protocol TCP -LocalPort 80 -Profile Any
    }
} catch {
    Write-Host "WARNING: Failed to configure Windows Firewall for Port 80: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Please ensure Port 80 is open in your firewall if you experience connection issues." -ForegroundColor Yellow
}


Write-Host ""
Write-Host "=== Python Deployer and Nginx installation complete! ===" -ForegroundColor Green
Write-Host "The Deployer panel should now be accessible externally via Nginx on Port 80." -ForegroundColor Green
Write-Host "Try opening your server's public IP address or domain in a browser: http://<YOUR_SERVER_IP_OR_DOMAIN>/" -ForegroundColor Green
Write-Host "For direct access (if Nginx isn't proxying), use: http://localhost:$DeployerHttpPort" -ForegroundColor Green
Write-Host "Use the user you created earlier to log in." -ForegroundColor Green
Write-Host ""
