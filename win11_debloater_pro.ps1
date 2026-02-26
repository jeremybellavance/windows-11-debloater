<#
    .SYNOPSIS
        Win11DebloaterPro — custom Windows 11 debloating and optimization script.

    .DESCRIPTION
        Removes unwanted preinstalled applications, disables telemetry and consumer
        features, deactivates Copilot/AI components, and applies a handful of
        performance tweaks.  The script uses an allowlist approach to avoid
        removing essential packages.  All actions are logged to a file on the
        desktop so you can audit what was changed and revert if necessary.

        IMPORTANT:  Run this script from an elevated PowerShell session (as
        Administrator).  Always test in a virtual machine or on a non‑production
        device before deploying widely.
#>

param()

# Verify the script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as an Administrator.  Exiting."
    exit 1
}

# Set up a simple logger.  Logs are written to a file on the current user's
# desktop.  Existing log files will be overwritten.
$logPath = Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\DebloatLog.txt'
New-Item -Path $logPath -ItemType File -Force | Out-Null
function Write-Log {
    param(
        [string] $Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp`t$Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
    Write-Host "$Message"
}

Write-Log "Starting Win11DebloaterPro …"

# Define a list of packages to keep.  Anything not matching these patterns will be
# considered removable.  Modify this list as needed for your environment.
$AllowList = @(
    '*WindowsCalculator*',
    '*Office.OneNote*',
    '*Microsoft.NET*',
    '*MicrosoftEdge*',
    '*WindowsStore*',
    '*WindowsTerminal*',
    '*WindowsNotepad*',
    '*Paint*'
)

function Remove-Bloatware {
    Write-Log "Removing non‑essential AppX packages …"
    $packages = Get-AppxPackage -AllUsers
    foreach ($pkg in $packages) {
        $keep = $false
        foreach ($pattern in $AllowList) {
            if ($pkg.Name -like $pattern) { $keep = $true; break }
        }
        # Skip packages marked as nonremovable or ones on the allowlist
        if (-not $keep -and -not $pkg.NonRemovable) {
            Write-Log "Attempting to remove $($pkg.Name) …"
            try {
                Remove-AppxPackage -AllUsers -Package $pkg.PackageFullName -ErrorAction Stop
                Write-Log "Removed $($pkg.Name)"
            } catch {
                Write-Log "Failed to remove $($pkg.Name): $($_.Exception.Message)"
            }
        }
    }
    Write-Log "AppX removal step complete."
}

function Disable-Telemetry {
    Write-Log "Disabling Windows telemetry …"
    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    New-Item -Path $regPath -Force | Out-Null
    New-ItemProperty -Path $regPath -Name 'AllowTelemetry' -Value 0 -PropertyType DWord -Force | Out-Null
    Write-Log "Telemetry disabled via AllowTelemetry = 0."
}

function Disable-ConsumerFeatures {
    Write-Log "Disabling consumer features (Teams, Cortana, News/Interests, cloud content) …"
    # Computer‑wide policies
    $computerPolicies = @(
        @{Key='Software\Microsoft\Windows\CurrentVersion\Communications';     ValueName='ConfigureChatAutoInstall';       Data=0},
        @{Key='Software\Policies\Microsoft\Windows\Windows Chat';              ValueName='ChatIcon';                       Data=2},
        @{Key='Software\Policies\Microsoft\Windows\Windows Search';            ValueName='AllowCortana';                   Data=0},
        @{Key='Software\Policies\Microsoft\Windows\Windows Feeds';             ValueName='EnableFeeds';                    Data=0},
        @{Key='Software\Policies\Microsoft\Windows\Windows Search';            ValueName='DisableWebSearch';               Data=1},
        @{Key='Software\Policies\Microsoft\Windows\CloudContent';              ValueName='DisableCloudOptimizedContent';    Data=1},
        @{Key='Software\Policies\Microsoft\Windows\CloudContent';              ValueName='DisableConsumerAccountStateContent'; Data=1},
        @{Key='Software\Policies\Microsoft\Windows\CloudContent';              ValueName='DisableWindowsConsumerFeatures';   Data=1},
        @{Key='Software\Policies\Microsoft\Windows\CloudContent';              ValueName='DisableWindowsSpotlightFeatures';  Data=1}
    )
    foreach ($policy in $computerPolicies) {
        $path = "HKLM:\$($policy.Key)"
        New-Item -Path $path -Force | Out-Null
        New-ItemProperty -Path $path -Name $policy.ValueName -Value $policy.Data -PropertyType DWord -Force | Out-Null
    }
    # Per‑user policies
    $userPolicies = @(
        @{Key='Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; ValueName='TaskbarMn';               Data=0},
        @{Key='Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';  ValueName='HideSCAMeetNow';         Data=1},
        @{Key='Software\Microsoft\Windows\CurrentVersion\Search';             ValueName='SearchboxTaskbarMode';    Data=1}
    )
    foreach ($policy in $userPolicies) {
        $path = "HKCU:\$($policy.Key)"
        New-Item -Path $path -Force | Out-Null
        New-ItemProperty -Path $path -Name $policy.ValueName -Value $policy.Data -PropertyType DWord -Force | Out-Null
    }
    Write-Log "Consumer features disabled via Group Policy keys."
}

function Remove-Copilot {
    Write-Log "Removing Microsoft Copilot (all users) …"
    try {
        Get-AppxPackage -AllUsers | Where-Object { $_.Name -like '*Microsoft.Copilot*' } | Remove-AppxPackage -ErrorAction Stop
        Write-Log "Copilot removed."
    } catch {
        Write-Log "Failed to remove Copilot: $($_.Exception.Message)"
    }
}

function Disable-AIComponents {
    Write-Log "Disabling AI‑related features (Copilot/Recall/ClickToDo) via registry …"
    $aiSettings = @(
        @{Path='HKLM:\Software\Policies\Microsoft\Windows\GenAI'; Name='DisableCopilot'; Value=1},
        @{Path='HKLM:\Software\Policies\Microsoft\Windows\GenAI'; Name='DisableRecall';  Value=1},
        @{Path='HKLM:\Software\Policies\Microsoft\Windows\GenAI'; Name='DisableClickToDo'; Value=1}
    )
    foreach ($setting in $aiSettings) {
        New-Item -Path $setting.Path -Force | Out-Null
        New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType DWord -Force | Out-Null
    }
    Write-Log "AI features disabled via GenAI policy keys."
}

function Optimize-System {
    Write-Log "Applying system optimizations …"
    # Disable Fast Startup / hibernate
    try {
        powercfg /hibernate off | Out-Null
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0
        Write-Log "Fast startup/hibernate disabled."
    } catch {
        Write-Log "Failed to disable Fast Startup: $($_.Exception.Message)"
    }
    # Activate high‑performance power plan if present
    try {
        $guid = (powercfg /list | Select-String -Pattern 'High performance' | ForEach-Object { ($_ -split '\s+')[3] })
        if ($guid) {
            powercfg /setactive $guid | Out-Null
            Write-Log "High performance power plan activated."
        } else {
            Write-Log "High performance power plan not found; skipping power plan activation."
        }
    } catch {
        Write-Log "Failed to set high performance power plan: $($_.Exception.Message)"
    }
    Write-Log "System optimizations complete."
}

# Execute the steps in order
Remove-Bloatware
Disable-Telemetry
Disable-ConsumerFeatures
Remove-Copilot
Disable-AIComponents
Optimize-System

Write-Log "Win11DebloaterPro finished.  Review the log file at $logPath for details."