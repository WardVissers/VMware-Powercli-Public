<#
    Secure Boot PK / KEK remediation workflow
    Cleaned up version with consistent $vmObj usage inside functions

    Building My Own Simplified FixSecureBoot Script
    I recently created my own version of a FixSecureBoot script — a lightweight alternative inspired by the excellent work of haz-ard-9, the author of  FixSecureBootBulk.ps1. Their script is powerful and absolutely the right choice if you rely on BitLocker or need a fully automated, safety first workflow.
    However, at roughly 3,000 lines of code, the original script is understandably complex. It includes many checks and safeguards, which are great for production environments but made it harder for me to fully understand what was happening under the hood. I wanted something simpler, easier to read, and tailored to my own workflow.
    So I took the time to study the original script, copied only the parts I needed, and built a much more compact version that gives me exactly the result I want — which show the  verification step that every thing is correct updated.
    What My Script Does
    Here’s the full sequence of actions my simplified script performs:
    1.	Ask for Template or VM
    2.    Shuts down the VM
    3.	Creates a snapshot
    4.	Enables UEFI Setup Mode
    5.	Clears VMRAM (for older VMs)
    6.	Upgrades virtual hardware if the VM is below version 21 (vSphere 8)
    7.	Starts the VM and waits for VMware Tools
    8.	Checks that the guest OS is fully online
    9.	Downloads the required certificates (only once)
    10.	Uploads the two certificates to the VM if not exist
    11.	Installs the new boot certificates
    12.	Shuts down the VM and clears Setup Mode
    13.	Boots the VM and sets AvailableUpdates to 0x5944 (certs ready for install)
    14.	Reboots until AvailableUpdates becomes 0x4100 (may require multiple reboots)
    15.	Reboots and runs Secure-Boot-Update again

#>

# =============================================================================
# SCRIPT LOCATION
# =============================================================================
switch ((Get-Host).Name) {
    'Windows PowerShell ISE Host' { $current_file_folder = $psISE.CurrentFile.FullPath -replace ($psISE.CurrentFile.DisplayName, "") }
    'ConsoleHost'                 { $current_file_folder = $MyInvocation.MyCommand.Path -replace ($MyInvocation.MyCommand.Name, "") }
    'Visual Studio Code Host'     { $current_file_folder = $psEditor.GetEditorContext().CurrentFile.Path | Split-Path }
}
Set-Location $current_file_folder

#Define LogFile with time stamp
$LogTime = Get-Date -Format "MM-dd-yyyy_hh-mm-ss"
    
$LogPath = Join-Path $current_file_folder $env:USERNAME

# Create folder if it does not exist
if (-not (Test-Path -Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# =============================================================================
# GLOBAL DEFAULTS
# =============================================================================
$CheckInterval  = 5
$TimeoutSeconds = 150
$MaxTries       = 10
$DelaySeconds   = 10

# =============================================================================
# FUNCTIONS
# =============================================================================

Function Write-log
{
   Param ([string]$logstring)
   #Add logtime to entry
   $LogTime = Get-Date -Format "MM-dd-yyyy_HH-mm-ss"
   $logstring = $LogTime + " : " + $logstring
   #Write logstring
   Add-content $LogFile -value $logstring
   Write-Host $logstring
}
function Invoke-GracefulShutdown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [int]$TimeoutSeconds = 150,
        [int]$CheckInterval = 5
    )

    write-host "`nProcessing VM: $VMName" -ForegroundColor Cyan
    write-log "`nProcessing VM: $VMName"

    try {
        $vmObj = Get-VM -Name $VMName -ErrorAction Stop
    }
    catch {
        Write-Warning "VM not found: $VMName"
        return $false
    }

    if ($vmObj.PowerState -eq 'PoweredOff') {
        write-host "VM is already powered off." -ForegroundColor Yellow
        write-log "VM is already powered off."
        return $true
    }

    $toolsStatus = $vmObj.ExtensionData.Guest.ToolsStatus
    if ($toolsStatus -in @('toolsOk', 'toolsOld')) {
        write-host "VMware Tools detected: $toolsStatus" -ForegroundColor Green
        write-log "VMware Tools detected: $toolsStatus"
        }
    else {
        Write-Warning "VMware Tools not running or not installed. Graceful shutdown may fail."
    }

    write-log "Sending guest shutdown..."
    write-host "Sending guest shutdown..." -ForegroundColor White
    Shutdown-VMGuest -VM $vmObj -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds $CheckInterval
        $elapsed += $CheckInterval

        $vmObj = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        if ($vmObj.PowerState -eq 'PoweredOff') {
            write-host "✔ VM powered off gracefully" -ForegroundColor Green
            write-log "✔ VM powered off gracefully"
            return $true
        }
    }

    Write-Warning "Graceful shutdown timed out. Forcing power off..."
    Stop-VM -VM $vmObj -Confirm:$false | Out-Null

    Start-Sleep -Seconds $CheckInterval
    $vmObj = Get-VM -Name $VMName -ErrorAction SilentlyContinue

    if ($vmObj.PowerState -eq 'PoweredOff') {
        write-host "⚡ VM forced off successfully" -ForegroundColor Green
        write-log "⚡ VM forced off successfully"
        return $true
    }

    Write-Error "❌ Failed to power off VM: $VMName"
    return $false
}

function Add-VMDK {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [string]$VMDKPath
    )

    $vmObj = Get-VM -Name $VMName -ErrorAction Stop

    $existing = Get-HardDisk -VM $vmObj | Where-Object {
        $_.Filename -eq $VMDKPath
    }

    if ($existing) {
        write-host "Disk already attached to VM: $VMDKPath" -ForegroundColor Yellow
        write-log "Disk already attached to VM: $VMDKPath"
        return
    }

    New-HardDisk -VM $vmObj -DiskPath $VMDKPath -Confirm:$false | Out-Null
    write-host "VMDK attached successfully to $($vmObj.Name)" -ForegroundColor Green
    write-log "VMDK attached successfully to $($vmObj.Name)"
}

function Wait-VMToolsRunning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [int]$TimeoutSeconds = 90,
        [int]$CheckInterval = 5
    )

    $vmObj = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if (-not $vmObj) {
        return [PSCustomObject]@{
            VM      = $VMName
            Status  = 'NotFound'
            Message = "VM '$VMName' not found."
        }
    }

    $start = Get-Date

    while ($true) {
        $vmObj = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        $elapsed = (Get-Date) - $start
        $percent = [math]::Min(100, ($elapsed.TotalSeconds / $TimeoutSeconds) * 100)

        Write-Progress `
            -Activity "Waiting for VMware Tools on $VMName" `
            -Status "Elapsed: $([int]$elapsed.TotalSeconds)s / $TimeoutSeconds s" `
            -PercentComplete $percent

        $toolsStatus = $vmObj.ExtensionData.Guest.ToolsRunningStatus

        if ($toolsStatus -eq 'guestToolsRunning') {
            Write-Progress -Activity "Waiting for VMware Tools on $VMName" -Completed
            return [PSCustomObject]@{
                VM      = $vmObj.Name
                Status  = 'Running'
                Message = 'VMware Tools is running.'
            }
        }

        if ($elapsed.TotalSeconds -ge $TimeoutSeconds) {
            Write-Progress -Activity "Waiting for VMware Tools on $VMName" -Completed
            return [PSCustomObject]@{
                VM      = $vmObj.Name
                Status  = 'Timeout'
                Message = 'Timed out waiting for VMware Tools to start.'
            }
        }

        Start-Sleep -Seconds $CheckInterval
    }
}

function Wait-GuestIdKnown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMname,
        [int]$TimeoutSeconds = 180
    )

    $elapsed = 0
    write-host "    Waiting for VMware Tools + guest context..." -ForegroundColor Gray
    write-log "    Waiting for VMware Tools + guest context..."

    while ($elapsed -lt $TimeoutSeconds) {
        $vmObj = Get-VM -Name $VMname -ErrorAction SilentlyContinue

        $toolsRunning = $vmObj.ExtensionData.Guest.ToolsRunningStatus -eq 'guestToolsRunning'
        $guestId      = $vmObj.GuestId
        $guestFam     = $vmObj.Guest.GuestFamily
        $hostName     = $vmObj.Guest.HostName

        if ($toolsRunning -and $guestId -and $guestFam -and $hostName) {
            write-host "    Guest context confirmed: GuestId=$guestId | Family=$guestFam | Host=$hostName" -ForegroundColor Green
            write-log  "    Guest context confirmed: GuestId=$guestId | Family=$guestFam | Host=$hostName"
            return $true
        }

        Start-Sleep -Seconds 5
        $elapsed += 5

        write-log ("    ...${elapsed}s (Tools={0} | GuestId={1} | Family={2} | HostName={3})" -f `
            $vmObj.ExtensionData.Guest.ToolsRunningStatus,
            $(if ($guestId) { $guestId } else { '?' }),
            $(if ($guestFam) { $guestFam } else { '?' }),
            $(if ($hostName) { $hostName } else { '?' }))
    }

    Write-Warning "    Timed out waiting for guest context on $VMObj - proceeding anyway."
    return $false
}


function Run-InGuest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMObj,

        [Parameter(Mandatory)]
        [pscredential]$GuestCredential,

        [Parameter(Mandatory)]
        [string]$Script
    )

    Invoke-VMScript `
        -VM $VMObj `
        -ScriptText $Script `
        -ScriptType Powershell `
        -GuestUser $GuestCredential.UserName `
        -GuestPassword $GuestCredential.GetNetworkCredential().Password
}

function Set-VMXOption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMObj,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$Value
    )

    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $extra = New-Object VMware.Vim.OptionValue
    $extra.Key = $Key
    $extra.Value = $Value
    $spec.ExtraConfig = @($extra)

    (Get-VM $VMObj | Get-View).ReconfigVM($spec)
}

function Get-VMXOption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMObj,

        [Parameter(Mandatory)]
        [string]$Key
    )

    (Get-VM $VMObj | Get-View).Config.ExtraConfig |
        Where-Object { $_.Key -eq $Key } |
        Select-Object -ExpandProperty Value -First 1
}

function Remove-VMSnapshotWithProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$VMName,

        [string[]]$ExcludeNamePattern = @('Restore*', '*Replica*'),

        [switch]$OnlyPoweredOn
    )

    try {
        $vmObjects = Get-VM -Name $VMName -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to get VM(s): $($_.Exception.Message)"
        return
    }

    if ($OnlyPoweredOn) {
        $vmObjects = $vmObjects | Where-Object { $_.PowerState -eq 'PoweredOn' }
    }

    if (-not $vmObjects) {
        Write-Warning "No VM objects found after filtering."
        return
    }

    $snapshots = $vmObjects | Get-Snapshot -ErrorAction SilentlyContinue

    foreach ($pattern in $ExcludeNamePattern) {
        $snapshots = $snapshots | Where-Object { $_.Name -notlike $pattern }
    }

    if (-not $snapshots) {
        Write-Host "No snapshots found to remove." -ForegroundColor Yellow
        return
    }

    $total   = @($snapshots).Count
    $current = 0

    foreach ($snap in $snapshots) {
        $current++

        try {
            Write-Host "Starting removal of snapshot '$($snap.Name)' on VM '$($snap.VM.Name)'" -ForegroundColor Cyan

            $task = Remove-Snapshot -Snapshot $snap -Confirm:$false -RunAsync -ErrorAction Stop

            do {
                try {
                    $task.ExtensionData.UpdateViewData("Info.State", "Info.Progress", "Info.Error")
                    $state   = $task.ExtensionData.Info.State
                    $percent = $task.ExtensionData.Info.Progress

                    if ($null -eq $percent) {
                        $percent = 0
                    }

                    Write-Progress `
                        -Id 1 `
                        -Activity "Removing snapshot $current of $total" `
                        -Status "$($snap.VM.Name) - $($snap.Name)" `
                        -PercentComplete $percent
                }
                catch {
                    # If task info cannot be refreshed anymore, stop polling
                    Write-Verbose "Could not refresh task state: $($_.Exception.Message)"
                    break
                }

                Start-Sleep -Seconds 2
            }
            while ($state -eq 'running' -or $state -eq 'queued')

            if ($state -eq 'success') {
                Write-Host "Removed snapshot '$($snap.Name)' on VM '$($snap.VM.Name)'" -ForegroundColor Green
            }
            elseif ($state -eq 'error') {
                $errMsg = $task.ExtensionData.Info.Error.LocalizedMessage
                Write-Warning "Snapshot removal failed for '$($snap.Name)' on VM '$($snap.VM.Name)': $errMsg"
            }
            else {
                Write-Host "Task finished, but final state could not be fully confirmed for '$($snap.Name)' on VM '$($snap.VM.Name)'" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Warning "Failed to remove snapshot '$($snap.Name)' on VM '$($snap.VM.Name)': $($_.Exception.Message)"
        }
    }

    Write-Progress -Id 1 -Activity "Removing snapshots" -Completed
    Write-Host "Snapshot removal completed for $($vmObjects.Count) VM(s)" -ForegroundColor Green
}

function Wait-ToolsWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [int]$MaxTries = 10,
        [int]$DelaySeconds = 10,
        [int]$TimeoutSeconds = 90
    )

    for ($i = 1; $i -le $MaxTries; $i++) {
        write-host "Checking VMware Tools (attempt $i of $MaxTries)..."
        write-log "Checking VMware Tools (attempt $i of $MaxTries)..."
        $result = Wait-VMToolsRunning -VMName $VMName -TimeoutSeconds $TimeoutSeconds

        if ($result.Status -eq 'Running') {
            write-host "VMware Tools are running." -ForegroundColor Green
            write-log "VMware Tools are running."
            return $true
        }
        write-host "VMware Tools not ready yet. Waiting $DelaySeconds seconds..." -ForegroundColor Yellow
        write-log "VMware Tools not ready yet. Waiting $DelaySeconds seconds..."
        Start-Sleep -Seconds $DelaySeconds
    }

    Write-Warning "VMware Tools did not become ready after $MaxTries attempts."
    return $false
}

function Download-File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Filename,

        [Parameter(Mandatory)]
        [string]$Url
    )

    $fullPath = Join-Path $current_file_folder $Filename

    if (Test-Path $fullPath) {
        Write-Host "File already exists: $fullPath" -ForegroundColor Green
        write-log "File already exists: $fullPath" 
        return $fullPath
    }

    write-host "Downloading $Filename from $Url..."
    write-log "Downloading $Filename from $Url..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Url -OutFile $fullPath
    write-host "Download complete: $fullPath"
    write-log "Download complete: $fullPath"

    return $fullPath
}

function Invoke-VMHardwareUpgrade {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMObj,

        [Parameter(Mandatory)]
        [int]$TargetVersion,

        [int]$TimeoutSeconds = 120
    )

    $result = [ordered]@{
        Upgraded    = $false
        FromVersion = $null
        ToVersion   = $null
        Notes       = ''
    }

    try {
        $vmView     = Get-VM $VMObj | Get-View -ErrorAction Stop
        $currentVer = $vmView.Config.Version
        $currentNum = [int]($currentVer -replace '^vmx-', '')
        $result.FromVersion = $currentNum
        $result.ToVersion   = $TargetVersion

        if ($currentNum -ge $TargetVersion) {
            $result.Notes = "Already at version $currentNum or higher."
            return [pscustomobject]$result
        }

        write-host "    Upgrading hardware version: vmx-$currentNum -> vmx-$TargetVersion" -ForegroundColor Cyan
        write-log "    Upgrading hardware version: vmx-$currentNum -> vmx-$TargetVersion"
        $taskMoRef = $vmView.UpgradeVM_Task("vmx-$TargetVersion")
        $taskView  = Get-View -Id $taskMoRef -ErrorAction Stop
        $elapsed   = 0

        while ($taskView.Info.State -in @('running', 'queued')) {
            if ($elapsed -ge $TimeoutSeconds) {
                throw "Timed out waiting for hardware upgrade task."
            }
            Start-Sleep -Seconds 3
            $elapsed += 3
            $taskView = Get-View -Id $taskMoRef
        }

        if ($taskView.Info.State -eq 'success') {
            $vmView = Get-View -Id $vmView.MoRef
            $newNum = [int]($vmView.Config.Version -replace '^vmx-', '')
            $result.ToVersion = $newNum
            $result.Upgraded  = $true
            $result.Notes     = 'Hardware upgraded successfully.'
            write-host "    Hardware version upgraded to vmx-$newNum." -ForegroundColor Green
            write-log "    Hardware version upgraded to vmx-$newNum."
        }
        else {
            $err = $taskView.Info.Error.LocalizedMessage
            if (-not $err) { $err = 'Unknown task error.' }
            $result.Notes = "Upgrade failed: $err"
            Write-Warning "    $($result.Notes)"
        }
    }
    catch {
        $result.Notes = "Upgrade error: $($_.Exception.Message)"
        Write-Warning "    $($result.Notes)"
        Write-Log " $($result.Notes)"
    }

    [pscustomobject]$result
}

# Returns the maximum hardware version supported by the ESXi host where the VM is "running" on
function Get-MaxHWVersionForHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMObj
    )

    try {
        $vmHost  = Get-VMHost -VM $VMObj -ErrorAction Stop
        $esxiVer = [version]$vmHost.Version

        switch ($esxiVer.Major) {
            9 { return 22 }
            8 { return 21 }
            7 { return 19 }
            default { return 21 }
        }
    }
    catch {
        Write-Warning "Could not determine ESXi host version for $($VMObj.Name) - defaulting to HW version 21."
        Write-Log "Could not determine ESXi host version for $($VMObj.Name) - defaulting to HW version 21."
        return 21
    }
}

function Wait-DatastoreTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Task,

        [int]$TimeoutSeconds = 30
    )

    $taskView = Get-View $Task
    $elapsed = 0

    while ($taskView.Info.State -notin @('success', 'error') -and $elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 2
        $elapsed += 2
        $taskView = Get-View $Task
    }

    if ($taskView.Info.State -eq 'success') {
        return $true
    }

    Write-Warning "    Datastore task failed: $($taskView.Info.Error.LocalizedMessage)"
    return $false
}

function Get-VMDatastoreContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMObj
    )

    $vmView  = Get-VM $VMObj | Get-View
    $vmxPath = $vmView.Config.Files.VmPathName
    $dsName  = $vmxPath -replace '^\[(.+?)\].*', '$1'
    $vmDir   = $vmxPath -replace '^\[.+?\] (.+)/[^/]+$', '$1'
    $ds      = Get-Datastore -Name $dsName -ErrorAction Stop

    $datacenter      = Get-Datacenter -VM $VMObj
    $datacenterView  = $datacenter | Get-View
    $serviceInstance = Get-View ServiceInstance

    return @{
        DsName      = $dsName
        VmDir       = $vmDir
        DsBrowser   = Get-View $ds.ExtensionData.Browser
        DcRef       = $datacenterView.MoRef
        FileManager = Get-View $serviceInstance.Content.FileManager
    }
}

function Rename-VMNvram {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$VMObj
    )

    try {
        $ctx  = Get-VMDatastoreContext -VMObj $VMObj

        $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
        $spec.MatchPattern = @('*.nvram')

        $results = $ctx.DsBrowser.SearchDatastoreSubFolders(
            "[$($ctx.DsName)] $($ctx.VmDir)", $spec
        )

        $files = $results | ForEach-Object { $_.File }

        if (-not $files) {
            Write-Warning "    No .nvram file found for $($VMObj.Name)"
            Write-Log "    No .nvram file found for $($VMObj.Name)"
            return $false
        }

        $nvramFile = $files |
            Where-Object { $_.Path -match '\.nvram$' -and $_.Path -notmatch '_old|_new' } |
            Select-Object -First 1

        if (-not $nvramFile) {
            Write-Warning "    Active .nvram file not found (may already be renamed)"
            Write-Log "    Active .nvram file not found (may already be renamed)"
            return $false
        }

        $oldPath = "[$($ctx.DsName)] $($ctx.VmDir)/$($nvramFile.Path)"
        $newName = $nvramFile.Path -replace '\.nvram$', '.nvram_old'
        $newPath = "[$($ctx.DsName)] $($ctx.VmDir)/$newName"

        Write-Host "    Renaming: $($nvramFile.Path) -> $newName" -ForegroundColor Cyan
        Write-Log  "    Renaming: $($nvramFile.Path) -> $newName"

        $task = $ctx.FileManager.MoveDatastoreFile_Task(
            $oldPath, $ctx.DcRef, $newPath, $ctx.DcRef, $true
        )

        if (Wait-DatastoreTask -Task $task) {
            Write-Host "    NVRAM renamed successfully." -ForegroundColor Green
            Write-Log  "    NVRAM renamed successfully."
            return $true
        }

        Write-Warning "    NVRAM rename task did not complete successfully."
        Write-Log  "    NVRAM rename task did not complete successfully."
        return $false
    }
    catch {
        Write-Warning "    NVRAM rename failed: $($_.Exception.Message)"
        Write-Log  "    NVRAM rename failed: $($_.Exception.Message)"
        return $false
    }
}

function Copy-IfNotExistsInGuest {
    param (
        [string]$Source,
        [string]$Destination,
        [string]$Description
    )

    # Check if source exists locally
    if (-not (Test-Path $Source)) {
        write-host "$Description not found locally: $Source" -ForegroundColor Yellow
        write-log "$Description not found locally: $Source"
        return
    }

    try {
        # Check inside guest
        $script = "Test-Path '$Destination'"
        $result = Invoke-VMScript -VM $VM `
                                 -ScriptText $script `
                                 -GuestCredential $GuestCredential `
                                 -ScriptType PowerShell

        if ($result.ScriptOutput.Trim() -eq "True") {
            write-host "$Description already exists in guest, skipping copy." -ForegroundColor Yellow
            write-log "$Description already exists in guest, skipping copy."
            return
            }

        # Copy file if not exists
        Copy-VMGuestFile -Source $Source `
                         -Destination $Destination `
                         -VM $VM `
                         -LocalToGuest `
                         -GuestCredential $GuestCredential `
                         -Force `
                         -ErrorAction Stop

        write-host "$Description copied successfully." -ForegroundColor Green
        write-log "$Description copied successfully."
    }
    catch {
        write-host "Error processing $Description : $_" -ForegroundColor Red
        write-log "Error processing $Description : $_"
       }
    }

function Connect-ToVCenter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$vCenter,

        [string]$vCenterCredFile = (Join-Path $current_file_folder "$($env:USERNAME)vCenter_Creds.xml")
    )

    $connected = $false

    do {
        # Eerst proberen met opgeslagen credentials
        if ((Test-Path $vCenterCredFile) -and -not $connected) {
            Write-Host "Credential file found. Attempting login..." -ForegroundColor Yellow

            try {
                $vCenterCreds = Import-Clixml -Path $vCenterCredFile -ErrorAction Stop

                $null = Connect-VIServer `
                    -Server $vCenter `
                    -Credential $vCenterCreds `
                    -AllLinked `
                    -ErrorAction Ignore

                Write-Host "Successfully connected using stored credentials." -ForegroundColor Green
                $connected = $true
            }
            catch {
                Write-Warning "Stored credential login failed: $($_.Exception.Message)"
                Remove-Item $vCenterCredFile -Force -ErrorAction SilentlyContinue
            }
        }

        # Als nog niet connected: vraag nieuwe credentials
        if (-not $connected) {
            Write-Host "Please enter vCenter credentials." -ForegroundColor Cyan
            $vCenterCreds = Get-Credential -Message "Enter credentials for $vCenter"

            try {
                $null = Connect-VIServer `
                    -Server $vCenter `
                    -Credential $vCenterCreds `
                    -AllLinked `
                    -ErrorAction Ignore

                Write-Host "Login successful. Saving credentials..." -ForegroundColor Green
                $vCenterCreds | Export-Clixml -Path $vCenterCredFile
                $connected = $true
            }
            catch {
                Write-Host "Login failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

    } until ($connected)

    return $true
}

# =============================================================================
# GUEST SCRIPTS
# =============================================================================

$CheckEventid = @'
try {
    $event = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Id      = 1801, 1808
    } -MaxEvents 1 -ErrorAction Stop

    switch ($event.Id) {
        1801 {
            "EVENT_1801_FOUND"
             exit 0
        }
        1808 {
            "EVENT_1808_FOUND"
            exit 0
        }
        default {
            "EVENT_UNKNOWN_FOUND: $($event.Id)"
            exit 0
        }
    }
}
catch {
    if ($_.FullyQualifiedErrorId -eq 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand') {
        "EVENT_1801_OR_1808_NOT_FOUND"
        exit 0
    }
    else {
        "EVENT_ERROR: $($_.Exception.Message)"
        exit 1
    }
}
'@


$enrollPKScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$result = @{ PKEnrolled = $false; KEKUpdated = $false; Notes = "" }

$setupMode = (Get-SecureBootUEFI SetupMode -EA SilentlyContinue).Bytes
if ($setupMode -and $setupMode[0] -eq 1) {
    try {
        $pkFile = "C:\Windows\Temp\WindowsOEMDevicesPK.der"
        if (Test-Path $pkFile) {
            $ownerGuid = "55555555-0000-0000-0000-000000000000"
            Format-SecureBootUEFI -Name PK `
                -CertificateFilePath $pkFile `
                -SignatureOwner $ownerGuid `
                -FormatWithCert `
                -Time "2025-10-23T11:00:00Z" `
                -ErrorAction Stop |
            Set-SecureBootUEFI -Time "2025-10-23T11:00:00Z" -ErrorAction Stop

            $result["PKEnrolled"] = $true
            $result["Notes"] += "PK enrolled successfully. "
        }
        else {
            $result["Notes"] += "WindowsOEMDevicesPK.der not found. "
        }
    }
    catch {
        $result["Notes"] += "PK enrollment failed: $($_.Exception.Message) "
    }

    $kekFile = "C:\Windows\Temp\kek2023.der"
    if (Test-Path $kekFile) {
        try {
            $ownerGuid = "77fa9abd-0359-4d32-bd60-28f4e78f784b"
            Format-SecureBootUEFI -Name KEK `
                -CertificateFilePath $kekFile `
                -SignatureOwner $ownerGuid `
                -FormatWithCert `
                -AppendWrite `
                -Time "2025-10-23T11:00:00Z" `
                -ErrorAction Stop |
            Set-SecureBootUEFI -AppendWrite -Time "2025-10-23T11:00:00Z" -ErrorAction Stop

            $result["KEKUpdated"] = $true
            $result["Notes"] += "KEK 2023 updated successfully. "
        }
        catch {
            $result["Notes"] += "KEK update failed: $($_.Exception.Message) "
        }
    }
}
else {
    $result["Notes"] = "VM is NOT in SetupMode. Check uefi.secureBootMode.overrideOnce VMX option."
}

$result
'@

$certVerifyScript = @'
try {
    $kek = [System.Text.Encoding]::ASCII.GetString(
        (Get-SecureBootUEFI kek -ErrorAction Stop).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
    $db  = [System.Text.Encoding]::ASCII.GetString(
        (Get-SecureBootUEFI db -ErrorAction Stop).Bytes) -match 'Windows UEFI CA 2023'
    [PSCustomObject]@{ KEK_2023 = $kek.ToString(); DB_2023 = $db.ToString() } | ConvertTo-Json -Compress
} catch {
    [PSCustomObject]@{ KEK_2023 = "CheckFailed"; DB_2023 = "CheckFailed" } | ConvertTo-Json -Compress
}
'@


$SecureBootUpdate = @"
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot /v AvailableUpdates /t REG_DWORD /d 0x5944 /f
Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update'
"@

$RunTask = @"
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
"@

# =============================================================================
# vCenter Connection
# =============================================================================
 
# Zet InvalidCertificateAction op Ignore voor deze sessie
    $config = Get-PowerCLIConfiguration

    if ($config.InvalidCertificateAction -ne 'Ignore') {
        Write-Host "InvalidCertificateAction is not set to Ignore. Updating..." -ForegroundColor Yellow
        Set-PowerCLIConfiguration `
            -InvalidCertificateAction Ignore `
            -Scope Session `
            -Confirm:$false | Out-Null
        Write-Host "InvalidCertificateAction set to Ignore." -ForegroundColor Green
    }
    else {
        Write-Host "InvalidCertificateAction is already set to Ignore." -ForegroundColor Green
    }

 # Check if already connected
    if ($global:DefaultVIServers -and $global:DefaultVIServers.IsConnected) {
    write-host "Already connected to vCenter: $($global:DefaultVIServers.Name)" -ForegroundColor Green
    }
    else {
        $vCenter = read-host "What is the name of the vCenter"
        Connect-ToVCenter -vCenter $vCenter
    }

# =============================================================================
# Guest Connection
# =============================================================================

if (
    -not $GuestCredential -or
    -not $GuestCredential.UserName -or
    -not $GuestCredential.GetNetworkCredential().Password
) {
    $GuestCredential = Get-Credential -Message "Enter guest credentials"
}

# =============================================================================
# MAIN
# =============================================================================


do {

# Ask user if they want to select a template
$useTemplate = Read-Host "Do you want to select a template? (y/n)"

$selectedVM = $null

if ($useTemplate -match '^[Yy]$') {

    # Get templates
    $template  = Get-Template | Sort-Object Name | Out-GridView -Title "Select Template" -PassThru
    $templateName     = $template.Name
    if (-not $template) {
        Write-Warning "No Template Selected."
        return
    }

    Write-Host "`nConverting template '$($template.Name)' to VM..." -ForegroundColor Yellow

    try {
        $selectedVM = Set-Template -Template $template -ToVM -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to convert template to VM. Exiting."
        return
    }

    $timeoutSeconds = 60
    $elapsed = 0
    $interval = 2

    do {
        Start-Sleep -Seconds $interval
        $elapsed += $interval
        $VM = Get-VM -Name $templateName -ErrorAction SilentlyContinue
    }
    until ($VM -or $elapsed -ge $timeoutSeconds)

    if (-not $selectedVM) {
        Write-Warning "Template conversion completed, but VM '$templateName' was not found within $timeoutSeconds seconds. Exiting script."
        return
    }

}
elseif ($useTemplate -match '^[Nn]$') {

    # Get VMs
    $VM = Get-VM | Sort-Object Name | Out-GridView -Title "Select VM" -PassThru
}
else {
    Write-Warning "No VM selected. Exiting script."
    return
}

# Build logfile path properly
$LogFile = Join-Path $LogPath "$($VM.Name)-$LogTime.log"

Write-Host "`nSelected VM: $($VM.Name)" -ForegroundColor Green
Write-Log "`nSelected VM: $($VM.Name)"


If ($VM.PowerState -eq "PoweredOn")
{
Run-InGuest -VMObj $VM -GuestCredential $GuestCredential -Script $CheckEventid
 try {
        $result = Run-InGuest -VMObj $VM -GuestCredential $GuestCredential -Script $CheckEventid

        $output   = $result.ScriptOutput.Trim()
        $exitCode = $result.ExitCode

        if ($exitCode -ne 0) {
            Write-Warning "Script failed on $($VM.Name) with exit code $exitCode"
            Write-Warning $output
            Write-Log "Script failed on $($VM.Name): $output"
        }
        else {
            Write-Host "[$($VM.Name)] Script run Success"
            Write-Host $output
            Write-Log $output
        }
    }
    catch {
        Write-Error "Failed to execute script on $($VM.Name): $_"
        Write-Log "Failed to execute script on $($VM.Name): $_"
    }

    if ($output -eq "EVENT_1808_FOUND") {
        Write-Host "Event 1808 detected on $($VM.Name)" -ForegroundColor Green
        Write-Log "Event 1808 detected on $($VM.Name)"
    
        if ($useTemplate -match '^[Yy]$' -and $templateName) {
            Write-Host "`nReverting VM '$($VM.Name)' back to template..." -ForegroundColor Yellow
            Write-Log "Reverting VM '$($VM.Name)' back to template..."

            try {
                $VM = Get-VM -Name $VM.Name -ErrorAction Stop

                if ($VM.PowerState -ne "PoweredOff") {
                    Invoke-GracefulShutdown -VMName $VM.Name -TimeoutSeconds $TimeoutSeconds -CheckInterval $CheckInterval | Out-Null
                  }

                Set-VM -VM $VM -ToTemplate -Confirm:$false -ErrorAction Stop | Out-Null

                Write-Host "VM successfully reverted to template." -ForegroundColor Green
                Write-Log "VM successfully reverted to template."
            }
            catch {
                Write-Error "Failed to revert VM back to template!"
                Write-Log "Failed to revert VM back to template!"
            }
        }
    Break
    }
    elseif ($output -eq "EVENT_1808_NOT_FOUND") {
        Write-Host "Event 1808 NOT present on $($VM.Name), continuing..." -ForegroundColor Green
        Write-Log "Event 1808 NOT present on $($VM.Name), continuing..."
    }
    else {
        Write-Host "Unexpected output: $output" -ForegroundColor Red
        Write-Log "Unexpected output on $($VM.Name): $output"
    }
}
Else
{
    Start-VM $VM 
    Wait-ToolsWithRetry -VMName $VM.Name -MaxTries $MaxTries -DelaySeconds $DelaySeconds | Out-Null

    try {
        $result = Run-InGuest -VMObj $VM -GuestCredential $GuestCredential -Script $CheckEventid

        $output   = $result.ScriptOutput.Trim()
        $exitCode = $result.ExitCode

        if ($exitCode -ne 0) {
            Write-Warning "Script failed on $($VM.Name) with exit code $exitCode"
            Write-Warning $output
            Write-Log "Script failed on $($VM.Name): $output"
        }
        else {
            Write-Host "[$($VM.Name)] Script run Success"
            Write-Host $output
            Write-Log $output
        }
    }
    catch {
        Write-Error "Failed to execute script on $($VM.Name): $_"
        Write-Log "Failed to execute script on $($VM.Name): $_"
    }

    if ($output -eq "EVENT_1808_FOUND") {
        Write-Host "Event 1808 detected on $($VM.Name)" -ForegroundColor Green
        Write-Log "Event 1808 detected on $($VM.Name)"
    
        if ($useTemplate -match '^[Yy]$' -and $templateName) {
            Write-Host "`nReverting VM '$($VM.Name)' back to template..." -ForegroundColor Green
            Write-Log "Reverting VM '$($VM.Name)' back to template..."

            try {
                $VM = Get-VM -Name $VM.Name -ErrorAction Stop

                if ($VM.PowerState -ne "PoweredOff") {
                    Invoke-GracefulShutdown -VMName $VM.Name -TimeoutSeconds $TimeoutSeconds -CheckInterval $CheckInterval | Out-Null
                  }

                Set-VM -VM $VM -ToTemplate -Confirm:$false -ErrorAction Stop | Out-Null

                Write-Host "VM successfully reverted to template." -ForegroundColor Green
                Write-Log "VM successfully reverted to template."
            }
            catch {
                Write-Error "Failed to revert VM back to template!"
                Write-Log "Failed to revert VM back to template!"
            }
        }
    Break
    }
    elseif ($output -eq "EVENT_1808_NOT_FOUND") {
        Write-Host "Event 1808 NOT present on $($VM.Name), continuing..." -ForegroundColor Green
        Write-Log "Event 1808 NOT present on $($VM.Name), continuing..."
    }
    else {
        Write-Host "Unexpected output: $output" -ForegroundColor Red
        Write-Log "Unexpected output on $($VM.Name): $output"
    }
}

# ------------------------------------------------------------------
# Step 1 -  Power off (skipped if NVRAM already has 2023 certs)
# ------------------------------------------------------------------

write-host " [Step 1 PK Change] Shutdown the VM..." -ForegroundColor Cyan
write-log " [Step 1 PK Change] Shutdown the VM..."
Invoke-GracefulShutdown -VMName $VM.Name -TimeoutSeconds $TimeoutSeconds -CheckInterval $CheckInterval | Out-Null
$VM = Get-VM -Name $VM.Name

# ------------------------------------------------------------------
# Step 2 - Take snapshot 
# ------------------------------------------------------------------
write-host " [Step 2 PK Change] Create Snapshot..." -ForegroundColor Cyan
write-log " [Step 2 PK Change] Create Snapshot..."
$text = 'FixSecureboot'
New-Snapshot -VM $VM -Name $text -Description $text | Out-Null

# ------------------------------------------------------------------
# Step 3 - PK Change Setting UEFI SetupMode VMX option
# ------------------------------------------------------------------
write-host " [Step 3 PK Change] Setting UEFI SetupMode VMX option..." -ForegroundColor Cyan
write-log " [Step 3 PK Change] Setting UEFI SetupMode VMX option..."


# ------------------------------------------------------------------
# PK Change Setting UEFI SetupMode VMX option
# ------------------------------------------------------------------
Set-VMXOption -VMObj $VM -Key "uefi.secureBootMode.overrideOnce" -Value "SetupMode"
$optVal = Get-VMXOption -VMObj (Get-VM -Name $VM) -Key "uefi.secureBootMode.overrideOnce"
if ($optVal -ne 'SetupMode') {
    throw 'Failed to set uefi.secureBootMode.overrideOnce - check vCenter permissions.'
}
write-host "    SetupMode VMX option confirmed." -ForegroundColor Green
write-log "    SetupMode VMX option confirmed."
$vmView   = $VM | Get-View
$hwVerNum = [int](($vmView.Config.Version) -replace 'vmx-', '')

# ------------------------------------------------------------------
# Step 3A - Rename NVRAM (triggers fresh generation with 2023 certs)
# ------------------------------------------------------------------
write-host " [Step 3A PK Change] Clearing NVRAM..." -ForegroundColor Cyan
write-log " [Step 3A PK Change] Clearing NVRAM..."

$NVRAMRenamed = Rename-VMNvram -VMObj $VM
if (-not $NVRAMRenamed) {
    write-host "NVRAM rename failed - cert update may not succeed." -ForegroundColor Red
    write-log "NVRAM rename failed - cert update may not succeed."
}

# ------------------------------------------------------------------
# Step 3B - HW Upgrade if Needed
# ------------------------------------------------------------------
if ($hwVerNum -lt 21) {
    write-host " [Step 3B PK Change] Upgrading Hardware Version (current: $hwVerNum)..." -ForegroundColor Cyan
    write-log " [Step 3B PK Change] Upgrading Hardware Version (current: $hwVerNum)..."
        $upResult = Invoke-VMHardwareUpgrade -VMObj $VM -TargetVersion (Get-MaxHWVersionForHost -VMObj $VM)

    if ($upResult.Upgraded) {
        write-host "    Hardware upgraded: $hwVerNum -> $($upResult.ToVersion)" -ForegroundColor Yellow
        write-log "    Hardware upgraded: $hwVerNum -> $($upResult.ToVersion)"
        $vmObj = Get-VM -Name $VM.Name
        $hwVerNum = $upResult.ToVersion
    }
    else {
        write-host "    Hardware upgrade failed - continuing with existing version $hwVerNum." -ForegroundColor Red
        write-log "    Hardware upgrade failed - continuing with existing version $hwVerNum."
    }
}
else {
    write-host "Hardware version $hwVerNum >= 21 - no upgrade needed." -ForegroundColor Green
    write-log "Hardware version $hwVerNum >= 21 - no upgrade needed."
}

# ------------------------------------------------------------------
# Step 4 - Power on (ESXi regenerates NVRAM with 2023 KEK)
# ------------------------------------------------------------------
Start-VM $VM | Out-Null
Wait-ToolsWithRetry -VMName $VM.Name -MaxTries $MaxTries -DelaySeconds $DelaySeconds | Out-Null

Wait-GuestIdKnown -VMname $VM -TimeoutSeconds 180 | Out-Null

write-host " [Step 4 PK Change] Download Cer Files..." -ForegroundColor Cyan
write-log " [Step 4 PK Change] Download Cer Files..."
$PKDerPath  = Download-File -Filename 'WindowsOEMDevicesPK.der' -Url 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der'
$KEKDerPath = Download-File -Filename 'kek2023.der' -Url 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/KEK/Certificates/microsoft%20corporation%20kek%202k%20ca%202023.der'

write-host " [PK Change] Copying .der certificate file(s) to guest..." -ForegroundColor Cyan
write-log " [PK Change] Copying .der certificate file(s) to guest..."

Copy-IfNotExistsInGuest -Source $PKDerPath  -Destination 'C:\Windows\Temp\WindowsOEMDevicesPK.der'
Copy-IfNotExistsInGuest -Source $KEKDerPath -Destination 'C:\Windows\Temp\kek2023.der' 

write-host "Step 5 Install New Boot Certs" -ForegroundColor Green
write-log "Step 5 Install New Boot Certs"

try {
    $result = Run-InGuest -VMObj $VM -GuestCredential $GuestCredential -Script $enrollPKScript

    if ($result.ExitCode -ne 0) {
        Write-Warning "Script failed on $($vm.Name) with exit code $($result.ExitCode)"
        Write-Warning $result.ScriptOutput
    }
    else {
        Write-Host "[$($VM.Name)] Script run Success"
        Write-Host $result.ScriptOutput.Trim()
        Write-Log $result.ScriptOutput.Trim()
    }
}
catch {
    Write-Error "Failed to execute script on $($vm.Name): $_"
}

write-host "Step 6 Clearing SetupMode, rebooting, and verifying PK..." -ForegroundColor Green
write-log "Step 6 Clearing SetupMode, rebooting, and verifying PK..."
Invoke-GracefulShutdown -VMName $VM.Name -TimeoutSeconds $TimeoutSeconds -CheckInterval $CheckInterval | Out-Null
$VM = Get-VM -Name $VM.Name

# ------------------------------------------------------------------
# PK Change Setting UEFI SetupMode VMX option
# ------------------------------------------------------------------
Set-VMXOption -VMObj (Get-VM -Name $vm) -Key "uefi.secureBootMode.overrideOnce" -Value " "
write-host "    SetupMode VMX option cleared." -ForegroundColor Cyan
write-log "    SetupMode VMX option cleared."

Start-VM $VM | Out-Null
Wait-ToolsWithRetry -VMName $VM.Name -MaxTries $MaxTries -DelaySeconds $DelaySeconds | Out-Null
$VM = Get-VM -Name $VM.Name

# ------------------------------------------------------------------
# Step 7 - Final verification (KEK/DB cert status)
# ------------------------------------------------------------------
write-host "Step 7 Secure-Boot-Update workflow..." -ForegroundColor Green
write-log "Step 7 Secure-Boot-Update workflow..."


write-host "=== Step 7A: Verifying 2023 certs in new NVRAM... ===" -ForegroundColor Yellow
write-log "=== Step 7A: Verifying 2023 certs in new NVRAM... ==="

try {
    $result = Run-InGuest -VMObj $VM -GuestCredential $GuestCredential -Script $certVerifyScript

    if ($result.ExitCode -ne 0) {
        Write-Warning "Script failed on $($vm.Name) with exit code $($result.ExitCode)"
        Write-Warning $result.ScriptOutput
    }
    else {
        Write-Host "[$($VM.Name)] Script run Success"
        Write-Host $result.ScriptOutput.Trim()
        Write-Log $result.ScriptOutput.Trim()
        }
    }
    catch {
    Write-Error "Failed to execute script on $($vm.Name): $_"
    }

write-host "=== Step 7B: Setting AvailableUpdates and triggering task ===" -ForegroundColor Yellow
write-log "=== Step 7B: Setting AvailableUpdates and triggering task ==="

try {
    $result = Run-InGuest -VMObj $VM -GuestCredential $GuestCredential -Script $SecureBootUpdate 

    if ($result.ExitCode -ne 0) {
        Write-Warning "Script failed on $($vm.Name) with exit code $($result.ExitCode)"
        Write-Warning $result.ScriptOutput
    }
    else {
        Write-Host "[$($VM.Name)] Script run Success"
        Write-Host $result.ScriptOutput.Trim()
        Write-Log $result.ScriptOutput.Trim()
    }
}
catch {
    Write-Error "Failed to execute script on $($vm.Name): $_"
}

Write-Host "=== Step 7C: Waiting for Eventid 1801 or 1808 ===" -ForegroundColor Yellow
Write-Log  "=== Step 7C: Waiting for Eventid 1801 or 1808 ==="

$maxRetries   = 5
$delaySeconds = 30
$attempt      = 0
$event1808Found = $false

while (($attempt -lt $maxRetries) -and (-not $event1808Found)) {
    $attempt++
    Write-Host "Attempt $attempt of $maxRetries" -ForegroundColor Cyan
    Write-Log  "Attempt $attempt of $maxRetries"

    try {
        $eventResult = Run-InGuest -VMObj $VM -GuestCredential $GuestCredential -Script $CheckEventid
        $eventOutput = $eventResult.ScriptOutput.Trim()

        Write-Host "Guest output: $eventOutput"
        Write-Log  "Guest output: $eventOutput"
    }
    catch {
        Write-Host "Failed to run event check in guest: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log  "Failed to run event check in guest: $($_.Exception.Message)"
        Start-Sleep -Seconds $delaySeconds
        continue
    }

    if ($eventOutput -match 'EVENT_1808_FOUND') {
        Write-Host "Event ID 1808 found. Step complete." -ForegroundColor Green
        Write-Log  "Event ID 1808 found. Step complete."
        $event1808Found = $true
    }
    elseif ($eventOutput -match 'EVENT_1801_FOUND') {
        Write-Host "Only Event ID 1801 found. Rebooting VM and checking again..." -ForegroundColor Yellow
        Write-Log  "Only Event ID 1801 found. Rebooting VM and checking again..."

        try {
            Restart-VMGuest -VM $VM -Confirm:$false | Out-Null
        }
        catch {
            Write-Host "Restart-VMGuest failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log  "Restart-VMGuest failed: $($_.Exception.Message)"
            break
        }

        Start-Sleep -Seconds 15
        Wait-ToolsWithRetry -VMName $VM.Name -MaxTries $MaxTries -DelaySeconds $DelaySeconds | Out-Null
        $VM = Get-VM -Name $VM.Name
        Start-Sleep -Seconds $delaySeconds
    }
    else {
        Write-Host "No Event ID 1801 or 1808 found yet. Waiting before retry..." -ForegroundColor Yellow
        Write-Log  "No Event ID 1801 or 1808 found yet. Waiting before retry..."
        Start-Sleep -Seconds $delaySeconds
    }
}

if (-not $event1808Found) {
    Write-Host "Maximum retries reached. Event ID 1808 was not detected." -ForegroundColor Red
    Write-Log  "Maximum retries reached. Event ID 1808 was not detected."
    break
}

Start-Sleep -Seconds 10

if ($eventOutput -match 'EVENT_1808_FOUND') {
        Write-Host "Event ID 1808 found. Skipping step 7D." -ForegroundColor Green
        Write-Log  "Event ID 1808 found. Skipping step 7D."
        
}
Else{
write-host "=== Step 7D: Running Task & Check Event Log again ===" -ForegroundColor Yellow
write-log "=== Step 7D: Running Task & Check Event Log again ==="

    try {
        $result = Run-InGuest -VMObj $VM -GuestCredential $GuestCredential -Script $RunTask

        if ($result.ExitCode -ne 0) {
            Write-Warning "Script failed on $($vm.Name) with exit code $($result.ExitCode)"
            Write-Warning $result.ScriptOutput
        }
        else {
            Write-Host "[$($vm.Name)] Success"
            Write-Host $result.ScriptOutput.Trim()
            Write-Log $result.ScriptOutput.Trim()
            }
        }
        catch {
        Write-Error "Failed to execute script on $($vm.Name): $_"
        }

    Start-Sleep 15

    try {
        $result = Run-InGuest -VMObj $VM -GuestCredential $GuestCredential -Script $CheckEventid

        if ($result.ExitCode -ne 0) {
            Write-Warning "Script failed on $($vm.Name) with exit code $($result.ExitCode)"
            Write-Warning $result.ScriptOutput
        }
        else {
            Write-Host "[$($vm.Name)] Success"
            Write-Host $result.ScriptOutput.Trim()
            Write-Log $result.ScriptOutput.Trim()
        }
    }
    catch {
        Write-Error "Failed to execute script on $($vm.Name): $_"
    }
}

# =============================================================================
# SNAPSHOT CLEANUP MODE
# =============================================================================
write-host "Step 8 Remove Snapshot..." -ForegroundColor Green
write-log "Step 8 Remove Snapshot..."
Remove-VMSnapshotWithProgress -VMName $VM.Name

if ($useTemplate -match '^[Yy]$' -and $templateName) {

    Write-Host "`nReverting VM '$($VM.Name)' back to template..." -ForegroundColor Yellow
    Write-Log "`nReverting VM '$($VM.Name)' back to template..."

    try {
        # Ensure VM is powered off
        if ($VM.PowerState -ne "PoweredOff") {
            Invoke-GracefulShutdown -VMName $VM.Name -TimeoutSeconds $TimeoutSeconds -CheckInterval $CheckInterval | Out-Null
        }

        Set-VM -VM $VM -ToTemplate -Confirm:$false -ErrorAction Stop | Out-Null

        Write-Host "VM successfully reverted to template." -ForegroundColor Green
        Write-Log "VM successfully reverted to template."
    }
    catch {
        Write-Error "Failed to revert VM back to template!"
        Write-Log "Failed to revert VM back to template!"
    }
}

# Your code here

$answer = Read-Host "Do you want to run it again? (Y/N)"

if ($answer -match '^(Y|y)$') {
    Write-Host "Running again..." -ForegroundColor Green
}
else {
    Write-Host "Stopping script." -ForegroundColor Yellow
    Disconnect-VIServer * -Confirm:$false
    write-host "✔ Disconnected from vCenter" -ForegroundColor Green
    }

} while ($answer -match '^(Y|y)$')