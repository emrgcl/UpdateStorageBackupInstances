[CmdletBinding(
    SupportsShouldProcess = $true
)]
Param(
[string]$LogFilePath,
[Parameter(Mandatory = $true)]
[string]$TenantID
)
Function new-backupInstanceBody {
    param (
        [string]$BackupInstanceID,
        [string]$BackupInstanceName,
        [string]$storageAccountName,
        [string]$StorageAccountResourceID,
        [string]$ResourceLocation,
        [string]$ContainerListString,
        [string]$BackupPolicyID
    )

@"
{
    "properties": {
        "friendlyName": "$storageAccountName",
        "dataSourceInfo": {
            "resourceID": "$StorageAccountResourceID",
            "resourceUri": "$StorageAccountResourceID",
            "datasourceType": "Microsoft.Storage/storageAccounts/blobServices",
            "resourceName": "$storageAccountName",
            "resourceType": "Microsoft.Storage/storageAccounts",
            "resourceLocation": "$ResourceLocation",
            "objectType": "Datasource"
        },
        "policyInfo": {
            "policyId": "$BackupPolicyID",
            "policyVersion": "",
            "policyParameters": {
                "backupDatasourceParametersList": [
                    {
                        "objectType": "BlobBackupDatasourceParameters",
                        "containersList": [
                        $ContainerListString
                        ]
                    }
                ]
            }
        },
        "objectType": "BackupInstance"
    }
}
"@
<#
@"
{
    "properties": {
        "friendlyName": "$storageAccountName",
        "dataSourceInfo": {
            "resourceID": "$StorageAccountResourceID",
            "resourceUri": "$StorageAccountResourceID",
            "datasourceType": "Microsoft.Storage/storageAccounts/blobServices",
            "resourceName": "$storageAccountName",
            "resourceType": "Microsoft.Storage/storageAccounts",
            "resourceLocation": "$ResourceLocation",
            "objectType": "Datasource"
        },
        "dataSourceSetInfo": {
            "resourceID": "$StorageAccountResourceID",
            "resourceUri": "$StorageAccountResourceID",
            "datasourceType": "Microsoft.Storage/storageAccounts/blobServices",
            "resourceName": "$storageAccountName",
            "resourceType": "Microsoft.Storage/storageAccounts",
            "resourceLocation": "$ResourceLocation",
            "objectType": "DatasourceSet"
        },
        "policyInfo": {
            "policyId": "$BackupPolicyID",
            "policyVersion": "",
            "policyParameters": {
                "backupDatasourceParametersList": [
                    {
                        "objectType": "BlobBackupDatasourceParameters",
                        "containersList": [
                        $ContainerListString
                        ]
                    }
                ]
            }
        },
        "objectType": "BackupInstance"
    }
}
"@
#>
}
function new-ContainerListString {
    param (
        [string[]]$ContainerList
    )
    $ContainerListString = @()
    foreach ($container in $ContainerList) {
        $ContainerListString += "`"$container`""
    }
    return $ContainerListString -join ","
}
Function Write-Log {

    [CmdletBinding()]
    Param(
    
    
    [Parameter(Mandatory = $True)]
    [string]$Message,
    [string]$LogFilePath = "$($env:TEMP)\log_$((New-Guid).Guid).txt",
    [Switch]$DoNotRotateDaily
    )
    
    if ($DoNotRotateDaily) {

        
        $LogFilePath = if ($Script:LogFilePath) {$Script:LogFilePath} else {$LogFilePath}
            
    } else {
        if ($Script:LogFilePath) {

        $LogFilePath = $Script:LogFilePath
        $DayStamp = (Get-Date -Format 'yMMdd').Tostring()
        $Extension = ($LogFilePath -split '\.')[-1]
        $LogFilePath -match "(?<Main>.+)\.$extension`$" | Out-Null
        $LogFilePath = "$($Matches.Main)_$DayStamp.$Extension"
        
    } else {$LogFilePath}
    }
    $Log = "[$(Get-Date -Format G)][$((Get-PSCallStack)[1].Command)] $Message"
    
    Write-Verbose $Log
    $Log | Out-File -FilePath $LogFilePath -Append -Force
    
}

Function new-ErrorStringObject {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]$ErrorString
    )
    try {
    $ErrorString | ConvertFrom-Json
    } catch {
        write-log  "Could not convert the error string to a json object. Error: '$($Error[0].Exception.Message)'"
    }
} 
Function new-AzApiHeader {
    param (
        [string]$AzToken
    )
    @{
        "Authorization" = "Bearer $AzToken"
    }
}
function Get-AzureBackupInstances {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$BackupVaultName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$AzApiHeader
    )

    # Define the API endpoint
    $url = "https://management.azure.com/Subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.DataProtection/backupVaults/$BackupVaultName/backupInstances?api-version=2024-04-01"

    try {
        # Make the REST API call
        $response = Invoke-RestMethod -Uri $url -Headers $AzApiHeader -Method Get -ErrorAction Stop -Verbose:$false
        
        # Return the response if the call was successful
        return $response.value
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException]{
        $ErrorStringObject = new-ErrorStringObject -ErrorString $_.ToString()
        write-log "Error: '$($ErrorStringObject.error.message)', Code: '$($ErrorStringObject.error.code)'"
    }
    catch {
        Write-Log "Error: $($_.Exception.Message)"
    }
}
function Get-AzureStorageContainers {
    param (

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountResourceID,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$AzApiHeader
    )

    # Define the API endpoint
    $url = " https://management.azure.com/$StorageAccountResourceID/blobServices/default/containers?api-version=2023-05-01"

    # Set up the headers for authorization

    try {
        # Make the REST API call
        $response = Invoke-RestMethod -Uri $url -Headers $AzApiHeader -Method Get -ErrorAction Stop -verbose:$false
        
        # Return the list of containers if the call was successful
        return $response.value
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException]{
        $ErrorStringObject = new-ErrorStringObject -ErrorString $_.ToString()
        write-log "Error: '$($ErrorStringObject.error.message)', Code: '$($ErrorStringObject.error.code)'"
    }
    catch {
        Write-Log "Error: $($_.Exception.Message)"
    }

}

function Update-AzureBackupInstance {
    [CmdletBinding()]
    Param(
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$BackupVaultName,
        
        [Parameter(Mandatory = $true)]
        [string]$BackupInstanceName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$AzApiHeader,
       
        [Parameter(Mandatory = $true)]
        [string]$Body
    )
    try {
        $BackInstancesUri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.DataProtection/backupVaults/$BackupVaultName/backupInstances/$BackupInstanceName`?api-version=2024-04-01"
        Invoke-RestMethod -Uri $backInstancesUri -Headers $AzApiHeader -Method Put -Body $Body -ContentType "application/json" -Verbose:$false -erroraction Stop
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException]{
        $ErrorStringObject = new-ErrorStringObject -ErrorString $_.ToString()
        write-log "Error: '$($ErrorStringObject.error.message)', Code: '$($ErrorStringObject.error.code)'"
    }
    catch {
        Write-Log "Error: $($_.Exception.Message)"
    }
}

function get-AzureBackupVaults {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$AzApiHeader
    )
    $url = "https://management.azure.com/Subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.DataProtection/backupVaults?api-version=2024-04-01"
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $AzApiHeader -Method Get -ErrorAction Stop -Verbose:$false
        $response.value
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException]{
        $ErrorStringObject = new-ErrorStringObject -ErrorString $_.ToString()
        write-log "Error: '$($ErrorStringObject.error.message)', Code: '$($ErrorStringObject.error.code)'"
    }
    catch {
        Write-Log "Error: $($_.Exception.Message)"
    }

}


function get-azuresubscriptions {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AzApiHeader
    )
    try {
    $Uri = "https://management.azure.com/subscriptions?api-version=2022-12-01"
    $response = Invoke-RestMethod -Uri $Uri -Headers $AzApiHeader -Method Get -ErrorAction Stop -Verbose:$false
    $response.value
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException]{
        $ErrorStringObject = new-ErrorStringObject -ErrorString $_.ToString()
        write-log "Error: '$($ErrorStringObject.error.message)', Code: '$($ErrorStringObject.error.code)'"
    }
    catch {
        Write-Log "Error: $($_.Exception.Message)"
    }
}
function Get-AzureResourceGroups {
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [hashtable]$AzApiHeader
)
$Uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups?api-version=2022-12-01"
try {
    $response = Invoke-RestMethod -Uri $Uri -Headers $AzApiHeader -Method Get -ErrorAction Stop -Verbose:$false
    $response.value
}
catch [Microsoft.PowerShell.Commands.HttpResponseException]{
    $ErrorStringObject = new-ErrorStringObject -ErrorString $_.ToString()
    write-log "Error: '$($ErrorStringObject.error.message)', Code: '$($ErrorStringObject.error.code)'"
}
catch {
    Write-Log "Error: $($_.Exception.Message)"
}
}
#region main
# Main script
# set variables

$ScriptStart = Get-Date
write-log "Script started."
Update-AzConfig -EnableLoginByWam $false | out-null
Connect-AzAccount -TenantId $TenantID | Out-Null
$AzToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
if (-not $AzToken) {
    throw "Failed to get AzToken"
}

$AzApiHeader = new-AzApiHeader -AzToken $AzToken

# get subscription list
$Subscriptions = @(get-azuresubscriptions -AzApiHeader $AzApiHeader) | Where-Object {$_.State -eq 'Enabled'}
Write-Log "Found $($Subscriptions.Count) enabled subscriptions"

foreach ($Subscription in $Subscriptions ) {

    $subscriptionId = $Subscription.subscriptionId
    $ResourceGroups = @(Get-AzureResourceGroups -SubscriptionId $subscriptionId -AzApiHeader $AzApiHeader)
    if ($ResourceGroups.Count -eq 0) {
        Write-Log "No resource groups found for subscription '$subscriptionId' skipping."
        continue
    }
    Foreach ($ResourceGroup in $ResourceGroups) {
        $BackupVaults = (get-AzureBackupVaults -SubscriptionId $subscriptionId -ResourceGroupName $ResourceGroup.name -AzApiHeader $AzApiHeader)
        if ($BackupVaults.Count -eq 0) {
            # Write-Log "No backup vaults found for subscription '$subscriptionId' and resource group '$($ResourceGroup.name)' skipping."
            continue
        }
        Foreach ($BackupVault in $BackupVaults) {
           
            $BackupInstancesParameters = @{
                SubscriptionId = $subscriptionId
                ResourceGroupName = $ResourceGroup.name
                BackupVaultName = $BackupVault.name
                AzApiHeader = $AzApiHeader
            }
            
            $backupInstances = @(Get-AzureBackupInstances @BackupInstancesParameters)
            $storageAccountInstances = @($backupInstances | Where-Object {$_.Properties.dataSourceInfo.datasourceType -eq 'Microsoft.Storage/storageAccounts/blobServices'})
            if (-not $storageAccountInstances) {
                Write-Log "No storage account backup instances found. SubscriptionId: '$subscriptionId', ResourceGroupName: '$($ResourceGroup.name)', BackupVaultName: '$($BackupVault.name)'"
                continue
            }
            foreach ($BackupInstance in $backupInstances) {
                 Write-Log "Found BackupInstance '$($BackupInstance.properties.friendlyName)' BackupVault: '$($BackupVault.name)' in subscription '$subscriptionId' and resource group '$($ResourceGroup.name)'"
                
                $ContainerList = @($BackupInstance.Properties.policyInfo.policyParameters.backupDatasourceParametersList.containersList)
                $StorageContainers = Get-AzureStorageContainers -StorageAccountResourceID $BackupInstance.Properties.dataSourceInfo.resourceID-AzApiHeader $AzApiHeader
                $EnabledContainers = $StorageContainers | Where-Object { $_.properties.deleted -eq $false}
                $StorageAccountContainerList = @($EnabledContainers | ForEach-Object { $_.name})
                if ($ContainerList.Count -eq 0) {
                    Write-Log "No enabled containers found for storage account '$($BackupInstance.Properties.dataSourceInfo.resourceName)'"
                    continue
                }
                if ($null -eq (Compare-Object -ReferenceObject $ContainerList -DifferenceObject $StorageAccountContainerList)) {
                    Write-Log "No changes detected for storage account '$($BackupInstance.Properties.dataSourceInfo.resourceName)'"
                    continue
                }
                $ContainerListString = new-ContainerListString -ContainerList $StorageAccountContainerList
                $Params = @{
                    BackupInstanceID = $BackupInstance.id
                    BackupInstanceName = $BackupInstance.Name
                    storageAccountName = $BackupInstance.Properties.dataSourceInfo.resourceName
                    StorageAccountResourceID = $BackupInstance.Properties.dataSourceInfo.resourceID
                    ResourceLocation = $BackupInstance.Properties.dataSourceInfo.resourceLocation
                    BackupPolicyID = $backupInstance.Properties.policyInfo.policyId
                    ContainerListString = $ContainerListString
                }
                $Body = new-backupInstanceBody @Params
                $Params = @{
                    SubscriptionId = $subscriptionId
                    ResourceGroupName = $ResourceGroup.name
                    BackupVaultName = $BackupVault.name
                    BackupInstanceName = $BackupInstance.Name
                    AzApiHeader = $AzApiHeader
                    Body = $Body
                }
                Write-Log "Updating Backup Instance $($backupInstance.Name) for $($BackupInstance.Properties.dataSourceInfo.resourceName). Containers: $ContainerListString"
                # implement what if below
                if ($PSCmdlet.ShouldProcess("Update Backup Instance", "Update Backup Instance for $($BackupInstance.Properties.dataSourceInfo.resourceName)")) {            
                Update-AzureBackupInstance @Params
               }
            }
    }
}
}
$DurationSeconds = [math]::Round(((get-date) - $ScriptStart).TotalSeconds)
Write-Log "Script completed. Duration: $DurationSeconds seconds."
#endregion