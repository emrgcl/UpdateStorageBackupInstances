# Azure Backup Management Script

This PowerShell script is designed to manage and update Azure backup instances by interacting with Azure REST APIs. It iterates through subscriptions, resource groups, and backup vaults to find and update backup instances based on detected changes in container lists.

## Features
- Connects to Azure using `Connect-AzAccount`.
- Retrieves and iterates through Azure subscriptions, resource groups, and backup vaults.
- Fetches and updates backup instances for storage accounts.
- Logs all operations for audit and debugging purposes.

## Prerequisites
- PowerShell 5.1 or higher.
- Azure PowerShell module (`Az.Accounts`).
- Permission to access and manage Azure resources.

## Parameters
- **`-LogFilePath`**: (Optional) Specifies the path to the log file.
- **`-TenantID`**: (Mandatory) Specifies the Tenant ID for Azure login.

## Default Log File
- By default, the log file will be created in the system's temporary folder (`$env:TEMP`) with a unique filename format: `log_<GUID>.txt`.
- If `-LogFilePath` is specified, logs will be written to the given file path.

## How to Run
1. **Open PowerShell** on your machine.
2. **Run the script** by providing the mandatory `-TenantID` parameter:
   ```powershell
   .\AzureBackupManagementScript.ps1 -TenantID "your-tenant-id"
   ```
   Optionally, specify the log file path:
   ```powershell
   .\AzureBackupManagementScript.ps1 -TenantID "your-tenant-id" -LogFilePath "C:\Path\To\LogFile.txt"
   ```

## Setting the Log File Location
- The `-LogFilePath` parameter allows you to set a custom path for the log file.
- If not set, the script defaults to `$env:TEMP`.
- Example with custom log path:
  ```powershell
  .\AzureBackupManagementScript.ps1 -TenantID "your-tenant-id" -LogFilePath "C:\Logs\AzureBackupLog.txt"
  ```

## Logging Details
- Logs include timestamps and context for each operation.
- The script logs both successes and errors for easier troubleshooting.

## Key Functions Explained
- **`Write-Log`**: Logs messages to the specified file.
- **`new-backupInstanceBody`**: Generates the JSON body for updating backup instances.
- **`Get-AzureBackupInstances`**: Retrieves backup instances for a given subscription, resource group, and backup vault.
- **`Update-AzureBackupInstance`**: Updates the backup instance if changes in the container list are detected.
- **`new-ErrorStringObject`**: Handles error string conversion for better error logging.

## Error Handling
- The script uses `try-catch` blocks to manage errors and logs them accordingly.
- If the script encounters an issue converting an error string, it logs a specific message indicating the conversion failure.

## Example Output
- **Log Entry**:
  ```plaintext
  [2024-11-08 14:45:32][Get-AzureBackupInstances] Found BackupInstance 'BackupInstanceName' BackupVault: 'BackupVaultName' in subscription 'SubscriptionId' and resource group 'ResourceGroupName'.
  ```

## Script Completion
- The script logs the total duration of the execution.
- Final log entry format:
  ```plaintext
  [2024-11-08 15:05:10][Main] Script completed. Duration: 120 seconds.
  ```

## Troubleshooting
- Ensure you have the required permissions to access Azure resources.
- Check for any network connectivity issues if API calls fail.
- Review the log file for detailed error messages if the script encounters problems.

---

**Note**: Replace `your-tenant-id` with your actual Azure Tenant ID when running the script.
