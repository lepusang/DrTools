

param([switch]$Elevated)
$script:UsernameIMP = "Administrator"
$script:PasswordIMP = 'p@ssw0rd'
#Import-Module dbatools

$host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(160, 700);
$host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(140, 50);
$LOGTIME = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
 
$script:UserToysClass = Add-Type -Namespace Huddled -Name UserToys -MemberDefinition @"
   // http://msdn.microsoft.com/en-us/library/aa378184.aspx
   [DllImport("advapi32.dll", SetLastError = true)]
   public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);
   // http://msdn.microsoft.com/en-us/library/aa379317.aspx
   [DllImport("advapi32.dll", SetLastError=true)]
   public static extern bool RevertToSelf();
"@ -passthru
$GCEGPODResultsArrey = @();
$script:ImpContextStack = new-object System.Collections.Generic.Stack[System.Security.Principal.WindowsImpersonationContext]
$script:IdStack = new-object System.Collections.Generic.Stack[System.Security.Principal.WindowsIdentity]


function Check-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if ((Check-Admin) -eq $false) {
    if ($elevated) {
        # could not elevate, quit
    }
 
    else {
 
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {   

    arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments

    break
}
Check-Admin

$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
Import-Module $ScriptPath\MSFT_xSmbShare.psm1 -Force -DisableNameChecking -Verbose
IF (-not ([System.Management.Automation.PSTypeName]'Microsoft.SqlServer.Management.Smo.Server').Type) {
    import-Module "$ScriptPath\dbatools.psd1" -Force
    import-Module "$ScriptPath\dbatools.psm1" -Verbose

}

Function Add-ACL {
    param (
        $path,
        $AccessGroup,
        $permissions
    )
    $acl = get-acl $($path)
    $permission = "$($AccessGroup)", "$($permissions)", "ContainerInherit,ObjectInherit", "None", "Allow"
    $accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.SetAccessRule($accessrule)
    $acl | Set-ACL $($path)
}
Function Set-SharePermissions {
    param(
        $sharename
    )
    Get-WmiObject -Class Win32_LogicalShareSecuritySetting -filter "Name=""$($sharename)""" | foreach {
        $newDescriptor = $_.GetSecurityDescriptor().descriptor
        $newDescriptor.dacl = $_.GetSecurityDescriptor().Descriptor.Dacl | Where { $_.trustee.name -ne 'Everyone' }
        $_.SetSecurityDescriptor($newDescriptor)
    }
}
function Invoke-Sqlcmd2 {

    [CmdletBinding(DefaultParameterSetName = 'Ins-Que')]
    [OutputType([System.Management.Automation.PSCustomObject], [System.Data.DataRow], [System.Data.DataTable], [System.Data.DataTableCollection], [System.Data.DataSet])]
    param (
        [Parameter(ParameterSetName = 'Ins-Que',
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'SQL Server Instance required...')]
        [Parameter(ParameterSetName = 'Ins-Fil',
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'SQL Server Instance required...')]
        [Alias('Instance', 'Instances', 'ComputerName', 'Server', 'Servers', 'SqlInstance')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ServerInstance,
        [Parameter(Position = 1,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [string]$Database,
        [Parameter(ParameterSetName = 'Ins-Que',
            Position = 2,
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Con-Que',
            Position = 2,
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [string]$Query,
        [Parameter(ParameterSetName = 'Ins-Fil',
            Position = 2,
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Con-Fil',
            Position = 2,
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [ValidateScript( { Test-Path -LiteralPath $_ })]
        [string]$InputFile,
        [Parameter(ParameterSetName = 'Ins-Que',
            Position = 3,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Ins-Fil',
            Position = 3,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Alias('SqlCredential')]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(ParameterSetName = 'Ins-Que',
            Position = 4,
            Mandatory = $false,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Ins-Fil',
            Position = 4,
            Mandatory = $false,
            ValueFromRemainingArguments = $false)]
        [switch]$Encrypt,
        [Parameter(Position = 5,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Int32]$QueryTimeout = 600,
        [Parameter(ParameterSetName = 'Ins-Fil',
            Position = 6,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Ins-Que',
            Position = 6,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Int32]$ConnectionTimeout = 15,
        [Parameter(Position = 7,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [ValidateSet("DataSet", "DataTable", "DataRow", "PSObject", "SingleValue")]
        [string]$As = "DataRow",
        [Parameter(Position = 8,
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [System.Collections.IDictionary]$SqlParameters,
        [Parameter(Position = 9,
            Mandatory = $false)]
        [switch]$AppendServerInstance,
        [Parameter(Position = 10,
            Mandatory = $false)]
        [switch]$ParseGO,
        [Parameter(ParameterSetName = 'Con-Que',
            Position = 11,
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Con-Fil',
            Position = 11,
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [Alias('Connection', 'Conn')]
        [ValidateNotNullOrEmpty()]
        [System.Data.SqlClient.SQLConnection]$SQLConnection,
        [Parameter(Position = 12,
            Mandatory = $false)]
        [Alias( 'Application', 'AppName' )]
        [String]$ApplicationName,
        [Parameter(Position = 13,
            Mandatory = $false)]
        [switch]$MessagesToOutput
    )

    begin {
        function Resolve-SqlError {
            param($Err)
            if ($Err) {
                if ($Err.Exception.GetType().Name -eq 'SqlException') {
                    # For SQL exception
                    #$Err = $_
                    Write-Debug -Message "Capture SQL Error"
                    if ($PSBoundParameters.Verbose) {
                        Write-Verbose -Message "SQL Error:  $Err"
                    } #Shiyang, add the verbose output of exception
                    switch ($ErrorActionPreference.ToString()) {
                        { 'SilentlyContinue', 'Ignore' -contains $_ } {   }
                        'Stop' { throw $Err }
                        'Continue' { throw $Err }
                        Default { Throw $Err }
                    }
                }
                else {
                    # For other exception
                    Write-Debug -Message "Capture Other Error"
                    if ($PSBoundParameters.Verbose) {
                        Write-Verbose -Message "Other Error:  $Err"
                    }
                    switch ($ErrorActionPreference.ToString()) {
                        { 'SilentlyContinue', 'Ignore' -contains $_ } { }
                        'Stop' { throw $Err }
                        'Continue' { throw $Err }
                        Default { throw $Err }
                    }
                }
            }

        }
        if ($InputFile) {
            $filePath = $(Resolve-Path -LiteralPath $InputFile).ProviderPath
            $Query = [System.IO.File]::ReadAllText("$filePath")
        }

        Write-Debug -Message "Running Invoke-Sqlcmd2 with ParameterSet '$($PSCmdlet.ParameterSetName)'.  Performing query '$Query'."

        if ($As -eq "PSObject") {
            #This code scrubs DBNulls.  Props to Dave Wyatt
            $cSharp = @'
                using System;
                using System.Data;
                using System.Management.Automation;
                public class DBNullScrubber
                {
                    public static PSObject DataRowToPSObject(DataRow row)
                    {
                        PSObject psObject = new PSObject();
                        if (row != null && (row.RowState & DataRowState.Detached) != DataRowState.Detached)
                        {
                            foreach (DataColumn column in row.Table.Columns)
                            {
                                Object value = null;
                                if (!row.IsNull(column))
                                {
                                    value = row[column];
                                }
                                psObject.Properties.Add(new PSNoteProperty(column.ColumnName, value));
                            }
                        }
                        return psObject;
                    }
                }
'@

            try {
                if ($PSEdition -ne 'Core') {
                    Add-Type -TypeDefinition $cSharp -ReferencedAssemblies 'System.Data', 'System.Xml' -ErrorAction stop
                }
                else {
                    Add-Type $cSharp -ErrorAction stop
                }

                
            }
            catch {
                if (-not $_.ToString() -like "*The type name 'DBNullScrubber' already exists*") {
                    Write-Warning "Could not load DBNullScrubber.  Defaulting to DataRow output: $_."
                    $As = "Datarow"
                }
            }
        }

        #Handle existing connections
        if ($PSBoundParameters.ContainsKey('SQLConnection')) {
            if ($SQLConnection.State -notlike "Open") {
                try {
                    Write-Debug -Message "Opening connection from '$($SQLConnection.State)' state."
                    $SQLConnection.Open()
                }
                catch {
                    throw $_
                }
            }

            if ($Database -and $SQLConnection.Database -notlike $Database) {
                try {
                    Write-Debug -Message "Changing SQLConnection database from '$($SQLConnection.Database)' to $Database."
                    $SQLConnection.ChangeDatabase($Database)
                }
                catch {
                    throw "Could not change Connection database '$($SQLConnection.Database)' to $Database`: $_"
                }
            }

            if ($SQLConnection.state -like "Open") {
                $ServerInstance = @($SQLConnection.DataSource)
            }
            else {
                throw "SQLConnection is not open"
            }
        }
        $GoSplitterRegex = [regex]'(?smi)^[\s]*GO[\s]*$'

    }
    process {
        foreach ($SQLInstance in $ServerInstance) {
            Write-Debug -Message "Querying ServerInstance '$SQLInstance'"

            if ($PSBoundParameters.Keys -contains "SQLConnection") {
                $Conn = $SQLConnection
            }
            else {
                $CSBuilder = New-Object -TypeName System.Data.SqlClient.SqlConnectionStringBuilder
                $CSBuilder["Server"] = $SQLInstance
                $CSBuilder["Database"] = $Database
                $CSBuilder["Connection Timeout"] = $ConnectionTimeout

                if ($Encrypt) {
                    $CSBuilder["Encrypt"] = $true
                }

                if ($Credential) {
                    $CSBuilder["Trusted_Connection"] = $false
                    $CSBuilder["User ID"] = $Credential.UserName
                    $CSBuilder["Password"] = $Credential.GetNetworkCredential().Password
                }
                else {
                    $CSBuilder["Integrated Security"] = $true
                }
                if ($ApplicationName) {
                    $CSBuilder["Application Name"] = $ApplicationName
                }
                else {
                    $ScriptName = (Get-PSCallStack)[-1].Command.ToString()
                    if ($ScriptName -ne "<ScriptBlock>") {
                        $CSBuilder["Application Name"] = $ScriptName
                    }
                }
                $conn = New-Object -TypeName System.Data.SqlClient.SQLConnection

                $ConnectionString = $CSBuilder.ToString()
                $conn.ConnectionString = $ConnectionString
                Write-Debug "ConnectionString $ConnectionString"

                try {
                    $conn.Open()
                }
                catch {
                    Write-Error $_
                    continue
                }
            }


            if ($ParseGO) {
                Write-Debug -Message "Stripping GOs from source"
                $Pieces = $GoSplitterRegex.Split($Query)
            }
            else {
                $Pieces = , $Query
            }
            # Only execute non-empty statements
            $Pieces = $Pieces | Where-Object { $_.Trim().Length -gt 0 }
            foreach ($piece in $Pieces) {
                $cmd = New-Object system.Data.SqlClient.SqlCommand($piece, $conn)
                $cmd.CommandTimeout = $QueryTimeout

                if ($null -ne $SqlParameters) {
                    $SqlParameters.GetEnumerator() |
                    ForEach-Object {
                        if ($null -ne $_.Value) {
                            $cmd.Parameters.AddWithValue($_.Key, $_.Value)
                        }
                        else {
                            $cmd.Parameters.AddWithValue($_.Key, [DBNull]::Value)
                        }
                    } > $null
                }

                $ds = New-Object system.Data.DataSet
                $da = New-Object system.Data.SqlClient.SqlDataAdapter($cmd)

                if ($MessagesToOutput) {
                    $pool = [RunspaceFactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS + 1)
                    $pool.ApartmentState = "MTA"
                    $pool.Open()
                    $runspaces = @()
                    $scriptblock = {
                        Param ($da, $ds, $conn, $queue )
                        $conn.FireInfoMessageEventOnUserErrors = $false
                        $handler = [System.Data.SqlClient.SqlInfoMessageEventHandler] { $queue.Enqueue($_) }
                        $conn.add_InfoMessage($handler)
                        $Err = $null
                        try {
                            [void]$da.fill($ds)
                        }
                        catch {
                            $Err = $_
                        }
                        finally {
                            $conn.remove_InfoMessage($handler)
                        }
                        return $Err
                    }
                    $queue = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
                    $runspace = [PowerShell]::Create()
                    $null = $runspace.AddScript($scriptblock)
                    $null = $runspace.AddArgument($da)
                    $null = $runspace.AddArgument($ds)
                    $null = $runspace.AddArgument($Conn)
                    $null = $runspace.AddArgument($queue)
                    $runspace.RunspacePool = $pool
                    $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
                    # While streaming ...
                    while ($runspaces.Status.IsCompleted -notcontains $true) {
                        $item = $null
                        if ($queue.TryDequeue([ref]$item)) {
                            "$item"
                        }
                    }
                    # Drain the stream as the runspace is closed, just to be safe
                    if ($queue.IsEmpty -ne $true) {
                        $item = $null
                        while ($queue.TryDequeue([ref]$item)) {
                            "$item"
                        }
                    }
                    foreach ($runspace in $runspaces) {
                        $results = $runspace.Pipe.EndInvoke($runspace.Status)
                        $runspace.Pipe.Dispose()
                        if ($null -ne $results) {
                            Resolve-SqlError $results[0]
                        }
                    }
                    $pool.Close()
                    $pool.Dispose()
                }
                else {
                    #Following EventHandler is used for PRINT and RAISERROR T-SQL statements. Executed when -Verbose parameter specified by caller and no -MessageToOutput
                    if ($PSBoundParameters.Verbose) {
                        $conn.FireInfoMessageEventOnUserErrors = $false
                        $handler = [System.Data.SqlClient.SqlInfoMessageEventHandler] { Write-Verbose "$($_)" }
                        $conn.add_InfoMessage($handler)
                    }
                    try {
                        [void]$da.fill($ds)
                    }
                    catch {
                        $Err = $_
                    }
                    finally {
                        if ($PSBoundParameters.Verbose) {
                            $conn.remove_InfoMessage($handler)
                        }
                    }
                    Resolve-SqlError $Err
                }
                #Close the connection
                if (-not $PSBoundParameters.ContainsKey('SQLConnection')) {
                    $Conn.Close()
                }
                if ($AppendServerInstance) {
                    #Basics from Chad Miller
                    $Column = New-Object Data.DataColumn
                    $Column.ColumnName = "ServerInstance"

                    if ($ds.Tables.Count -ne 0) {
                        $ds.Tables[0].Columns.Add($Column)
                        Foreach ($row in $ds.Tables[0]) {
                            $row.ServerInstance = $SQLInstance
                        }
                    }
                }

                switch ($As) {
                    'DataSet' {
                        $ds
                    }
                    'DataTable' {
                        $ds.Tables
                    }
                    'DataRow' {
                        if ($ds.Tables.Count -ne 0) {
                            $ds.Tables[0]
                        }
                    }
                    'PSObject' {
                        if ($ds.Tables.Count -ne 0) {
                            #Scrub DBNulls - Provides convenient results you can use comparisons with
                            #Introduces overhead (e.g. ~2000 rows w/ ~80 columns went from .15 Seconds to .65 Seconds - depending on your data could be much more!)
                            foreach ($row in $ds.Tables[0].Rows) {
                                [DBNullScrubber]::DataRowToPSObject($row)
                            }
                        }
                    }
                    'SingleValue' {
                        if ($ds.Tables.Count -ne 0) {
                            $ds.Tables[0] | Select-Object -ExpandProperty $ds.Tables[0].Columns[0].ColumnName
                        }
                    }
                }
            } #foreach ($piece in $Pieces)
        }
    }
} #Invoke-Sqlcmd2
Function New-NetworkShare {
    param (
        $path,
        $sharename,
        $AccessGroup,
        [Validateset("Read", "Modify", "FullControl")][string]$permissions
    )
    #Create Directory
    try {
        New-item "$($path)" -itemtype Directory -erroraction stop | out-null
    }
    catch [System.IO.IOException] {
        Write-Verbose "Directory $($path) Already Exists"
    }
    #Check it's not already shared.
    $check = (Get-WmiObject Win32_Share).where({ $_.path -eq "$($path)" })
    if ($check) {
        Write-Verbose "Directory $($path) already shared as $($check.Name)"
    }
    Else {
        $result = (Get-WmiObject Win32_Share -List).Create("$($path)", "$sharename", 0)
        if ($result -ne 0) {
            Write-Verbose "Failed to create share return code $($result.returncode)"
        }
    }
    Add-ACL -AccessGroup $AccessGroup -Path $path -permissions $permissions | out-null
    Set-SharePermissions -sharename $sharename | out-null
    return $((Get-WmiObject Win32_Share).where({ $_.path -eq "$($path)" }))
}


FUNCTION GenericSqlQuery ($SettingSourceServer, $Db, $SQLQuery) {
        
        
    RETURN
}
     
FUNCTION Get-ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}
    
FUNCTION Set-MigShare ($dir) {
        
    $LocalServerName = $(Get-WmiObject Win32_Computersystem).name
    IF (!(Test-path "$ScriptPath\SQL-Migration-Sync")) {
        write-host "Create Folder $ScriptPath\SQL-Migration-Sync" -ForegroundColor Yellow
            
        New-Item -Path "$ScriptPath\SQL-Migration-Sync" -ItemType directory -Force | Out-Null
    }
    else {
        write-host "The folder already exists: "$ScriptPath\SQL-Migration-Sync -ForegroundColor Yellow
    }
    IF (!(Get-SmbShare -Name "SQL-Migration-Sync" -ErrorAction SilentlyContinue)) {
        set-TargetResource -Name SQL-Migration-Sync -Path $ScriptPath\SQL-Migration-Sync -Description "DR share path" -FullAccess Administrators -Verbose -Ensure Present -ChangeAccess "Everyone"
        New-NetworkShare -path "$ScriptPath\SQL-Migration-Sync" -sharename "SQL-Migration-Sync" -AccessGroup "Everyone" -permissions FullControl
       
    }
    else {
        write-host "The share already exists:  SQL-Migration-Sync" -ForegroundColor Yellow
    }
   
    set-TargetResource -Name SQL-Migration-Sync -Path "$ScriptPath\SQL-Migration-Sync" -Description "DR share path" -FullAccess "Administrators" -Verbose -ChangeAccess "Everyone" -Debug
 RETURN "\$LocalServerName\SQL-Migration-Sync"

 
  
        
}
    
$script:UserToysClass = Add-Type -Namespace Huddled -Name UserToys -MemberDefinition @"
   // http://msdn.microsoft.com/en-us/library/aa378184.aspx
   [DllImport("advapi32.dll", SetLastError = true)]
   public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);
   // http://msdn.microsoft.com/en-us/library/aa379317.aspx
   [DllImport("advapi32.dll", SetLastError=true)]
   public static extern bool RevertToSelf();
"@ -passthru
$GCEGPODResultsArrey = @();
$script:ImpContextStack = new-object System.Collections.Generic.Stack[System.Security.Principal.WindowsImpersonationContext]
$script:IdStack = new-object System.Collections.Generic.Stack[System.Security.Principal.WindowsIdentity]



function Push-ImpersonationContext {

 [CmdletBinding(DefaultParameterSetName = "Credential")]
 Param(
     [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "Credential")]
     [System.Management.Automation.PSCredential]$Credential,
 
     [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "Identity")]
     [Security.Principal.WindowsIdentity]$Identity,
 
     [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "UserPass")]
     [string]$Name,
 
     [Parameter(Position = 1, Mandatory = $true, ParameterSetName = "password")]
     [Alias("PW")]
     $Password,
 
     [Parameter(Position = 2, Mandatory = $false, ParameterSetName = "Domain")]
     [string]$Domain,
 
     [Alias("PT")]
     [switch]$Passthru
 )
 
 Begin {
     # Initialize stacks if they don't exist
     if (-not $script:IdStack) { $script:IdStack = New-Object System.Collections.Generic.Stack[Security.Principal.WindowsIdentity] }
     if (-not $script:ImpContextStack) { $script:ImpContextStack = New-Object System.Collections.Generic.Stack[Security.Principal.WindowsImpersonationContext] }
 
     # Define or validate UserToysClass
     if (-not (Get-Variable -Name UserToysClass -Scope Script -ErrorAction SilentlyContinue)) {
         throw "Required class UserToysClass is not defined"
     }
 }
 
 Process {
     try {
         if (!$Identity) {
             if (!$Credential) {
                 # Convert string password to SecureString if needed
                 if ($password -is [string]) {
                     $securePassword = New-Object System.Security.SecureString
                     foreach ($char in $password.ToCharArray()) {
                         $securePassword.AppendChar($char)
                     }
                     # Clear the plaintext password from memory
                     $password.Dispose()
                     $password = $securePassword
                 }
 
                 # Build username based on domain presence
                 $userName = if ($domain) { "${name}@${domain}" } else { $name }
                 
                 try {
                     $Credential = New-Object System.Management.Automation.PSCredential($userName, $password)
                 } catch {
                     throw "Failed to create credential object: $_"
                 }
             }
 
             Write-Verbose ([Security.Principal.WindowsIdentity]::GetCurrent() | Format-Table Name, Token, User, Groups -Auto | Out-String)
 
             # Get current token for comparison later
             [IntPtr]$userToken = [IntPtr]::Zero
 
             try {
                 if (!$UserToysClass::LogonUser(
                         $Credential.GetNetworkCredential().UserName,
                         $Credential.GetNetworkCredential().Domain,
                         ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                             [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                                 $Credential.GetNetworkCredential().SecurePassword
                             )
                         )),
                         9,
                         0,
                         [ref]$userToken
                     )) {
                     throw (New-Object System.ComponentModel.Win32Exception([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))
                 }
 
                 try {
                     $Identity = New-Object Security.Principal.WindowsIdentity($userToken)
                 } catch {
                     throw "Failed to create Windows identity: $_"
                 }
             } finally {
                 # Clean up token if something went wrong after getting it but before creating identity
                 if ($userToken -ne [IntPtr]::Zero -and !$Identity) {
                     [UserToysClass]::CloseHandle($userToken)
                 }
             }
         }
 
         # Push identity onto stack and impersonate
         try {
             $script:IdStack.Push($Identity)
             try {
                 Write-Verbose ("Attempting impersonation with identity: " + ($Identity | Format-Table Name, Token, User, Groups -Auto | Out-String))
                 
                 # Create impersonation context and push it onto stack so we can undo it later 
                 # when popping this identity off the IdStack 
                 try{
                    $_context=$identity.Impersonate() 
                    $_result=$null; 
 
                    trap{
                       write-error ("Failed during impersonation:`n"+($_|out-string)); 
                       continue; 
                    } 
 
                    $_result=$_context; 
 
                    finally{ 
                       If($_result){ 
                          write-verbose ("Successfully pushed new context onto ImpContextStack"); 
                          $_=@(); while(@($_=$impcontextstack).count){break};  
                          If(!@($_)){[void](new-object collections.stack);}  
                          Else{[void](new-object collections.stack(@($_)))}  
 
                          $_=@(); while(@($_=$impcontextstack).peek()){break};  
                          If(!@($_)){[void](new-object collections.stack);}  
                          Else{[void](new-object collections.stack(@($_)))}  
 
                          write-debug ("Pushing new context onto stack");  
                          @()>$null; while(!(@()>$null)){break};  
 
                          @()>$null; while(!(@()>$null)){break};  
 
                          1..10|%{start-sleep-milliseconds(100)};  
 
                       }Else{write-warning("No context was created!");}  
                    } 
 
                  }Catch{Throw;}Finally{}  
 
               }Catch{Throw;}Finally{}  
 
            }Catch{Throw;}Finally{}  
 
          Write-Verbose ([Security.Principal.WindowsIdentity]::GetCurrent() | Format-Table Name, Token, User, Groups -Auto | Out-String)
 
          If ($Passthru) { Return ,$script:IdStack.Peek() }
 
       } Catch {
 
          Throw ("An error occurred during impersonation setup:`n" + ($_ | Out-String))
 
       }
 
 }
}
 
#Push-ImpersonationContext
function Pop-ImpersonationContext {

    param( [switch]$Passthru )
    trap {
        Write-Error "Impersonation Context Stack is Empty"
        while ($script:ImpContextStack.Count -lt $script:IdStack.Count) { $null = $script:IdStack.Pop() }
        return
    }
    if ($Passthru) { $script:IdStack.Peek() }
    $context = $script:ImpContextStack.Pop()
    $null = $script:IdStack.Pop()

    $context.Undo();
    $context.Dispose();
}

function Get-ImpersonationContext {
    <#
.Synopsis
   Display the currently active WindowsIdentity
#>
    trap {
        Write-Error "Impersonation Context Stack is Empty"
        return
    }
    Write-Host "There are $($script:ImpContextStack.Count) contexts on the stack"
    while ($script:ImpContextStack.Count -lt $script:IdStack.Count) { $null = $script:IdStack.Pop() }
    if ($script:ImpContextStack.Count -eq $script:IdStack.Count) {
        $script:IdStack.Peek()
    }
}

function Set-ClientGPODString {

    Param(
        [parameter(ValueFromPipeline = $True)]
        # [ValidateNotNullOrEmpty()]
        [string]$Computername = $env:Computername,
        [parameter(ValueFromPipeline = $True)]
        #[ValidateNotNullOrEmpty()]
        [string]$Input = "$ScriptPath\clientss.txt",
        [parameter(ValueFromPipeline = $True)]
        #[ValidateNotNullOrEmpty()]
        [string]$Username = $Username,
        [parameter(ValueFromPipeline = $True)]
        #[ValidateNotNullOrEmpty()]
        [string]$Password = $Password,
        [parameter(ValueFromPipeline = $True)]
        #[ValidateNotNullOrEmpty()]
        [string]$Domain = $Domain

    )


    $Clientcomputers = Get-Content $ScriptPath\clientss.txt
 

    Write-host $LOGTIME `t "Getting Connection string from Current and Destinaction server $DestinationApplicationserver `t SourceApplicationServer:: $Applicationserver" -ForegroundColor Yellow





    Try {
        get-service -Name RemoteRegistry -computerName $DestinationApplicationserver | ? { $_.status -eq 'Stopped' } | Start-Service -Verbose
        get-service -Name RemoteRegistry -computerName $Applicationserver | ? { $_.status -eq 'Stopped' } | Start-Service -Verbose
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $DestinationApplicationserver) 
    
    
           $regKey = $reg.OpenSubKey("SOFTWARE\Wow6432Node\Finteq\GenericCapture", $true) 
        if (!($regKey.GetValue('ConnectionString'))) { Throw "Key '$Key' doesn't exist." }else { write-host $DestinationApplicationserver registry key pulled through successfully -ForegroundColor Green }
        $DestinationApplicationserverREGkey = $regKey.GetValue('ConnectionString')
        Write-host $DestinationApplicationserver `n $DestinationApplicationserverREGkey

        $reg.Flush()
        $reg.Close()
 
        $reg1 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Applicationserver) 
        $regKey1 = $reg1.OpenSubKey("SOFTWARE\Wow6432Node\Finteq\GenericCapture", $true) 
        #$regKey1.GetValueNames()
        $SourceApplicationServerRegKey = $regKey1.GetValue('ConnectionString')
        Write-host $ApplicationServer `n $SourceApplicationServerRegKey

        IF (!$SourceApplicationServerRegKey) { Throw "Key SourceApplicationServerRegKey '$Key' doesn't exist." }else { Write-host $SourceApplicationServer Pulled through Successfully -ForegroundColor Green }
    }
    Catch {
        $e = $_.Exception
        $msg = $e.Message
        while ($e.InnerException) {
            $e = $e.InnerException
            $msg += "`n" + $e.Message
        }
        Write-host $msg -ForegroundColor Red
        $msg
        Pop-ImpersonationContext
        Write-output $LOGTIME `t $msg | Out-File $ScriptPath\ErrorLog.log -Append
        continue;
    }

    foreach ($Clientcomputer in $Clientcomputers) {
        if ( !(Test-Connection -computerName $Clientcomputer -Count 1 -Quiet)) {
            Write-Warning "[$Clientcomputer] doesn't respond to ping."
            Continue;
        }
        $Clientcomputerhost = Resolve-DbaNetworkName -ComputerName $Clientcomputer -Verbose | ? { $_.ComputerName }
        $Clientcomputerhost.ComputerName 
       
        $Clientcomputerhost = $Clientcomputer
        write-host $Clientcomputerhost.HostName
   

        $Script:DomainIMP = $Clientcomputer
        Push-ImpersonationContext -Name $UsernameIMP -Password $PasswordIMP -Domain $DomainIMP 

        If (test-connection -computerName $Clientcomputer -Count 1 -Quiet) {

            try {
                #Pop-ImpersonationContext

             
                get-service -Name RemoteRegistry -computerName $Clientcomputer -Verbose
                get-service -Name RemoteRegistry -computerName $Clientcomputer | Start-Service -Verbose
             

                $DotNetRegistryBase = 'SOFTWARE\Finteq\GenericCapture'
                $ErrorActionPreference = 'Continue'
                $RegSuccess = $false
                try {
                    if ($PSRemoting -or $LocalHost) {
                        # Open local registry
                        $Registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', [string]::Empty)
                        $RegSuccess = $?
                    }
                    else {
                        $Registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Clientcomputer)
                        $RegSuccess = $?
                    }
                }



                catch {
                    Write-Warning -Message "${Clientcomputer}: Unable to open $(if (-not $PSremoting) { 'remote ' })registry: $_"
                    $DotNetData.$Clientcomputer | Add-Member -Name Error -Value "Unable to open remote registry: $_" -MemberType NoteProperty
                    return $DotNetData.$Clientcomputer
                }

                $ErrorActionPreference = 'Continue'
                Write-Verbose -Message "${Clientcomputer}: Successfully connected to registry."
           
                if ( $RegKey = $Registry.OpenSubKey("$DotNetRegistryBase\ConnectionString")) { Write-host $regkey }


                try {
                    $32bitgpodexc = $true
                    $regClient = $([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Clientcomputer))
                    $regClientKey = $regClient.OpenSubKey("SOFTWARE\Finteq\GenericCapture", $true)
                    $32bitgpod = ($regClientKey.GetValue('ConnectionString'))
                    Write-host $Clientcomputer `n $32bitgpod
                }
                Catch {
                    [bool]$32bitgpodexc = $false
                    $32bitgpodexc 
                }
                If ($32bitgpodexc -eq $true) {
     
                    Write-host $LOGTIME `t $regClientKey.GetSubKeyNames()
              
                    Write-host $LOGTIME `t $Clientcomputer `t OLD String `t $regClientKey.GetValue("ConnectionString") -ForegroundColor Cyan
                    if ($($regClientKey.GetValue("ConnectionString")) -eq $($SourceApplicationServerRegKey).tostring()) {
                        Write-host $LOGTIME `t Updateing client from SourceApplicationServer Connection string to DestinationApplicationserver  -ForegroundColor Green
                        $regClientKey.SetValue("ConnectionString", $DestinationApplicationserverREGkey, [Microsoft.Win32.RegistryValueKind]::String) 
                        $regClientKey.GetValue("ConnectionString")

                        Write-host $LOGTIME `t $Clientcomputer `t NEW key `t $regClientKey.GetValue("ConnectionString") -ForegroundColor Yellow
                        continue
                    }
                    continue
                }
                elseif (!$32bitgpodexc) {
                    Write-host $LOGTIME `t "Registry key not found SOFTWARE\Finteq\GenericCapture... Now searching X64  :: 'SOFTWARE\WOW6432Node\Finteq\GenericCapture'" -ForegroundColor Yellow
                    $regClient = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Clientcomputer) 
                    $regClientKey = $regClient.OpenSubKey("SOFTWARE\WOW6432Node\Finteq\GenericCapture", $true) 
                    Write-host $LOGTIME `t "X64 found $($regClient.GetValue('ConnectionString'))"
                    Write-host $LOGTIME `t $Clientcomputer `t X64 OLD String `t $regClientKey.GetValue("ConnectionString") -ForegroundColor Cyan
                    if ($($regClientKey.GetValue("ConnectionString").tostring()) -eq $($SourceApplicationServerRegKey).tostring()) {
                        Write-host $LOGTIME `t X64 Updateing client from SourceApplicationServer Connection string to DestinationApplicationserver  -ForegroundColor Green
                        $regClientKey.SetValue("ConnectionString", $DestinationApplicationserverREGkey, [Microsoft.Win32.RegistryValueKind]::String) 
                        #$regkey.GetValue("ConnectionString")

                        Write-host $LOGTIME `t $Clientcomputer `t X64 NEW key `t $regClientKey.GetValue("ConnectionString") -ForegroundColor Yellow
                    }

                }

            }
            Catch {
                $e = $_.Exception
                $msg = $e.Message
                while ($e.InnerException) {
                    $e = $e.InnerException
                    $msg += "`n" + $e.Message
                }
                Write-host $msg -ForegroundColor Red
             
                $msg
                Write-output $LOGTIME `t $msg | Out-File $ScriptPath\UpdateErrorLog.log -Append
                continue;
            }
        }	
    
        else {
            Write-Host $LOGTIME `t "$Clientcomputer unreachable"
            Pop-ImpersonationContext
        }
        Pop-ImpersonationContext
        $Clientcomputer | export-csv $ScriptPath\Win7VisioStd.csv -append -Force
    }
}
    

FUNCTION WaitOnScheduledTask($server = $(THROW "Server is required."), [string[]]$tasks = $(THROW "Task is required."), $maxSeconds = 300,
    [switch]$Disable,
    [switch]$Enable,
    [String]$ServiceAccount

) {
    Write-Host $ServiceAccount -BackgroundColor green
    $name = $ServiceAccount
    $arraylist = new-object System.Collections.Arraylist
    
    $foundtask = cmd.exe /c schtasks.exe /query /s $server /V /FO CSV | CONVERTFROM-CSV | Where-Object {
        $_."Run As User" -like "$name"
    } | Select-Object -Property @{
        N = "HostName"; E = {
            $_.HostName
        }
    }, @{
        N = "TaskName"; E = {
            $_.TaskName.split("\")[-1]
        }
    }
    Write-Host $foundtask.TaskName -ForegroundColor Cyan
    $global:arraylist += $foundtask.TaskName
    
    Write-Host $arraylist
    
    FOREACH ($task IN $foundtask.TaskName) {
            
        IF (($Enable) -and ($Disable)) {
            Write-Host $LOGTIME `t 'It is not possible to use the parameter -Enable together with -Disable at the command line' -ForegroundColor Red
            BREAK
        }
        $startTime = get-date
        $initialDelay = 1
        $intervalDelay = 30
        IF (-not (Test-Connection -ComputerName $server -Count 1 -quiet)) {
            Write-host $LOGTIME `t "$server is down" -ForegroundColor Red
            RETURN;
        }
        ELSE {
            IF ($Enable) {
                Write-Output "Starting task '$task' on '$server'. Please wait..."
                Write-host $LOGTIME `t "Enable $task on $server!" -ForegroundColor Yellow -BackgroundColor DarkCyan
                schtasks /Change /s $server /TN $task /Enable
                    
                schtasks /run /s $server /TN $task
            }
            IF ($Disable) {
                Write-host $LOGTIME `t "Disabling $task on $server!" -ForegroundColor Yellow -BackgroundColor DarkCyan
                schtasks /Change /s $server /TN $task /Disable
                    
            }
                
            # wait a tick before checking the first time, otherwise it may still be at ready, never transitioned to running
            Write-Output "One moment..."
            start-sleep -Seconds $initialDelay
            $timeout = $false
                
                
            WHILE ($true) {
                $ts = New-TimeSpan $startTime $(get-date)
                    
                # this whole csv thing is hacky but one workaround I found for server 2003
                $tempFile = Join-Path $env:temp "SchTasksTemp.csv"
                schtasks /Query /FO CSV /s $server /TN $task /v > $tempFile
                IF ($Enable) {
                    Write-Output "Starting task '$task' on '$server'. Please wait..."
                    Write-host $LOGTIME `t "Enable $task on $server!" -ForegroundColor Yellow -BackgroundColor DarkCyan
                    schtasks /Change /s $server /TN $task /Enable
                    
                    schtasks /run /s $server /TN $task
                }
                IF ($Disable) {
                    Write-host $LOGTIME `t "Disabling $task on $server!" -ForegroundColor Yellow -BackgroundColor DarkCyan
                    schtasks /Change /s $server /TN $task /Disable
                    
                }
                $taskData = Import-Csv $tempFile
                $status = $taskData.Status
       
                IF ($status.tostring() -eq "Running") {
                    $status = ((get-date).ToString("hh:MM:ss tt") + " Still running '$task' on '$server'...")
                    Write-Progress -activity $task -status $status -percentComplete -1 #-currentOperation "Waiting for completion status"
                    Write-Output $status
                }
                ELSE {
                    BREAK
                }
                    
                start-sleep -Seconds $intervalDelay
                    
                IF ($ts.TotalSeconds -gt $maxSeconds) {
                    $timeout = $true
                    Write-Output "Taking longer than max wait time of $maxSeconds seconds, Task execution will continue"
                    BREAK
                }
                    
            }
                
            IF (-not $timeout) {
                $ts = New-TimeSpan $startTime $(get-date)
                "Scheduled task '{0}' on '{1}' complete in {2:###} seconds" -f $task, $server, $ts.TotalSeconds
            }
        }
    }
}
    
FUNCTION Control-Services {
    #[cmdletbinding(SupportsShouldProcess,DefaultParametersetName='UserPassword')]
    [CmdletBinding()]
    PARAM (
        [string]$ComputerName,
                
        [switch]$Disable,
                
        [switch]$Enable,
                
        [switch]$Start,
                
        [switch]$Stop
                
    )
    Write-host $LOGTIME `t $ComputerName

    #$applicationserver = $ComputerName
    IF (($Enable) -and ($Disable)) {
        Write-Host $LOGTIME `t 'It is not possible to use the parameter -Enable together with -Disable at the command line' -ForegroundColor Red
        BREAK
    }
    IF (($Start) -and ($Stop)) {
        Write-Host $LOGTIME `t 'It is not possible to use the parameter -Start together with -Stop at the command line' -ForegroundColor Red
        BREAK
    }

    FOREACH ($Srvc IN ('COMS_Transferer', 'COms_Inwards', 'COMS_Batcher', 'COMS_OutwardSplit', 'COMS_Formatter', 'COMS_Scheduler', 'GC_Policeman', 'COMS_FTSServer', 'COms_Inwards2')) {
   
            
            
            
            
        $ObjServiceStatus = New-Object System.Object
        $ObjServiceStatus | Add-Member -MemberType NoteProperty -name ServerName -value $ComputerName -Verbose
        $ObjServiceStatus | Add-Member -MemberType NoteProperty -name ServiceName -value $Srvc.ToString()
        IF ($Enable) {
            Write-host $LOGTIME `t "Enabling $Srvc on $ComputerName" -ForegroundColor Yellow -BackgroundColor DarkCyan
            $ObjServiceStatus | Add-Member -MemberType NoteProperty -name ServiceDisable -value (Get-Service -ComputerName $ComputerName -Name $Srvc | Where-Object {
                    $_.StartType -eq 'Disabled'
                } | Set-Service -StartupType Automatic -Verbose)
            if ($?) { Write-Host $LOGTIME `t $DbaSqlQuery + " File executed successfully"  -foregroundcolor "green"; }else { Write-Host $LOGTIME `t $DbaSqlQuery.FullName + " File execution FAILED" -foregroundcolor "red"; }
        }
        IF ($Disable) {
            Write-host $LOGTIME `t "Disabling $Srvc on $ComputerName" -ForegroundColor Yellow -BackgroundColor DarkCyan
            $ObjServiceStatus | Add-Member -MemberType NoteProperty -name ServiceDisable -value (Get-Service -ComputerName $ComputerName -Name $Srvc | Where-Object {
                    $_.StartType -eq 'Automatic'
                } | Set-Service -StartupType Disabled -Verbose)
            if ($?) { Write-Host $LOGTIME `t $DbaSqlQuery + " File executed successfully"  -foregroundcolor "green"; }else { Write-Host $LOGTIME `t $DbaSqlQuery.FullName + " File execution FAILED" -foregroundcolor "red"; }
        }
            
        IF ($Start) {
            Write-host $LOGTIME `t "Starting $Srvc on $ComputerName" -ForegroundColor Yellow -BackgroundColor DarkCyan
            $ObjServiceStatus | Add-Member -MemberType NoteProperty -name ServiceStop -value (Get-Service -ComputerName $ComputerName -Name $Srvc | Where-Object {
                    $_.status -eq 'Stopped'
                } | Start-Service -Verbose)
            if ($?) { Write-Host $LOGTIME `t $DbaSqlQuery + " File executed successfully"  -foregroundcolor "green"; }else { Write-Host $LOGTIME `t $DbaSqlQuery.FullName + " File execution FAILED" -foregroundcolor "red"; }
        }
        IF ($Stop) {
            Write-host $LOGTIME `t "Stopping $Srvc on $ComputerName" -ForegroundColor Yellow -BackgroundColor DarkCyan
            $ObjServiceStatus | Add-Member -MemberType NoteProperty -name ServiceStop -value (Get-Service -ComputerName $ComputerName -Name $Srvc | Where-Object {
                    $_.status -eq 'Running'
                } | Stop-Service -Verbose)
        }
            
    }
    $ObjServiceStatus | Format-Table -Property *
    #$ServiceStatus | Format-Table -Property *
}
FUNCTION Resolve-HostNameOrAddress {
    [CmdletBinding()]
    PARAM
    (
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)][Alias('HostName')][Alias('cn')][Alias('ComputerName')][Alias('IPAddress')][string[]]$NameOrIPAddress = $env:COMPUTERNAME
    )
    
    BEGIN {
    }
    
    PROCESS {
        FOREACH ($computer IN $NameOrIPAddress) {
            TRY {
            
                [bool]$isIPAddress = [bool]($computer -as [ipaddress])
                Write-Host isIPAddress $isIPAddress
                IF ($isIPAddress -eq $true) {
                    $ip1 = $computer
                    $host1 = [System.Net.Dns]::GetHostEntry($computer)
                }
                ELSE {
                  
                    
                    [System.Net.IPHostEntry]$ip1 = [System.Net.Dns]::GetHostEntry($computer)
                    [System.Net.IPAddress[]]$ip1 = $ip1.AddressList;
                    Write-Host $ip1 | % {
                        $_.IPAddressToString
                    }
                    
                    $host1 = [System.Net.Dns]::GetHostEntry($ip1)
                }
                
                #If the host has an IPAddressList, it will be in $host1.AddressList
                New-Object psobject -Property @{
                    Input           = $computer
                    IPAddressString = $ip1.IPAddressToString
                    ComputerName    = $host1.HostName
                    IPAddress       = $ip1
                    Host            = $host1
                    IsError         = 'N'
                    Error           = $null
                }
                
            }
            CATCH {
                $err = $_.Exception
                
                New-Object psobject -Property @{
                    Input           = $computer
                    IPAddressString = $null
                    ComputerName    = $null
                    IPAddress       = $null
                    Host            = $null
                    IsError         = 'Y'
                    Error           = $err
                }
                
                Write-Warning "$computer - $err"
            }
        }
    }
    
    END {
    }
}

FUNCTION Gen-Configfile {
    [cmdletbinding(SupportsShouldProcess)]
    PARAM ([Parameter(Mandatory, Position = 0)][ValidateNotNull()]
        [ValidateNotNullOrEmpty()][string]$computername,
                
        [Parameter(Mandatory, Position = 1)][ValidateNotNull()]
        [ValidateNotNullOrEmpty()][string]$database,
                
        [Parameter(Mandatory, Position = 2)][ValidateNotNull()]
        [ValidateNotNullOrEmpty()][string]$appserver
    )
    
    
    if (!($database -eq 'gce')) {
        $FWS_query = ("
use $database
--SELECT @@SERVERNAME + '\' + @@SERVICENAME AS InstanceName
UPDATE GC_TowActivity
SET WorkingFolder = ('\$appserver' + SUBSTRING(WorkingFolder, CHARINDEX('\GPOD\', WorkingFolder), LEN(WorkingFolder)))
WHERE WorkingFolder LIKE '%GPOD%';
GO

UPDATE GC_ServicesParms
SET ParmValue = ('$script:driveletter' + SUBSTRING(ParmValue, CHARINDEX('\GPOD\', ParmValue), LEN(ParmValue)))
WHERE ParmName IN ('BACKUP_PATH', 'DB_BACKUP_PATH', 'REPORT_PATH', 'ADJUSTMENT_LETTER_PATH', 'CLIENT_AUTO_UPDATE_PATH');
GO
 
UPDATE GC_ServicesParms
SET ParmValue = 'N'
WHERE ParmName = 'CLIENT_AUTO_UPDATE_ENABLED' OR ParmName = 'USE_SECOND_LEVEL_SIGN_ON'

UPDATE GC_ServicesParms
SET ParmValue = '$appserver'
WHERE ParmName = 'CENTRAL_SERVER'

UPDATE GC_ITEMTABLECONTROL
SET ConnectionString = 'Data Source=$computername;Initial Catalog=$database;Integrated Security=True;Persist Security Info=True;Connect Timeout=30'

UPDATE Report
SET ExecutablePath = 'Data Source=$computername;Initial Catalog=$database;Integrated Security=True;Persist Security Info=True;Connect Timeout=30'
")
        
        
        $pathScripts = "$ScriptPath\Scripts" 
        If (!(test-path $pathScripts)) { New-Item -ItemType Directory -Force -Path $pathScripts }
        IF (!(Test-Path "$ScriptPath\Scripts\FWS_update.sql" -PathType Leaf -IsValid)) {
            New-Item -path $ScriptPath\Scripts\ -name FWS_update.sql -type "file" -value "$FWS_query"
            Write-Host $LOGTIME `t "Created new file and text content added"
        }
        Write-output "--$LOGTIME `t $FWS_query" | Out-File $ScriptPath\Scripts\FWS_update.sql
        write-host $LOGTIME `t $FWS_query -ForegroundColor Magenta
        $title = "Update destinastion database!"
        $message = "Excute on $SettingDestinationServer"
        $option1 = New-Object System.Management.Automation.Host.ChoiceDescription "Update $SettingDestinationServer Config: &YES", "YES"
        $option2 = New-Object System.Management.Automation.Host.ChoiceDescription "Update $SettingDestinationServer Config: &NO", "NO"
        $option3 = New-Object System.Management.Automation.Host.ChoiceDescription "&Return to Menu", "Menu"
        $option4 = New-Object System.Management.Automation.Host.ChoiceDescription "&Exit", "Exit"
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($option1, $option2, $option3, $option4)

        $result = $host.ui.PromptForChoice($title, $message, $options, 1)

        switch ($result) {
            0 {
                Write-host $LOGTIME `t YES -ForegroundColor Green
                $DbaSqlQuery = Invoke-DbaQuery  -SqlInstance $SettingDestinationServer -Database $database -Query $ScriptPath\Scripts\FWS_update.sql
                Write-host $LOGTIME `t $DbaSqlQuery
                if ($?) {
                    Write-Host $LOGTIME `t $DbaSqlQuery + " File executed successfully"  -foregroundcolor "green";
                }
                else {
                    Write-Host $LOGTIME `t $DbaSqlQuery.FullName + " File execution FAILED" -foregroundcolor "red";
                }
          
            }
            1 {
                Write-host NO -ForegroundColor red
                Write-host $LOGTIME `t Script was generated but hasnt yet been run -ForegroundColor red
                Write-host $LOGTIME `t $ScriptPath\Scripts\FWS_update.sql

            }
            2 { Show-Menu }
            3 { exit }
        }
        
    }
    
    ##
    #Find and replace Working
    ##
    FOREACH ($SettingREplac IN $SettingREplace) {
        $Test = $([regex]::split($SettingREplac, ";;"))
        
        IF (!([string]::IsNullOrWhiteSpace($Test))) {
            
            $Splitt = $Test | ForEach-Object {
                $_.split(',')
            }
            #$Splitt | FT
            
            $FindSQL = $Splitt[0] #| % { $_ -replace '"', ""}
            $replaceSQL = $Splitt[1] #| % { $_ -replace '"', ""}

            "$FindSQL", "$replaceSQL" | Resolve-HostNameOrAddress -WarningAction Inquire | Where-Object {
                $_.IsError -eq 'Y'
            } | Select-Object  Input, ComputerName, IPAddressString, IsError, Error 
                
            Write-Host " $LOGTIME `t FIndSQL :: " -NoNewline -ForegroundColor Cyan
            Write-Host "$FindSQL `t " -NoNewline -ForegroundColor Yellow
            write-host "replaceSQL :: " -NoNewline -ForegroundColor Cyan
            write-host 	"$replaceSQL `t " -NoNewline -ForegroundColor Yellow
            write-host "Working With :: " -NoNewline -ForegroundColor Cyan
            write-host 	"$computername :: $database" -ForegroundColor Yellow
            
            $Table01Param = @{
                OutVariable    = "updatequery = 'updatequery'"
                ServerInstance = $computername
                Database       = $database
                #Debug = $true
                query          = "DECLARE @stringToFind VARCHAR(100); 
DECLARE @stringToReplace VARCHAR(100); 
DECLARE @SearchStrTableName NVARCHAR(255), @SearchStrColumnName NVARCHAR(255), @SearchStrColumnValue NVARCHAR(255), @SearchStrInXML BIT, @FullRowResult BIT, @FullRowResultRows INT;
SET @SearchStrColumnValue = '%$FindSQL%'; /* use LIKE syntax */
SET @FullRowResult = 1;
SET @FullRowResultRows = 990;
SET @SearchStrTableName = '%GC_itemgeneric%'; /* NULL for all tables, uses Not LIKE syntax */
SET @SearchStrColumnName = NULL; /* NULL for all columns, uses LIKE syntax */
SET @SearchStrInXML = 0; /* Searching XML data may be slow */
SET @stringToFind = '$FindSQL'; 
SET @stringToReplace = '$replaceSQL'; 
IF OBJECT_ID('tempdb..#Results') IS NOT NULL DROP TABLE #Results;
CREATE TABLE #Results (TableName NVARCHAR(128), ColumnName NVARCHAR(128), ColumnValue NVARCHAR(MAX),ColumnType NVARCHAR(20));

SET NOCOUNT ON;

DECLARE @TableName NVARCHAR(256) = '',@ColumnName NVARCHAR(128),@ColumnType NVARCHAR(20), @QuotedSearchStrColumnValue NVARCHAR(110), @QuotedSearchStrColumnName NVARCHAR(110);
SET @QuotedSearchStrColumnValue = QUOTENAME(@SearchStrColumnValue,'''');
DECLARE @ColumnNameTable TABLE (COLUMN_NAME NVARCHAR(128),DATA_TYPE NVARCHAR(20));

WHILE @TableName IS NOT NULL
BEGIN
    SET @TableName = 
    (
        SELECT MIN(QUOTENAME(TABLE_SCHEMA) + '.' + QUOTENAME(TABLE_NAME))
        FROM    INFORMATION_SCHEMA.TABLES
        WHERE       TABLE_TYPE = 'BASE TABLE'
            AND TABLE_NAME not Like COALESCE(@SearchStrTableName,TABLE_NAME)
            AND TABLE_NAME not Like COALESCE('FIN_SystemLog',TABLE_NAME)
            --AND TABLE_NAME not Like COALESCE('GC_TOWActivity',TABLE_NAME)
            AND TABLE_NAME not Like COALESCE('GC_Run',TABLE_NAME)
            AND QUOTENAME(TABLE_SCHEMA) + '.' + QUOTENAME(TABLE_NAME) > @TableName
            AND OBJECTPROPERTY(OBJECT_ID(QUOTENAME(TABLE_SCHEMA) + '.' + QUOTENAME(TABLE_NAME)), 'IsMSShipped') = 0
    );
    IF @TableName IS NOT NULL
    BEGIN
        DECLARE @sql VARCHAR(MAX);
        SET @sql = 'SELECT QUOTENAME(COLUMN_NAME),DATA_TYPE
                FROM    INFORMATION_SCHEMA.COLUMNS
                WHERE       TABLE_SCHEMA    = PARSENAME(''' + @TableName + ''', 2)
                AND TABLE_NAME  = PARSENAME(''' + @TableName + ''', 1)
                AND DATA_TYPE IN (' + CASE WHEN ISNUMERIC(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(@SearchStrColumnValue,'%',''),'_',''),'[',''),']',''),'-','')) = 1 THEN '''tinyint'',''int'',''smallint'',''bigint'',''numeric'',''decimal'',''smallmoney'',''money'',' ELSE '' END + '''char'',''varchar'',''nchar'',''nvarchar'',''timestamp'',''uniqueidentifier''' + CASE @SearchStrInXML WHEN 1 THEN ',''xml''' ELSE '' END + ')
                AND COLUMN_NAME LIKE COALESCE(' + CASE WHEN @SearchStrColumnName IS NULL THEN 'NULL' ELSE '''' + @SearchStrColumnName + '''' END  + ',COLUMN_NAME)';
        INSERT INTO @ColumnNameTable
        EXECUTE (@sql);
        WHILE EXISTS (SELECT TOP 1 COLUMN_NAME FROM @ColumnNameTable)
        BEGIN
       --     PRINT @ColumnName;
            SELECT TOP 1 @ColumnName = COLUMN_NAME,@ColumnType = DATA_TYPE FROM @ColumnNameTable;
            SET @sql = 'SELECT ''' + @TableName + ''',''' + @ColumnName + ''',' + CASE @ColumnType WHEN 'xml' THEN 'LEFT(CAST(' + @ColumnName + ' AS nvarchar(MAX)), 4096),''' 
            WHEN 'timestamp' THEN 'master.dbo.fn_varbintohexstr('+ @ColumnName + '),'''
            ELSE 'LEFT(' + @ColumnName + ', 4096),''' END + @ColumnType + ''' 
                    FROM ' + @TableName + ' (NOLOCK) ' +
                    ' WHERE ' + CASE @ColumnType WHEN 'xml' THEN 'CAST(' + @ColumnName + ' AS nvarchar(MAX))' 
                    WHEN 'timestamp' THEN 'master.dbo.fn_varbintohexstr('+ @ColumnName + ')'
                    ELSE @ColumnName END + ' LIKE ' + @QuotedSearchStrColumnValue;
            INSERT INTO #Results
            EXECUTE(@sql);
            IF @@ROWCOUNT > 0 IF @FullRowResult = 99 
            BEGIN
                SET @sql = 'SELECT TOP ' + CAST(@FullRowResultRows AS VARCHAR(3)) + ' ''' + @TableName + ''' AS [TableFound],''' + @ColumnName + ''' AS [ColumnFound],''FullRow>'' AS [FullRow>],*' +
                    ' FROM ' + @TableName + ' (NOLOCK) ' +
                    ' WHERE ' + CASE @ColumnType WHEN 'xml' THEN 'CAST(' + @ColumnName + ' AS nvarchar(MAX))' 
                    WHEN 'timestamp' THEN 'master.dbo.fn_varbintohexstr('+ @ColumnName + ')'
                    ELSE @ColumnName END + ' LIKE ' + @QuotedSearchStrColumnValue;
                EXECUTE(@sql);
            END;
            DELETE FROM @ColumnNameTable WHERE COLUMN_NAME = @ColumnName;
        END; 
    END;
END;
SET NOCOUNT OFF;

--SELECT TableName, ColumnName, ColumnValue, ColumnType, COUNT(*) AS Count FROM #Results
--GROUP BY TableName, ColumnName, ColumnValue, ColumnType
DECLARE @test AS VARCHAR(8000);
--Select * from #Results;
WITH reallyfastcte AS (
SELECT *, 
ROW_NUMBER() OVER (PARTITION BY TableName, ColumnName, ColumnValue, ColumnType ORDER BY TableName, ColumnName, ColumnValue, ColumnType) AS rownum
,LTRIM(RTRIM(REPLACE(REPLACE(REPLACE(ColumnName,'%',''),'[',''),']',''))) as 'NewColumnName',
LTRIM(RTRIM(REPLACE(REPLACE(REPLACE(ColumnValue,'%',''),'[',''),']',''))) as 'NewCColumnValue'
FROM #Results
)
SELECT DISTINCT 'UPDATE ' + TableName+
                   ' SET ' + NewColumnName
                            + ' = REPLACE('+ NewColumnName +','''+ NewCColumnValue +''','''+ (SELECT
STUFF(NewCColumnValue,
    PATINDEX('%'+@stringToFind+'%',ColumnValue),
    LEN(@stringtofind),
    UPPER(SUBSTRING(@stringToReplace,CHARINDEX('',@stringToReplace)-1,0) + ''+ @stringToReplace+''))
WHERE PATINDEX('%'+@stringtofind+'%',ColumnValue) > 0) + ''') WHERE ' + CASE ColumnType WHEN 'xml' THEN 'CAST(' + ColumnName + ' AS nvarchar(MAX))' 
                    WHEN 'timestamp' THEN 'master.dbo.fn_varbintohexstr('+ ColumnName + ')'
                    ELSE ColumnName END + ' LIKE ''%' + NewCColumnValue + '%''' as 'updatequery'
                 
                    
FROM reallyfastcte
WHERE rownum = 1;
IF OBJECT_ID('tempdb..#Results') IS NOT NULL DROP TABLE #Results;
"
            }

            
            $Table1 = Invoke-Sqlcmd2 @Table01Param -As SingleValue
            IF (!([string]::IsNullOrWhiteSpace($Table1))) {

                $pathScripts = "$ScriptPath\Scripts" 
                If (!(test-path $pathScripts)) { New-Item -ItemType Directory -Force -Path $pathScripts }
                $FindReplaceupdate = "$ScriptPath\Scripts\Find_Replace_update{0}.sql" -f (get-date -f "MMddyyyy_hhmmss")
                $Table1 | Format-Table -Property updatequery -AutoSize -HideTableHeaders | Out-String -Width 4096
                $Table1 | Format-Table -Property updatequery -AutoSize -HideTableHeaders | Out-String -Width 4096 | out-file  $FindReplaceupdate
                IF (!(Test-Path "$FindReplaceupdate")) {
                    New-Item -path $FindReplaceupdate
                    New-Item -path $ScriptPath\Scripts -name ("Find_Replace_update{0}.sql" -f (get-date -f "MMddyyyy_hhmm")) -type "file" -value $Table1
                    Write-Host $LOGTIME `t "Created new file and text content added"
                }
            
                Write-output $Table1 | Format-Table -Property updatequery -AutoSize -HideTableHeaders | Out-String -Width 8096 | Out-File $FindReplaceupdate
        

                
                $title = "Update Find replace! $computername"
                $message = "Excute on $computername"
                $option1 = New-Object System.Management.Automation.Host.ChoiceDescription "Update $SettingDestinationServer Config: &YES", "YES"
                $option2 = New-Object System.Management.Automation.Host.ChoiceDescription "Update $SettingDestinationServer Config: &NO", "NO"
                $option3 = New-Object System.Management.Automation.Host.ChoiceDescription "&Return to Menu", "Menu"
                $option4 = New-Object System.Management.Automation.Host.ChoiceDescription "&Exit", "Exit"
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($option1, $option2, $option3, $option4)
            
                $result = $host.ui.PromptForChoice($title, $message, $options, 1)

                switch ($result) {
                    0 {
                        Write-host YES -ForegroundColor Green
                        Invoke-DbaQuery -SqlInstance $computername -Database $database -file $FindReplaceupdate -Verbose 
                        Invoke-Sqlcmd2 -ServerInstance $computername -Database $database -InputFile $FindReplaceupdate -Verbose 
                        if ($?) { Write-Host $LOGTIME `t $DbaSqlQuery + " File executed successfully"  -foregroundcolor "green"; }else { Write-Host $LOGTIME `t $DbaSqlQuery.FullName + " File execution FAILED" -foregroundcolor "red"; }
                        #$PSDefaultParameterValues[$(Write-host $choices[$backup])] =$true
                    }
                    1 {
                        Write-host Script was generated but hasnt yet been run -ForegroundColor red
                        Write-host  $FindReplaceupdate


                    }
                    2 { Show-Menu }
                    3 { exit }
                }

            }
            ELSE {
                Write-Host No String found to replace -ForegroundColor Cyan
                Continue
            }

        }
        else {
            Write-Host skipping emtpy field
            RETURN;
        }
        
    }
    Show-Menu

}
#Write-Host 	
    
$DBArrey = @()
FUNCTION Mig-CertainDatabases	
{
    [CmdletBinding()]
    PARAM (
                
        [switch]$GenConfigfile,
                
        [switch]$Services,
                
        [switch]$Start,
                
        [switch]$Tasks
    )
    IF (Test-Path "$ScriptPath\Databases.txt") {
        $MigDatabases = Get-Content "$ScriptPath\Databases.txt" -ErrorAction Stop
        $MigDatabases | ForEach-Object {
            write-host $_ -ForegroundColor Magenta -  #$database.Name
            $DBarrey += $_

                
            $SQLQuery = "select CENTRAL_SERVER
from
(
  select ParmName, ParmValue
  from GC_ServicesParms
) d
pivot
(
  max(ParmValue)
  for ParmName in (CENTRAL_SERVER)
) piv;"
            Write-host SettingSourceServer $SettingSourceServer
            TRY {
                $Datatable = New-Object System.Data.DataTable
                    
                $Connection = New-Object System.Data.SQLClient.SQLConnection
                $Connection.ConnectionString = "server=$SettingSourceServer;database='$_';trusted_connection=true;"
                $Connection.Open()
                $Command = New-Object System.Data.SQLClient.SQLCommand
                $Command.Connection = $Connection
                $Command.CommandText = $SQLQuery
                    
                $DataAdapter = new-object System.Data.SqlClient.SqlDataAdapter $Command
                $Dataset = new-object System.Data.Dataset
                $DataAdapter.Fill($Dataset)
                $Connection.Close()
                #	$Applicationserver = $Dataset.Tables[0].Rows[0].CENTRAL_SERVER
            }
            CATCH {
                    
            }
        }
            
        Write-host "Current database server  $SettingSourceServer " -ForegroundColor yellow
        Write-host "Current Application server  $Applicationserver " -ForegroundColor Cyan
        write-host "SQL Destination server $SettingDestinationServer " -ForegroundColor yellow
        Write-host "Destination Application server $DestinationApplicationserver " -ForegroundColor Cyan
        Write-host	$_ -ForegroundColor yellow
        WRITE-HOST $DBarrey -ForegroundColor Green
        $DBarrey
            
        Read-host "Please confirm values above values hit enter to continue"
            
    }

    if ($Services) {
        Control-Services -ComputerName $Applicationserver -Disable -Stop;
    }

    if ($Tasks) {
        WaitOnScheduledTask -server $Applicationserver -tasks 'GC DailyCleanup',
        'GC FolderCleanup',
        'GCE Auto Create NCC Files',
        'GCE Auto EOD',
        'GCE Auto SOD',
        'GCE Daily Clean Up',
        'GCE Update Completed Binary Files' -Disable
    }
    

         
    #================================================================================================
    #Generates GPOD update script to Local directory .\Scripts\FWS_update.sql		
    #This script will be desplayed can confirmed by the tech
        
    #================================================================================================	

 
    $dir = Set-MigShare

    $DBarrey | Foreach {
        Write-host $_
        Get-DbaProcess -SqlInstance $script:SettingSourceServer, $script:SettingDestinationServer -Program 'DR Tool' | Stop-DbaProcess -SqlInstance $script:SettingSourceServer -WarningAction Inquire
        $results = Copy-DbaDatabase -Source $script:SettingSourceServer -Destination $script:SettingDestinationServer -Database $_ -WithReplace -Force -BackupRestore -NetworkShare $dir -Verbose -EnableException -WarningAction Inquire # 3>$null

        IF ($results.Status -eq "Successful") {
            Write-host " $($results.Name) copies a database successfully" -ForegroundColor Green
            $results | FT -Property *
        }
    }
    if ($GenConfigfile) {
        Gen-Configfile -computername $SettingDestinationServer -database $SettingDatabase -appserver $DestinationApplicationserver
        Gen-Configfile -computername $SettingDestinationServer -database 'gce' -appserver $DestinationApplicationserver
    }

    if ($Services) {
        Control-Services -ComputerName $DestinationApplicationserver -Enable -Start
     
    }

    if ($Tasks) {
        WaitOnScheduledTask -server $DestinationApplicationserver -tasks 'GC DailyCleanup',
        'GC FolderCleanup',
        'GCE Auto Create NCC Files',
        'GCE Auto EOD',
        'GCE Auto SOD',
        'GCE Daily Clean Up',
        'GCE Update Completed Binary Files' -Enable
    }
    

}


Set-MigShare
[string[]]$SettingREplace = @()


FUNCTION Show-Menu {
    Clear-Host
    Write-Host "+------------------------------------------+" -ForegroundColor Cyan
    Write-Host "Â¦  Welcome Botswana DR switch   0.0.2.1   Â¦" -ForegroundColor Cyan
    Write-Host "+------------------------------------------+" -ForegroundColor Cyan
   
    Write-Host " FROM: " -NoNewline
    Write-host "$($SettingSourceServer.ToUpper()) " -NoNewline -ForegroundColor Yellow
    Write-host " `n >>>" -NoNewline
    Write-host "TO: " -NoNewline
    write-host " $($SettingDestinationServer.ToUpper())" -ForegroundColor Yellow "`n"
    IF ($Force) {
        Write-Host " Attention: FORCE is active" -ForegroundColor Red
    }
    
    Write-Host " Press '1' Check if DR switch is Possible"
    Write-Host " Press '2' Stop & disable services on Production " -NoNewline
    write-host "$($Applicationserver)" -ForegroundColor Yellow 

    Write-Host " Press '3' Disable Scheduled Tasks on Source server " -NoNewline
    Write-host "$($Applicationserver)" -ForegroundColor Yellow
    Write-Host " Press '4' Migrates\copys databases definded in >> .\databases.txt " -NoNewline
    Write-Host " $SettingSourceServer " -ForegroundColor Yellow -NoNewline
    Write-host " > Destination :" -NoNewline
    Write-host "$SettingDestinationServer" -ForegroundColor yellow
    Write-Host " Press '5' DR :: Generate & Runs (Find Replace) Gen-Configfile For "  -NoNewline
    Write-Host "$($SettingDestinationServer)"  -ForegroundColor Yellow
    Write-Host " Press '6' Enable & Run Scheduled Tasks on Destinaction server "  -NoNewline
    Write-Host "$($SettingDestinationServer)"  -ForegroundColor Yellow
    Write-Host " Press '7' Copy SQL login Source :" -NoNewline
    write-host  $SettingSourceServer -ForegroundColor Yellow -NoNewline
    Write-host " > Destination :" -NoNewline
    Write-host "$SettingDestinationServer" -ForegroundColor yellow
    Write-Host " Press '8' Starts & Enable services on Production " -NoNewline
    Write-host "$($DestinationApplicationserver)" -ForegroundColor Yellow
    Write-Host " Press '9' Run all at once"
    Write-Host " Press '10' Update Branchs Config " -nonewline
    Write-Host "[Note Branchs must be added to >> $ScriptPath\Branch.txt]" -ForegroundColor Yellow -BackgroundColor DarkCyan
    write-host " Press '11' Update Client connectionstring [Note Clitent PC names must be added to >> $ScriptPath\Clientss.txt]"
    IF (!$Force) {
        Write-Host " Write 'FORCE' to enable the FORCE Parameter (with overwrite)"
    }
    IF ($Force) {
        Write-Host " Write 'ENDFORCE' to disable the FORCE Parameter"
    }
    Write-Host " Press 'q' to quit.`n"
}
$ShowMenu = $true
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent #Get-ScriptDirectory
IF ($(Test-Path "$ScriptPath\settings.ini")) {
    $i = 0
    Get-Content "$ScriptPath\settings.ini" -ErrorAction Stop | foreach-object -begin {
        $setting = @{
        }
    } -process {
        $x = [regex]::split($_, '='); IF (($x[0].CompareTo("") -ne 0) -and ($x[0].StartsWith("[") -ne $True)) {
            $setting.Add($x[0], $x[1])
        }
    }
    $SettingMigShare = Set-MigShare $($setting.SmbShare)
    $SettingSourceServer = $($setting.SourceServer)
    $ApplicationServer = $($setting.SourceApplicationServer)
    $SettingDestinationServer = $($setting.DestinationServer)
    $DestinationApplicationserver = $($setting.DestinationApplicationServer)
    
    $SettingDatabase = $($setting.Database)
    $script:driveletter = $($setting.GPODFolderDriveletter)
    #FindReplace Adds ";;" to each entry so '.' or ',' would confict
    $SettingREplace += $($Setting.replace0 + ";;")
    $SettingREplace += $($Setting.replace1 + ";;")
    $SettingREplace += $($Setting.replace2 + ";;")
    $SettingREplace += $($Setting.replace3 + ";;")
    $SettingREplace += $($Setting.replace4 + ";;")
    $SettingREplace += $($Setting.replace5 + ";;")
    $SettingREplace += $($Setting.replace6 + ";;")
    $SettingREplace += $($Setting.replace10)

}
ELSE {
    Write-Host "File not found settings.ini, but don't worry. :(...^_^" -ForegroundColor Red
    $SettingMigShare = read-host "[*]set migration directory"
    $SettingMigShare = Set-MigShare $SettingMigShare
    $SettingSourceServer = read-host "[*]set source Server"
    $SettingDestinationServer = read-host "[*]set destination server"
    $SettingDatabase = read-host "[*]set Database"
}
    

FUNCTION Get-CENTRAL_SERVER {
    [CmdletBinding()]
    PARAM ([Parameter(Mandatory, Position = 0)][string]$computername,
            
        [Parameter(Mandatory, Position = 1)][string]$database
    )
    $SettingDatabase = $database
    $SettingSourceServer = $computername
    IF (Test-Path "$ScriptPath\Databases.txt") {
        $MigDatabases = Get-Content "$ScriptPath\Databases.txt" -ErrorAction Stop
        $MigDatabases | ForEach-Object {
            $db = $_ #$database.Name
            Write-host $db
            start-sleep 5
        }
    }
    ELSEIF (!($SettingDestinationServer)) {
        
        $db = $SettingDatabase
        
    }
    ELSE {
        RETURN "Create a $ScriptPath\Databases.txt with all your certain databases you want to migrate.`nAfter that, come back and choose the same option again.`n"
    }

    $SQLQuery = "select CENTRAL_SERVER
from
(
  select ParmName, ParmValue
  from GC_ServicesParms
) d
pivot
(
  max(ParmValue)
  for ParmName in (CENTRAL_SERVER)
) piv;"
    
    TRY {
        
        $Datatable = New-Object System.Data.DataTable
        
        $Connection = New-Object System.Data.SQLClient.SQLConnection
        $Connection.ConnectionString = "server='$SettingSourceServer';database='$SettingDatabase';trusted_connection=true;"
        $Connection.Open()
        $Command = New-Object System.Data.SQLClient.SQLCommand
        #	Import-Module PesterImport-Module Pester	
        $Command.Connection = $Connection
        $Command.CommandText = $SQLQuery
        
        $DataAdapter = new-object System.Data.SqlClient.SqlDataAdapter $Command
        $Dataset = new-object System.Data.Dataset
        [void]$DataAdapter.Fill($Dataset)
        $Connection.Close()
        
        $Applicationserver = $Dataset.Tables[0].Rows[0].CENTRAL_SERVER
        RETURN $Applicationserver
    }
    CATCH {
        write-host $_
    }
}

    
Write-host SettingSourceServer $SettingSourceServer

IF (([string]::IsNullOrWhiteSpace($Applicationserver))) {
    write-host Applicationserver empty attempting to retrieve from database 



}

Write-host SettingSourceServer $SettingSourceServer
Write-host "Application server  $Applicationserver " -ForegroundColor Cyan
Write-host $SettingREplace -ForegroundColor Magenta
IF (!($DestinationApplicationserver)) {
    $DestinationApplicationserver = Get-CENTRAL_SERVER -computername $SettingDestinationServer -database $SettingDatabase
    
    DO {
        
        Write-Host Couldnt find DR application server :: please enter Name\IPaddress of the DR Server
        $DestinationApplicationserver = Read-Host "[*]set DR Application server"
        IF ($DestinationApplicationserver -eq '') {
            Write-Host -BackgroundColor Red -ForegroundColor Black "Invalid entry, please try again"
            #$error.clear()
        }
        if (!([String]::IsNullOrWhiteSpace($DestinationApplicationserver))) {
            Write-Host Checking if input is valid resolving hostname if IP was entere
            IF (-not !($DestinationApplicationserver -As [IPAddress]) -As [Bool]) {
                TRY {
                    Write-Host Attempting to resolve hostname of ipaddress $DestinationApplicationserver
                    $DestinationApplicationserver = [System.Net.Dns]::GetHostEntry($DestinationApplicationserver).HostName
                }
                CATCH {
                    Write-Host $DestinationApplicationserver Host name could not be resolved please enter host name and not IPaddress
                    $DestinationApplicationserver = $null
                }
                    
            }
        }
        #$DestinationApplicationserver = Read-Host
    } WHILE ([String]::IsNullOrWhiteSpace($DestinationApplicationserver))
    Write-Host 	$DestinationApplicationserver -ForegroundColor Cyan
        
        
}

#Gets the service account for later 
$ServiceAccount = Get-WMIObject Win32_Service -ComputerName $Applicationserver | ? {
    $_.name -like "GC_policeman"
} | select startname

$ServiceAccount = $ServiceAccount.startname
Write-Host ServiceAccount :: $ServiceAccount
#starts the menu
IF ($ShowMenu) {
    DO {
        Show-Menu
        $input = Read-Host "Select option"
        $elapsed = [System.Diagnostics.Stopwatch]::StartNew()
            
        $OutputLog = "$($SettingSourceServer.Split(".")[0])-to-$($SettingDestinationServer.Split(".")[0])-migration.log"
            
        Start-Transcript -path $ScriptPath\ -append
            
        SWITCH ($input) {
            {
                    ($_ -eq "") -or ($_ -eq "1")
            } {
                Test-DbaMigrationConstraint -Source $SettingSourceServer -Destination $SettingDestinationServer -Database $SettingDatabase  -Verbose | Format-Table Database, Notes, SourceVersion, DestinationVersion
             
                Measure-DbaDiskSpaceRequirement -Source $SettingSourceServer -Database $SettingDatabase -Destination $SettingDestinationServer -DestinationDatabase $SettingDatabase -Verboses 
             
                ; BREAK
            }
                
            '2' {
                Control-Services -ComputerName $ApplicationServer -Disable -Stop; BREAK
            }
            #'2' {Copy-DbaDatabase -Source $SettingSourceServer -Destination $SettingDestinationServer -Database $SettingDatabase.ToSingle() -BackupRestore -NetworkShare $SettingMigShare -Force -WithReplace -Confirm; break}
            '4' {
                Mig-CertainDatabases; BREAK
            }
            '8' {
                Control-Services -ComputerName $DestinationApplicationserver -Enable -Start; BREAK
              
            }
            '3' {
                WaitOnScheduledTask -server $ApplicationServer -ServiceAccount $ServiceAccount -tasks 'DailyCleanup',
                'GC FolderCleanup',
                'GCE Auto Create NCC Files',
                'GCE Auto EOD',
                'GCE Auto SOD',
                'GCE Daily Clean Up',
                'GCE Update Completed Binary Files', 'Copy Account Status File', 'Move Inward Files', 'Move Outward Files' -Disable -maxSeconds 10 ; Break
            }
           
            '6' {
                WaitOnScheduledTask -server $DestinationApplicationserver -ServiceAccount $ServiceAccount -tasks 'GC DailyCleanup',
                'GC FolderCleanup',
                'GCE Auto Create NCC Files',
                'GCE Auto EOD',
                'GCE Auto SOD',
                'GCE Daily Clean Up',
                'GCE Update Completed Binary Files', 'Copy Account Status File', 'Move Inward Files', 'Move Outward Files' -enable; break
            }
            '7' {
                Copy-DbaLogin -Source $SettingSourceServer -Destination $SettingDestinationServer -sync -Verbose -Force:$Force; BREAK
            }
            '5' {
                Gen-Configfile -computername $SettingDestinationServer -database $SettingDatabase -appserver $DestinationApplicationserver
                Gen-Configfile -computername $SettingDestinationServer -database 'gce' -appserver $DestinationApplicationserver
                break
            }
            '9' {
                Mig-CertainDatabases -GenConfigfile -Services -Tasks
            }
            '10' {
                Get-Content $ScriptPath\Branch.txt | ForEach-Object {
                    Gen-Configfile -computername $_ -database 'gce' -appserver $_
                    Control-Services -ComputerName $_ -Stop
                    Control-Services -ComputerName $_ -start
                }
                break
            }
            '11' {
                Set-ClientGPODString -Input "$ScriptPath\Clientss.txt" -Username 'Administrator'; break
            }
            'FORCE' {
                $Force = $true
            }
            'ENDFORCE' {
                $Force = $true
            }
            'q' {
                RETURN
            }
        }
            
        Stop-Transcript
        $ErrorActionPreference = "SilentlyContinue"
        write-host elapsed time: ($elapsed.Elapsed.toString().Split(".")[0])
        write-host detaild migration log $ScriptPath\.
        pause
    } UNTIL ($input -eq 'q')
        
}
    
Show-Menu

