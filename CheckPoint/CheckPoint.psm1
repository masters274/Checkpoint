#requires -Version 3.0 -Modules Posh-SSH, core

# TODO: Create service object
# TODO: NAT on host objects, via param and pipeline

#region System Commands


Function Get-CheckPointActiveShell {
    Param (
        [Parameter(Mandatory = $true, HelpMessage = 'IP or hostname of the firewall')]
        [String] $Firewall,
        
        [Parameter(Mandatory = $true, HelpMessage = 'Credentials for managing workstations')]
        [System.Management.Automation.Credential()]
        [PSCredential] $Credential
    )
    
    $strCommand = 'echo $SHELL'
    $strFailed = 'CLINFR0329'
    
    # Create an SSH session to the firewall 
    $objSession = New-SSHSession -Credential $Credential -ComputerName $Firewall
	
    
    $retVal = Invoke-SSHCommand -SessionId $objSession.SessionId -Command $strCommand
    
    If ($retVal.Output -match $strFailed) {
        Return 'CliSH'
    }
    Else {
        $retVal.Output
    }
    
    # Clean up
    $null = Remove-SSHSession -SessionId $($objSession.SessionId) 
}


Function Get-CheckpointVpnActiveUser {
    # Get the count or details of all users connected via VPN
    # Get all the connected users, and their data [UserName, UserDN, PeerLast, Expires]
    # fw tab -t userc_users -f | sed 's/;/\n/g'
    
    # Get a count of active users
    # "fw tab -t userc_users -s |grep userc_users |sed 's/ \+/ /g' |cut -d' ' -f4"
	
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Firewall')]
        [Alias('Firewall')]
        [String] $Server,
        
        [Parameter(Mandatory = $true, Position = 1,
            HelpMessage = 'Credentials to connect to your firewall')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        # List of required modules for this function
        $arrayModulesNeeded = (
            'Posh-SSH', 'core'
        )
        
        # Verify and load required modules
        $ErrorActionPreference = 'Stop'
        Test-ModuleLoaded -RequiredModules $arrayModulesNeeded -Quiet
    }
    
    Process {
        # Get active users 
        [String] $strCommand = 'fw tab -t userc_users -f'
    
        # Connection
        $objSessionCheckpoint = New-SSHSession -ComputerName $Server -Credential $Credential -AcceptKey -ConnectionTimeout 90
        $sshStream = New-SSHShellStream -SessionID $($objSessionCheckpoint.SessionID)
        
        $rawOutput = @()
    
    
        # Execute commands on the server via ssh
        $null = $sshStream.Read() # Clear the default messages from the buffer. 
        $SshStream.WriteLine($strCommand) 
        $boolDataReceived = $false
        
        :waiter While ($true) {
            $streamOut = $sshStream.Read() 
            
            If ($boolDataReceived -eq $true -and $streamOut.Length -eq 0) {
                break waiter
            }
            
            If ($streamOut.Length -gt 0) {
                $rawOutput += $streamOut
                $streamOut = $null 
                $boolDataReceived = $true # Watch until we do not receive data anymore
            }

            Start-Sleep -Seconds 2 # fw is sloooow.
        }
    
        # Data
        $objOfHolding = @()
     
        Foreach ($Thing in $( $rawOutput.Split("`n") | Select-String -Pattern ' :(+);' -SimpleMatch -AllMatches) ) {
            $objBuilder = New-Object -TypeName PSObject

            Foreach ($line in $Thing.ToString().Split(';')) {
                $line = $line.Trim("^,")

                If ($line -notmatch "^$|^\s") {
                    # Temp variables
                    $tmpName = $null
                    $tmpName = $line.Split(':')[0]
                    
                    If ($tmpName.Trim() -eq 'ConnectTime') {
                        $tmpName = $tmpName + '_UTC'
                        $tmpVal = $null
                        $tmpVal = $line.Split(':')[1]
                        
                        # Object stored in CTIME/Unix time format
                        $epoch = get-date '1/1/1970'
                        $tmpVal = $epoch.AddSeconds($tmpVal)
                    }
                    
                    Else {
                        $tmpVal = $null
                        $tmpVal = $line.Split(':')[1]
                    }
                
                    Invoke-DebugIt -Console -Message 'Name' -Value $tmpName
                    Invoke-DebugIt -Console -Message 'Value' -Value $tmpVal
                
                    $objBuilder | 
                    Add-Member -MemberType NoteProperty -Name $tmpName -Value $tmpVal
                }
            }
        
            $objOfHolding += $objBuilder
        }
    
        If (!($objOfHolding.Count -gt 0)) {
            Write-Host "`n"
            Write-Host 'No data returned. Try increasing the timeout. You may have a slow firewall :(' -ForegroundColor Red
            Write-Host "`n"
        }
        
        Else {
            $objOfHolding
        }
    }
    
    End {
        $null = Remove-SSHSession -SessionId $($objSessionCheckpoint.SessionID) 
    }
}


Function Add-CheckpointSamDatabaseEntry {
    <#
            .Synopsis
            Block an IP on your Checkpoint firewall

            .DESCRIPTION
            Uses the destination IP address to block all traffic to that host

            .EXAMPLE
            Add-CheckpointSamDatabaseEntry firewall1 forever john

            .EXAMPLE
            Add-CheckpointSamDatabaseEntry -Server firewall1 -BlockTime Hour -Credential $myCreds
    #>

    <#
            Version 0.0
            - Day one!

            TODO: Add more functionality for editing the SAM database
    #>

    [CmdLetBinding()]
    Param
    (   <#     
                [Parameter(Mandatory=$true, Position=0,
                HelpMessage='Select the type of action you wish to take.')]
                [ValidateSet('Block','CSV','Screen','GridView')]
                [String] $Action, 
        #>                         # Currently only blocking
        
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Firewall')]
        [String] $Server,
        
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Destination IP we want to block')]
        [Alias('host')]
        [String] $ThreatActor,
        
        [Parameter(Position = 1)]
        [ValidateSet('10Minutes', 'Hour', 'Day', 'Week', 'Forever')]
        [String] $BlockTime = 'Hour',
        
        [Parameter(Mandatory = $true, Position = 2,
            HelpMessage = 'Credentials to connect to your firewall')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        # List of required modules for this function
        $arrayModulesNeeded = (
            'Posh-SSH', 'core'
        )
        
        # Verify and load required modules
        Test-ModuleLoaded -RequiredModules $arrayModulesNeeded -Quiet
    }
    
    Process {
        # Variables
        $dicTime = @{
            '10Minutes' = 600
            'Hour'      = 3600
            'Day'       = 86400
            'Week'      = 604800
        }
        [String] $strCommand = 'fw sam '
        
        If (!($BlockTime -eq 'Forever')) {
            $strCommand += '-t {0} ' -f $dicTime[$BlockTime]
        }
        
        $strCommand += '-I dst {0}' -f $ThreatActor

        $objSessionCheckpoint = New-SSHSession -ComputerName $Server -Credential $Credential -AcceptKey -ConnectionTimeout 90
        $sshStream = New-SSHShellStream -SessionID $($objSessionCheckpoint.SessionID)
        $rawOutput = ''
        
        
        $SshStream.WriteLine($strCommand) 
        Start-Sleep -Seconds 1
        $rawOutput = $sshStream.Read()
    }
    
    End {
        $null = Remove-SSHSession -SessionId $($objSessionCheckpoint.SessionID)
    }
}


Function Set-CheckPointStaticRoute {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [IPAddress] $Network,
        
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Netmask')]
        [IPAddress] $Mask,
        
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [IPAddress] $Gateway,
        
        [ValidateSet('on', 'off')]
        [String] $State = 'on',
        
        [Parameter(Mandatory = $true, HelpMessage = 'IP or hostname of the firewall')]
        [String] $Firewall,
        
        [Parameter(Mandatory = $true, HelpMessage = 'Creds for user with clish shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential,
        
        [Switch] $Force
    )

    Process {
    
        $strShell = Get-CheckPointActiveShell -Firewall $Firewall -Credential $Credential
    
        Try {
            $objAddr = IP-Calc -IPAddress $Network -Mask $Mask -WarningAction Stop -ErrorAction Stop
        }
        Catch {
            Throw
            Return
        }
    
        #[String] $strCidr = (Convert-SubnetMaskToCidr -SubnetMask $Mask).ToString()
        [String] $strCidr = $objAddr.PrefixLength.ToString()
    
        [String] $strCommand = 'set static-route {0}/{1} nexthop gateway address {2} {3}' -f `
            $Network.IPAddressToString, $strCidr, $Gateway.IPAddressToString, $State
    
        If ($strShell -eq 'CliSH') { 
            $objSession = New-SSHSession -Credential $Credential -ComputerName $Firewall

            $retVal = Invoke-SSHCommand -SessionId $objSession.SessionId -Command $strCommand
    
            $retVal
    
            # Clean up
            $null = Remove-SSHSession -SessionId $($objSession.SessionId) 
        }
        Else {
            Write-Error -Message "`nThis command requires SuperShell (CliSH) as the default. You're using $strShell `n"
            Return
        }
    }
}


Function Get-CheckPointRouteTable {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True,
            HelpMessage = 'IP or hostname of the firewall')]
        [String] $Firewall,
        
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True,
            HelpMessage = 'Creds for user with clish shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential
    )
    
    Begin {
        Function ConvertFrom-ShowRoute ($InputObject) {
            $strReMatch = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
            
            $routes = $InputObject -match $strReMatch -replace " `+|, ", ' '

            $objRoutes = @()

            $dicTypes = @{
                'C'    = 'Connected'
                'S'    = 'Static'
                'R'    = 'RIP'
                'B'    = 'BGP'
                'D'    = 'Default'
                'U'    = 'Unreachable'
                'i'    = 'Inactive'
                'K'    = 'Kernel'
                'H'    = 'Hidden'
                'P'    = 'Suppressed'
                'O IA' = 'OSPF InterArea'
                'O E'  = 'OSPF External'
                'O N'  = 'OSPF NSSA'
                'A'    = 'Aggregate'
            }

            Foreach ($route in $routes) {
                
                # Define all object members
                $strType = $dicTypes[$($route.Split(' ').Trim()[0])]

                $objNetwork = IP-Calc -CIDR $($route.Split(' ').Trim()[1])

                [IPAddress] $Network = $objNetwork.IP

                If ($objNetwork.IP -eq '0.0.0.0') {
                    $strType = 'Default'
                    [IPAddress] $Netmask = $Network
                }
                Else {
                    [IPAddress] $Netmask = $objNetwork.Mask
                }

                #     
                IF ($strType -eq 'Connected') {
                    [IPAddress] $Gateway = $Network

                    [String] $Interface = $route.Split(' ').Trim()[5]

                    [Int] $Cost = 0

                    [Int] $Age = 0
                }
                Else {
                    [IPAddress] $Gateway = $route.Split(' ').Trim()[3]

                    [String] $Interface = $route.Split(' ').Trim()[4]

                    [Int] $Cost = $route.Split(' ').Trim()[6]

                    [Int] $Age = $route.Split(' ').Trim()[8]
                }
                
                

                # Build the object
                $objBuilder = New-Object -TypeName PSObject

                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Type' -Value $strType

                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Network' -Value $Network

                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Mask' -Value $Netmask

                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Gateway' -Value $Gateway

                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Interface' -Value $Interface

                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Cost' -Value $Cost

                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Age' -Value $Age

                $objRoutes += $objBuilder
            }

            $objRoutes
        }
    }
    
    Process {
        # Need to figure out which shell we're working with
        $strShell = Get-CheckPointActiveShell -Firewall $Firewall -Credential $Credential
        
        If ($strShell -eq 'CliSH') {
            [String] $strCommand = 'show route'

            $objSession = New-SSHSession -Credential $Credential -ComputerName $Firewall

            $retVal = Invoke-SSHCommand -SessionId $objSession.SessionId -Command $strCommand

            $objRoutes = ConvertFrom-ShowRoute $retVal.Output
        }
        Else {
            Write-Error -Message "`nThis command requires SuperShell (CliSH). You're using $strShell `n"
            Return
        }

        # Clean up
        Remove-SSHSession -SessionId $objSession.SessionId
    
        $objRoutes
    }

    End {
        
    }
}


New-Alias -Name Get-CheckpointVpnActiveUsers -Value Get-CheckpointVpnActiveUser -ErrorAction SilentlyContinue -WarningAction SilentlyContinue


#endregion


#region Bulk import commands


Function New-CheckPointImportFile { 
    # Build a clean import list for Checkpoint network objects from a CSV file
    <#
            CSV Headers
            Group,CIDR,IP,Netmask,Type,Site,Name,Color,Comment
    #>
	
    Param
    (
        [String] $InputFile = ".\nodes.csv",
        
        [String] $OutputFile = ".\$(Get-Date -UFormat '%Y%m%d-%H%M%S')-dbedit-import.txt",
        
        [Parameter(Mandatory = $True, HelpMessage = 'Checkpoint Firewall',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall,
        
        [Parameter(Mandatory = $True, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential
    )
    # Note: The "-" (dash) sign is used in INSPECT code as a word separator, and any string that is in the form of: "<characters>-<reserved word>" cannot be used (e.g., the name "something-inbound").   *** in English... just use an underscore ("_") character. 

    # Variables:
    [System.Collections.ArrayList] $arrayCollectionOutput = @()
    # Empty array for building temporary output.
    $boolShouldContinue = $true
    $boolDebug = $true

    # Private functions:
    function createNetworkObject ([String] $Name, [String] $Color, [String] $Comments, [String] $IP, [String] $Netmask, [String] $Group) {
        # Output code to create network object
        $arrayCollectionOutput.Add("create network $Name")
        $arrayCollectionOutput.Add("modify network_objects $Name ipaddr $IP")
        $arrayCollectionOutput.Add("modify network_objects $Name netmask $Netmask")
        $arrayCollectionOutput.Add("modify network_objects $Name color `"$Color`"")
        $arrayCollectionOutput.Add("modify network_objects $Name comments `"$Comments`"")
        #$arrayCollectionOutput.Add("update network_objects $Name")
        $arrayCollectionOutput.Add("addelement network_objects $Group `'`' network_objects:$Name")
        #$arrayCollectionOutput.Add("update network_objects $Group")
    }
	
    function createHostObject ([String] $Name, [String] $Color, [String] $Comments, [String] $IP, [String] $Group) {
        # Output code to create a host object 
        $arrayCollectionOutput.Add("create host_plain $Name")
        $arrayCollectionOutput.Add("modify network_objects $Name ipaddr $IP")
        $arrayCollectionOutput.Add("modify network_objects $Name color `"$Color`"")
        $arrayCollectionOutput.Add("modify network_objects $Name comments `"$Comments`"")
        #$arrayCollectionOutput.Add("update network_objects $Name")
        $arrayCollectionOutput.Add("addelement network_objects $Group `'`' network_objects:$Name")
        #$arrayCollectionOutput.Add("update network_objects $Group")
    }
	
    function createGroupObject ([String] $Name, [String] $Color, [String] $Comments) {
        # Output code to create a group object 
        $arrayCollectionOutput.Add("create network_object_group $Name")
        $arrayCollectionOutput.Add("modify network_objects $Name color `"$Color`"")
        #$arrayCollectionOutput.Add("update network_objects $Name")
    }
	
	
    if ($Firewall.length -gt 0) {
        # Check if we'll be comparing the our items against the current firewall configuration.
        # Make the credential parameter required.
        if ($Credential.UserName.Length -gt 0) { 
            $boolShouldContinue = $true
            $boolCheckFirewall = $true
            #If ($boolDebug -eq $true) {Write-Host "Firewall is set to $Firewall"}
        }
        else {
            # $boolShouldContinue = $false
        }
    }
	
    if ($boolShouldContinue = $true) {
        if ($boolCheckFirewall -eq $true) {
            # Get the list of objects from the firewall 
            $ArrayCurrentFirewallObjects = Export-CheckPointNetworkConfig -Credential $Credential -Firewall $Firewall
            #If ($boolDebug -eq $true) {Write-Host "Boolean value for checking firewall is True"}
        }
		
        $objImportFile = Import-CSV $InputFile -Encoding ascii
        # Import the CSV file for getting the data
        #If ($boolDebug -eq $true) {Write-Host "Imported the CSV file"}
		
        foreach ($line in $objImportFile) {
            # Loop through the lines in the CSV, and create the output collection
            # Variables
            $strObjectName = $($line.Name).Trim()
            $strObjectIP = $($line.IP).Trim()
            $strObjectColor = $($line.Color).Trim()
            # dodgerblue3, olive drab, orchid, aquamarine, black
            $strObjectGroup = $($line.Group).Trim()
            $strObjectComment = $($line.Comments).Trim()
            $strObjectType = $($line.Type).Trim()
            # host_plain, network, network_object_group
            $strObjectMask = $($line.Netmask).Trim()
 
		
            # Figure out what kind of object we're working with and build the list.
            switch ($strObjectType) {
                host_plain {
                    # Run the createHostObject function.
                    createHostObject -Name $strObjectName -Color $strObjectColor -Comments $strObjectComment -IP $strObjectIP -Group $strObjectGroup | Out-Null
                    break
                }  
                network {
                    # Run the createNetworkObject function 
                    createNetworkObject -Name $strObjectName -Color $strObjectColor -Comments $strObjectComment -IP $strObjectIP -Netmask $strObjectMask -Group $strObjectGroup | Out-Null
                    break
                } 
                network_object_group {
                    # Run the createGroupObject function 
                    createGroupObject -Name $strObjectName -Color $strObjectColor -Comments $strObjectComment | Out-Null
                    break
                }
            }
			
			
        } #If ($boolDebug -eq $true) {Write-Host "Finished creating all objects"}
		
        # Clean up the list, if we need to compare to existing firewall output. 
        if ($boolCheckFirewall -eq $true) {
            # Compare and order objects. Create all groups first if they don't exist.
			
            # Build the list of groups from our array. 
            $arrayGroupNames = $arrayCollectionOutput.Group | Sort-Object -Unique
            #If ($boolDebug -eq $true) {Write-Host "**** Unique group names ****"$arrayGroupNames}
				
            $arrayHostNames = $arrayCollectionOutput | Where-Object { $_.Type -eq 'plain_host' } | ForEach-Object { $_.Name }
            $arrayNetworkNames = $arrayCollectionOutput | Where-Object { $_.Type -eq 'network' } | ForEach-Object { $_.Name }
			
            # Build an array for cleaned list of items to create. 
            [System.Collections.ArrayList] $arrayCleanedOutput = $arrayCollectionOutput
            # This will be our cleaned output file. 
            [System.Collections.ArrayList] $arrayGroupsToCreate = @()
			
            # Remove any host or network objects that were found in the firewall output.
            foreach ($line in $ArrayCurrentFirewallObjects) { 
                foreach ($record in $($arrayCleanedOutput | Select-String "$line")) {
                    $arrayCleanedOutput.Remove($record.ToString())
					
                    #If ($boolDebug -eq $true) {Write-Host "Removing: $record"}
                }
            }
			
            foreach ($Group in $arrayGroupNames) {
                # Check if the groups already exist 
                # Add to the collection array if missing from firewall array.
                if ($ArrayCurrentFirewallObjects.Contains("$Group") -eq $false) { $arrayGroupsToCreate.Add("$Group") }
            }

            if ($arrayGroupsToCreate.Count -gt 0) {
                # Do we have any groups to create?
                foreach ($Group in $arrayGroupsToCreate) {
                    # Lookup the object in the array, and pump this out to the proper function
                    $objTempGroup = $objImportFile | Where-Object { $_.Group -eq "$Group" } | Select-Object -First 1
                    $arrayCleanedOutput.Add("create network_object_group $Group")
                    $arrayCleanedOutput.Add("modify network_objects $Group color `"$($objTempGroup.Color)`"")
                    #$arrayCollectionOutput.Add("update network_objects $Group")
                }
            }
        }
		
        # Add the update command to the end of the script file. 
        $arrayCollectionOutput.Add("update_all")
		
        # Create the output file if it doesn't exist. 
        Invoke-Touch -Path $OutputFile | Out-Null
		
        if ($boolCheckFirewall -eq $true -and $arrayCleanedOutput.Count -gt 0) {
            # Output the cleaned file
            $CleanOutFile = "Cleaned-$(Get-ChildItem $OutputFile | ForEach-Object{$_.Name})"
            Invoke-Touch -Path $CleanOutFile | Out-Null
            $CleanOutFile = Get-ChildItem $CleanOutFile | ForEach-Object { $_.FullName }
			
            # Write the output to the cleaned file 
            [System.IO.File]::WriteAllLines($CleanOutFile, ($arrayCleanedOutput))
			
            ConvertFrom-DosToUnix -FilePath $CleanOutFile
            # Convert to Unix line terminators. 
        }
		
        # Get the full name of the file 
        $Outputfile = Get-ChildItem $Outputfile | ForEach-Object { $_.FullName }
        # System.IO.File works from your home directory. 
		
        # Output the collection to the output file 
        [System.IO.File]::WriteAllLines($OutputFile, ($arrayCollectionOutput))

        # Convert the file to Unix format, as we'll be sending this file to the firewall for processing. 
        ConvertFrom-DosToUnix -FilePath $OutputFile
		
        Write-Host "Your dbedit import has been created. Copy the file or its contents to your mgmt server and execute the following command"
        Write-Host " dbedit -continue_updating -f file_name -s localhost -u admin_account , you will then be prompted for the password. Enter it and your done"
    }
    else {
        Write-Host "Missing parameter. Check ur work, son!"
    }
}


Function Import-CheckPointBulkObject { 
    # Checkpoint Firewall object import tool
    # Import a network objects file into the CheckPoint database. Provisioning just got easy son!!!

    Param 
    (
        [Parameter(Mandatory = $True, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential, 
        
        [Parameter(Mandatory = $True, HelpMessage = 'Checkpoint Firewall',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall, 
        
        [Parameter(Mandatory = $True, HelpMessage = 'Input file')]
        [String] $InputFile,
        
        [String] $RemotePath,
        
        [Int] $Port = 22
    )
	
    # Variables:
    if ($RemotePath.Length -lt 1) { $RemotePath = "/home/$($Credential.UserName.ToString())" }
    $strFileName = Get-ChildItem $InputFile | ForEach-Object { $_.Name }
    $strDBeditBatchCommand = "dbedit -local -f $($RemotePath + '/' + $strFileName) -continue_updating"
	
    # Copy our import file to the firewall 
    Set-ScpFile -Computername $Firewall -Credential $Credential -Port $Port -LocalFile $InputFile -RemotePath $RemotePath
	
    # Create an SSH session to the firewall 
    $objSession = New-SSHSession -Credential $Credential -ComputerName $Firewall
	
    # Run the script file via dbedit on the firewall 
    $retVal = Invoke-SSHCommand -SessionId $objSession.SessionId -Command "$strDBeditBatchCommand"
    
    If ($retVal.ExitStatus -ne 0) {
        $retVal
    }
    Else {
        $retVal.ExitStatus
    }
	
    # Close the connection to the firewall 
    $null = Remove-SSHSession -SessionId $objSession.SessionId
}


#endregion


#region Network objects


Function Export-CheckPointNetworkConfig { 
    # used to get a list of all objects from the network_objects table via dbedit.
    # TODO: 
    # Check if requirements are present
    # Stop using a file. redirect variable data into the -f argument. 

    # REQUIREMENTS:	
    # Requires Posh-SSH modules to be loaded 

    # Description:
    # This script checks for Checkpoint reserved words, and duplicates...
    # There's no need to maintain more than one file. Just add to the master sheet of objects, and run the script. 
    
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $True, HelpMessage = 'Checkpoint Firewall',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall,
        
        [Parameter(Mandatory = $True, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential,
        
        [Switch] $ReturnPsObject,
        
        [Parameter(DontShow)]
        [String] $Filter,
        
        [Parameter(DontShow)]
        [ValidateSet('network_objects', 'services')]
        [String] $Table = 'network_objects'
    )
	
    # Variables
    
    
    $strCommandFileName = "getObjects.txt"
    $strDBeditPrintCommand = "printxml $Table"
    $strSshDumpCommand = "dbedit -local -f $strCommandFileName"
	
    # Get the current firewall dump
	
    # Connect to the firewall via SSH session 
    $objSession = New-SSHSession -Credential $Credential -ComputerName $Firewall
	
    # Invoke a command within the created session and create a command file 
    Invoke-SSHCommand -SessionId $objSession.SessionId -Command ("echo `'$strDBeditPrintCommand`' `> $strCommandFileName") | Out-Null
	
    # Invoke a command to dump all the network_objects to an array variable.
    
    # Checkpoint doesn't know how to do XML, so have to fix...
    [xml] $objFirewallDump = '<objects>' + "`n" + $(Invoke-SSHCommand -SessionId $objSession.SessionId -Command "$strSshDumpCommand" | 
        ForEach-Object { $_.output }) + "`n" + '</objects>'
	
    If ($ReturnPsObject) {
        $bucket = @()
        
        [String] $strEntryElement = $null
        
        If ($Table -eq 'network_objects') { $strEntryElement = 'network_objects_object' }
        If ($Table -eq 'services') { $strEntryElement = 'services_object' }
        
        If ($Filter) {
            $objSearch = ($objFirewallDump | Select-Xml -XPath "(/objects/$strEntryElement[contains(text(), '$Filter')])").Node
            #($objFirewallDump | Select-Xml -XPath "//network_objects_object[text()='$Filter']").Node
        }
        Else {
            $objSearch = $objFirewallDump.objects.$strEntryElement
        }
        
        Foreach ($obj in $objSearch) {
            $props = $obj | Get-Member -MemberType Property
            
            $objBuilder = New-Object -TypeName PSObject
            $objBuilder | Add-Member -MemberType NoteProperty -Name 'Name' -Value $obj.'#text'.Trim()
            
            Foreach ($prop in $props) {
                If (($obj.$($prop.Name) | Get-Member -MemberType Property | ForEach-Object Name) -eq '#cdata-section') {
                    $strValue = $obj.$($prop.Name).'#cdata-section'.Trim()
                }
                Else {
                    $strValue = $obj.$($prop.Name)
                }
                
                $objBuilder | Add-Member -MemberType NoteProperty -Name "$($prop.Name)" -Value $strValue
            }
            
            $bucket += $objBuilder
        }
        
        $bucket
    }
    Else {
        $objFirewallDump
    }
    
    # Clean up the SSH session 
    $null = Remove-SSHSession -SessionId $objSession.SessionId
}


Function Get-CheckPointNetworkObject {
    Param
    (
        [Parameter(Mandatory = $True, Position = 0, HelpMessage = 'Name of network object',
            ValueFromPipelineByPropertyName = $True, ValueFromPipeline = $True)]
        [String[]] $Name,
        
        [Parameter(Mandatory = $True, HelpMessage = 'Checkpoint Firewall',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall,
        
        [Parameter(Mandatory = $True, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential
    )
    
    Process {
        Foreach ($obj in $Name) {
            $Config = Export-CheckPointNetworkConfig -Firewall $Firewall -Credential $Credential -ReturnPsObject -Filter $obj
    
    
            $Config
        }
    }
}


Function New-CheckPointNetworkObject {
 
    [CmdLetBinding()]
    Param 
    (
        [Parameter(Mandatory = $True, Position = 0, HelpMessage = 'Name of network object',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Name, 
        
        [Parameter(Mandatory = $True, Position = 1, HelpMessage = 'Subnet address',
            ValueFromPipelineByPropertyName = $True)]
        [Alias('ipaddr', 'IPv4Address', 'IPAddress')]
        [IPAddress] $IP, 
        
        [Parameter(Mandatory = $True, Position = 2, HelpMessage = 'Netmask for the subnet',
            ValueFromPipelineByPropertyName = $True)]
        [Alias('Mask')]
        [String] $Netmask, 
        
        [Parameter(Position = 3, ValueFromPipelineByPropertyName = $True)]
        [ValidateSet(
            "aquamarine1", "black", "blue", "burlywood4", "dark orchid", "darkseagreen3",
            "deepskyblue1", "dodgerblue3", "gray90", "light coral", "medium orchid",
            "medium slate blue", "olive drab", "orange", "red", "sienna"
        )][String] $Color, 
        
        [Parameter(Position = 4, ValueFromPipelineByPropertyName = $True)]
        [Alias('Comments')]
        [String] $Comment,
        
        [Parameter(Mandatory = $True, Position = 5, HelpMessage = 'Checkpoint Firewall',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall,
        
        [Parameter(Mandatory = $True, Position = 6, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential,
        
        [Int] $Port = 22
    )
    
    Begin {
        If (!((Get-CheckPointActiveShell -Firewall $Firewall -Credential $Credential) -match 'bash')) {
            Write-Error -Message ('Wrong shell for user: {0}' -f $Credential.UserName)
            Return
        }
    }
    
    Process {
        # Create our configuration file

        $guid = [GUID]::NewGuid().guid
        $OutputFile = $env:TEMP + '\' + $guid + '.dbedit'
    
        [System.Collections.ArrayList] $arrayCollectionOutput = @()
    
        $arrayCollectionOutput.Add(('create network {0}' -f $Name)) | Out-Null 
        $arrayCollectionOutput.Add(('modify network_objects {0} ipaddr {1}' -f $Name, $IP)) | Out-Null
        $arrayCollectionOutput.Add(('modify network_objects {0} netmask {1}' -f $Name, $Netmask)) | Out-Null
        $arrayCollectionOutput.Add(('modify network_objects {0} color "{1}"' -f $Name, $Color)) | Out-Null
        $arrayCollectionOutput.Add(('modify network_objects {0} comments "{1}"' -f $Name, $Comment)) | Out-Null
        $arrayCollectionOutput.Add("update_all") | Out-Null
    
        # Create the output file if it doesn't exist. 
        Invoke-Touch -Path $OutputFile -Quiet | Out-Null
		
        # Get the full name of the file 
        $Outputfile = Get-ChildItem -Path $Outputfile | ForEach-Object { $_.FullName }
        
        # Output the collection to the output file 
        [System.IO.File]::WriteAllLines($OutputFile, ($arrayCollectionOutput)) | Out-Null 

        # Convert the file to Unix format, as we'll be sending this file to the firewall for processing. 
        ConvertFrom-DosToUnix -FilePath $OutputFile | Out-Null
    
        Import-CheckPointBulkObject -Credential $Credential -Firewall $Firewall -Port $Port -InputFile $OutputFile 

        $null = Remove-Item -Path $OutputFile -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}


Function New-CheckPointHostObject {
    [CmdLetBinding()]
    Param 
    (
        [Parameter(Mandatory = $True, Position = 0, HelpMessage = 'Name of network object',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Name, 
        
        [Parameter(Mandatory = $True, Position = 1, HelpMessage = 'Subnet address',
            ValueFromPipelineByPropertyName = $True)]
        [Alias('ipaddr', 'IPv4Address', 'IPAddress')]
        [IPAddress] $IP,
        
        [Parameter(Mandatory = $True, Position = 3, HelpMessage = 'Checkpoint Firewall',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall,
        
        [Parameter(Mandatory = $True, Position = 4, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential,
        
        [Int] $Port = 22,
        
        [Parameter(Position = 5, ValueFromPipelineByPropertyName = $True)]
        [ValidateSet(
            "aquamarine1", "black", "blue", "burlywood4", "dark orchid", "darkseagreen3",
            "deepskyblue1", "dodgerblue3", "gray90", "light coral", "medium orchid",
            "medium slate blue", "olive drab", "orange", "red", "sienna"
        )][String] $Color, 
        
        [Parameter(Position = 6, ValueFromPipelineByPropertyName = $True)]
        [Alias('Comments')]
        [String] $Comment
    )
    
    Begin {
        If (!((Get-CheckPointActiveShell -Firewall $Firewall -Credential $Credential) -match 'bash')) {
            Write-Error -Message ('Wrong shell for user: {0}' -f $Credential.UserName)
            Return
        }
    }
    
    Process {
        $guid = [GUID]::NewGuid().guid
        $OutputFile = $env:TEMP + '\' + $guid + '.dbedit'
    
        [System.Collections.ArrayList] $arrayCollectionOutput = @() # Empty array for building temporary output.
    
   
        $arrayCollectionOutput.Add("create host_plain $Name") | Out-Null
        $arrayCollectionOutput.Add("modify network_objects $Name ipaddr $IP") | Out-Null
        $arrayCollectionOutput.Add("modify network_objects $Name color `"$Color`"") | Out-Null
        $arrayCollectionOutput.Add("modify network_objects $Name comments `"$Comment`"") | Out-Null
        
    
        # Check if the object needs automatic NAT configuration 
        
        # Update the object
        $arrayCollectionOutput.Add("update_all") | Out-Null
        
        # Create the output file if it doesn't exist. 
        Invoke-Touch -Path $OutputFile -Quiet | Out-Null
		
        # Get the full name of the file 
        $Outputfile = Get-ChildItem -Path $Outputfile | ForEach-Object { $_.FullName }
        
        # Output the collection to the output file 
        [System.IO.File]::WriteAllLines($OutputFile, ($arrayCollectionOutput)) | Out-Null 

        # Convert the file to Unix format, as we'll be sending this file to the firewall for processing. 
        ConvertFrom-DosToUnix -FilePath $OutputFile | Out-Null
    
        Import-CheckPointBulkObject -Credential $Credential -Firewall $Firewall -Port $Port -InputFile $OutputFile 

        $null = Remove-Item -Path $OutputFile -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}


Function New-CheckPointGroupObject {
    [CmdLetBinding()]
    Param 
    (
        [Parameter(Mandatory = $True, Position = 0, HelpMessage = 'Name of network object',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Name, 
        
        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $True)]
        [ValidateSet(
            "aquamarine1", "black", "blue", "burlywood4", "dark orchid", "darkseagreen3",
            "deepskyblue1", "dodgerblue3", "gray90", "light coral", "medium orchid",
            "medium slate blue", "olive drab", "orange", "red", "sienna"
        )][String] $Color, 
        
        [Parameter(Position = 2, ValueFromPipelineByPropertyName = $True)]
        [Alias('Comments')]
        [String] $Comment,
        
        [Parameter(Mandatory = $True, Position = 3, HelpMessage = 'Checkpoint Firewall',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall,
        
        [Parameter(Mandatory = $True, Position = 4, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential,
        
        [Int] $Port = 22
    )
    
    Begin {
        If (!((Get-CheckPointActiveShell -Firewall $Firewall -Credential $Credential) -match 'bash')) {
            Write-Error -Message ('Wrong shell for user: {0}' -f $Credential.UserName)
            Return
        }
    }
    
    Process {
        # Create our configuration file

        $guid = [GUID]::NewGuid().guid
        $OutputFile = $env:TEMP + '\' + $guid + '.dbedit'
    
        [System.Collections.ArrayList] $arrayCollectionOutput = @()
    
        $arrayCollectionOutput.Add(('create network_object_group {0}' -f $Name)) | Out-Null 
        $arrayCollectionOutput.Add(('modify network_objects {0} color "{1}"' -f $Name, $Color)) | Out-Null
        $arrayCollectionOutput.Add(('modify network_objects {0} comments "{1}"' -f $Name, $Comment)) | Out-Null
        $arrayCollectionOutput.Add("update_all") | Out-Null
    
        # Create the output file if it doesn't exist. 
        Invoke-Touch -Path $OutputFile -Quiet | Out-Null
		
        # Get the full name of the file 
        $Outputfile = Get-ChildItem -Path $Outputfile | ForEach-Object { $_.FullName }
        
        # Output the collection to the output file 
        [System.IO.File]::WriteAllLines($OutputFile, ($arrayCollectionOutput)) | Out-Null 

        # Convert the file to Unix format, as we'll be sending this file to the firewall for processing. 
        ConvertFrom-DosToUnix -FilePath $OutputFile | Out-Null
    
        Import-CheckPointBulkObject -Credential $Credential -Firewall $Firewall -Port $Port -InputFile $OutputFile 

        $null = Remove-Item -Path $OutputFile -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}


Function Get-CheckPointGroupObject {

}


Function Add-CheckPointObjectToGroup {
    Param
    (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $True)]
        [String] $Name,
        
        [Parameter(Mandatory = $True, Position = 1, ValueFromPipelineByPropertyName = $True)]
        [String] $Group,
        
        [Parameter(Mandatory = $True, Position = 2, HelpMessage = 'Checkpoint Firewall',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall,
        
        [Parameter(Mandatory = $True, Position = 3, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential,
        
        [Int] $Port = 22
    )
    
    Process {
        $guid = [GUID]::NewGuid().guid
        $strTempFile = $env:TEMP + '\' + $guid + '.dbedit'
    
        Invoke-Touch -Path $strTempFile -Quiet
    
        $InputFile = Get-ChildItem -Path $strTempFile | ForEach-Object { $_.FullName }
    
        [System.Collections.ArrayList] $arrayCollectionOutput = @()
 
        $arrayCollectionOutput.Add(("addelement network_objects {0} `'`' network_objects:{1}" -f $Group, $Name)) | 
        Out-Null
    
        $arrayCollectionOutput.Add('update_all') | Out-Null 
    
        [System.IO.File]::WriteAllLines($InputFile, ($arrayCollectionOutput)) | Out-Null 

        ConvertFrom-DosToUnix -FilePath $InputFile | Out-Null
    
        Import-CheckPointBulkObject -Credential $Credential -Firewall $Firewall -Port $Port -InputFile $InputFile
    
        $null = Remove-Item -Path $InputFile -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}



Function Search-CheckPointWhereUsed {
    Param
    (
        [String] $Name,
        
        [ValidateSet('network_objects', 'services')]
        [String] $Table = 'network_objects',
        
        [Parameter(Mandatory = $True, HelpMessage = 'Checkpoint Firewall',
            ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall,
        
        [Parameter(Mandatory = $True, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential,
        
        [Int] $Port = 22
    )
    
    # Variables
    $strCommandFileName = "getObjects.txt"
    $strDBeditPrintCommand = "printxml $Table"
    $strSshDumpCommand = "dbedit -local -f $strCommandFileName"
    
    $guid = [GUID]::NewGuid().guid
    $strTempFile = $env:TEMP + '\' + $guid + '.dbedit'
    
    Invoke-Touch -Path $strTempFile -Quiet
    
    $InputFile = Get-ChildItem -Path $strTempFile | ForEach-Object { $_.FullName }
    
    [System.Collections.ArrayList] $arrayCollectionOutput = @()
 
    $arrayCollectionOutput.Add(("addelement network_objects {0} `'`' network_objects:{1}" -f $Group, $Name)) | 
    Out-Null
    
    $arrayCollectionOutput.Add('update_all') | Out-Null 
    
    [System.IO.File]::WriteAllLines($InputFile, ($arrayCollectionOutput)) | Out-Null 

    ConvertFrom-DosToUnix -FilePath $InputFile | Out-Null
    
    Import-CheckPointBulkObject -Credential $Credential -Firewall $Firewall -Port $Port -InputFile $InputFile
    
    $null = Remove-Item -Path $InputFile -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
}


New-Alias -Name New-CPHost -Value New-CheckPointHostObject -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
New-Alias -Name New-CPGroup -Value New-CheckPointGroupObject -ErrorAction SilentlyContinue -WarningAction SilentlyContinue


#endregion


#region DEV

<#
        Function Export-CheckPointFWPolicyConfig
        { 

    
        [CmdLetBinding()]
        Param
        (
        [Parameter(Mandatory = $True, HelpMessage = 'Checkpoint Firewall',
        ValueFromPipelineByPropertyName = $True)]
        [String] $Firewall,
        
        [Parameter(Mandatory = $True, HelpMessage = 'Credentials with bash shell')]
        [PSCredential] [System.Management.Automation.Credential()] $Credential,
        
        [Switch] $ReturnPsObject,
        
        [Parameter(DontShow)]
        [String] $Filter
        )
	
        # Variables
        $strCommandFileName = "getObjects.txt"
        $strDBeditPrintCommand = "printxml fw_policies"
        $strSshDumpCommand = "dbedit -local -f $strCommandFileName"
	
        # Get the current firewall dump
	
        # Connect to the firewall via SSH session 
        $objSession = New-SSHSession -Credential $Credential -ComputerName $Firewall
	
        # Invoke a command within the created session and create a command file 
        Invoke-SSHCommand -SessionId $objSession.SessionId -Command ("echo `'$strDBeditPrintCommand`' `> $strCommandFileName") | Out-Null
	
        # Invoke a command to dump all the network_objects to an array variable.
    
        # Checkpoint doesn't know how to do XML, so have to fix...
        [xml] $objFirewallDump = '<objects>' + "`n" + $(Invoke-SSHCommand -SessionId $objSession.SessionId -Command "$strSshDumpCommand" | 
        ForEach-Object {$_.output}) + "`n" + '</objects>'
	
        If ($ReturnPsObject)
        {
        $bucket = @()
        
        If ($Filter)
        {
        $objSearch = ($objFirewallDump | Select-Xml -XPath "(/objects/network_objects_object[contains(text(), '$Filter')])").Node
        #($objFirewallDump | Select-Xml -XPath "//network_objects_object[text()='$Filter']").Node
        }
        Else
        {
        $objSearch = $objFirewallDump.objects.fw_policies_object
        }
        
        Foreach ($obj in $objSearch)
        {
        $props = $obj | Get-Member -MemberType Property
            
        $objBuilder = New-Object -TypeName PSObject
        $objBuilder | Add-Member -MemberType NoteProperty -Name 'Name' -Value $obj.'#text'.Trim()
            
        Foreach ($prop in $props)
        {
        If (($obj.$($prop.Name) | Get-Member -MemberType Property | ForEach-Object Name) -eq '#cdata-section')
        {
        $strValue = $obj.$($prop.Name).'#cdata-section'.Trim()
        }
        Else
        {
        $strValue = $obj.$($prop.Name)
        }
                
        $objBuilder | Add-Member -MemberType NoteProperty -Name "$($prop.Name)" -Value $strValue
        }
            
        $bucket += $objBuilder
        }
        
        $bucket
        }
        Else
        {
        $objFirewallDump
        }
    
        # Clean up the SSH session 
        $null = Remove-SSHSession -SessionId $objSession.SessionId
        }
#>

#endregion
