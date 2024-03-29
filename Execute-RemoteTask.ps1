<#
.NAME
	Execute-RemoteTask
	
.SYNOPSIS
	Transfers and Executes a script or executable on a remote computer using WMI or Schedtasks

.SYNTAX   
	Usage: powershell .\Execute-RemoteTask.ps1 <TARGET> [-Pickup] [-Task Survey.ps1] [-TaskName psTHS_task] [-Outfile HostSurvey.xml] [-Help]
		[-Pickup]			- Recover output and cleanup remote host
		[-WMI]				- Use WMI Process Call Create. Default=Schtasks
		[-Task] 			- Name of script to execute.  Default=$Task
		[-TaskName]			- Name of scheduled task.  Default=$TaskName
		[-Outfile]			- Name of file to recover from remote host.  Default=$Outfile
		[-Verbose]			- Verbose display
			
.DESCRIPTION 
		Execute-RemoteTask - Remote Script Transport and Execution
		Will deploy any file within .\task folder to remote host and execute it. 
		Will schedule a task and kick it off in the background. Or you can use WMI parameter to do it with WMIC Process Call Create.
		
.RELATED LINKS
	Analyze-psTHS.ps1
	Survey.ps1
	Process-Survey.ps1
	
.NOTES
	Name: 			Execute-RemoteTask.ps1	
	Author:  		Aaron Ferrell
	DateCreated: 	01 Feb 2019
	Version: 		0.1
	 
.EXAMPLE

#>
[CmdletBinding()]
Param(	[Parameter(Position=0, Mandatory=$false, ValueFromPipeline=$True)]
		[string[]]$Targets,
		[switch]$Pickup,
		[switch]$WMI,
		[string]$Task="Default",
		[string]$TaskName="psTHS_task",
		[string]$Outfile="HostSurvey.xml",
		[switch]$Help
		)

BEGIN {
	##################### Variables

	$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
	
	# Setting context for System Tasks (always thinks it's working directory is System32 and forgets where the script is)
	$RemoteTempDir = "C:\Windows\temp"
	
	if ($Task -like "Default") { $Task = "$ScriptPath\task\Survey.ps1" }
	$TaskFileName = $Task.Substring($Task.LastIndexOf("\")+1)

	##################### Initialize Shell
		
	# Colors
	$ForegroundColor = "Green"
	$BackgroundColor = "Black"
	$LabelColor = "Cyan"
	$SunkColor = "DarkGray"
	
	#Setup User Interface
	$UI = (Get-Host).UI.RawUI
	$oldFGColor = $UI.ForegroundColor
	$oldBGColor = $UI.BackgroundColor
	$UI.WindowTitle = "67 CW - Defensive Counter Cyber - Remote Task Execution"
	$b = $UI.BufferSize
	$b.Width = 1500
	$b.Height = 9000
	$UI.BufferSize = $b
	$UI.ForegroundColor = $ForegroundColor
	$UI.BackgroundColor = $BackgroundColor

	
	if (!$PSBoundParameters['Verbose']) { 
		$AdvancedPreference = "Continue"
	} else {
		Write-Verbose "Verbose Output!"
	}
	if (!$PSBoundParameters['Debug']) { 
		#Supress Error
		#$ErrorActionPreference  = "SilentlyContinue"
		$ErrorActionPreference  = "Continue"
		$ErrorView = "CategoryView"
	} else {
		Write-Warning Debugging
		Set-StrictMode -version 2.0
		$ErrorActionPreference  = "continue"
	}

	####################### Display functions:

	function Display_Help {
		$UI.ForegroundColor = $LabelColor
		Write-Host ""
		Write-Host "psTHS - Remote Script Transport and Execution"
		Write-Host "	Will deploy and execute a batch script, PS script, or executable to a remote host." 
		Write-Host "	By default, will chedule a task and kick it off in the background. Or you can use WMI parameter to do it through WMI's Process Call Create."
		Write-Host "	Defauls are set for psTHS's $PSScriptRoot\task\Survey.ps1 and retrieving HostSurvey.xml on pickup"
		Write-Host ""	
		Write-Host "Usage: powershell .\Execute-RemoteTask.ps1 <TARGET> [-Pickup] [-WMI] [-Task Survey.ps1] [-TaskName psTHS_task] [-Outfile HostSurvey.xml] [-Verbose] [-Help]"
		Write-Host "	[-Pickup]		- Recover output and cleanup remote host"
		Write-Host "	[-Task] 		- Name of script to execute.  Default=$Task" 
		Write-Host "	[-WMI]			- Use WMI to execute task instead of remote schtasks"
		Write-Host "	[-TaskName]		- Name of scheduled task, if used.  Default=$TaskName"
		Write-Host "	[-Outfile]		- Name of file to recover from remote host on pickup.  Default=$Outfile"
		Write-Host "	[-Verbose]		- Verbose display" 
		Write-Host "	[-Help]			- Display this helpfile"
		Write-Host ""
		$UI.ForegroundColor = $ForegroundColor
		Exit
	}
	
	####################### Display functions:
	
	function TCPConnect($Target, $port) {
		try {
			$tcp=new-object System.Net.Sockets.TcpClient
			$tcp.connect($Target,$port)
			return $true
		} 
		catch {		
			return $false
		} 
		finally {
			$tcp.close()
		}
	}

	function Execute_Schtask ($Target, $RemotePath, $TaskToRun, $TaskName) {
		$time = (Get-Date).ToString()
		
		# Create remote task & Run task
		try {
			# Setting context for System Tasks (always thinks it's working directory is System32 and forgets where the script is)
			Write-Verbose "Scheduling Task $TaskToRun in $RemotePath under SYSTEM account"
			schtasks /create /s $Target /RU SYSTEM /tn $TaskName /tr $TaskToRun /sc once /st 23:59 /F 2>> $OPDATADIR\log.txt | Out-Null
			if (!($?)) { Throw System.Exception }
			
			Write-Verbose "Running $TaskName"
			schtasks /run /s $Target /tn $TaskName 2>> $OPDATADIR\log.txt | Out-Null
			if ($?) { return "Success" } else { Throw System.Exception }
		} 
		catch {
			Write-Error "Error while running scheduled task on $Target"
			schtasks /delete /s $Target /tn $TaskName /F | Out-Null
			"$target, Error: Could not schedule Task on target" >> $OPDATADIR\log.txt
			Return "Error: Schtask Execution on $Target"
		} 
	}
	
	function Execute_WMITask ($target, $script) {
		Write-Verbose "Executing $script via WMI on $target"
		$time = (Get-Date).ToString()
		
		try {
			if ($script -like "*.ps1") {
				$proc = invoke-wmimethod -computer $target win32_process -name create -argumentlist "powershell.exe -NonInteractive -WindowStyle Hidden -NoProfile -ExecutionPolicy bypass -File $script"
			}
			elseif ($script -like "*.bat") {
				$proc = invoke-wmimethod -computer $target win32_process -name create -argumentlist "cmd /c $script"
			}
			elseif ($script -like "*.exe") {
				$proc = invoke-wmimethod -computer $target win32_process -name create -argumentlist "$script"
			} 
			else {
				return "Error: Bad file Format (must be .ps1, .bat, or .exe)"
			}
			if ($?) { return $proc.ProcessID } else { throw $error[0].Exception } 
		} catch [System.UnauthorizedAccessException] {
			# Access is denied
			"$time, $target, Error: $_.Exception.Message" >> $OPDATADIR\log.txt
			return "Error: Access Denied to $Target"
		} catch [System.Runtime.InteropServices.COMException] {
			# The RPC server is unavailable
			"$time, $target, Error: $_.Exception.Message" >> $OPDATADIR\log.txt
			return "Error: The RPC server is unavailable on $Target"
		} catch [system.exception] {
			# General Exception
			"$time, $target, Error: $_.Exception.Message" >> $OPDATADIR\log.txt
			return "Error: General WMI Failure on $Target"
		}

		# To use the -EncodedCommand parameter:
		#$command = 'dir "c:\program files" '
		#$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
		#$encodedCommand = [Convert]::ToBase64String($bytes)
		#powershell.exe -encodedCommand $encodedCommand

	}


	# MAIN #################	
	if ($help) { Display_Help }
	
	$date = get-date -uformat "%Y%m%d"
	
	# Error Checking
	
	if ( ($Task -notlike "*.exe") -AND ($Task -notlike "*.ps1") -AND ($Task -notlike "*.bat") ) {
		Write-Error "$Task is not a properly formatted executable or script (ie. exe, ps1, bat)"
		exit
	}
	if (-not (Test-Path $Task) ) { 
		Write-Error "$Task does not exist"
		exit		
	}
	
	$n = 0
}

PROCESS {
	foreach ($target in $Targets) {
		$n += 1
		
		$RemotePath = "\\$Target\C$\Windows\temp"
		$OPDATADIR = "$ScriptPath\OPDATA\$date\$Target" 
		$time = (Get-Date).ToString()

		#  Making local output directory
		if (!(Test-Path $OPDATADIR)) { mkdir $OPDATADIR | out-null }
		
		if ($Pickup) {
			"$time, $target, Picking up $Outfile on $target" >> $OPDATADIR\log.txt
			Write-Host "($n): Picking up $Outfile on $target"			
		} else {
			if ($WMI) {
				"$time, $target, Executing $Task on $target" >> $OPDATADIR\log.txt
				Write-Host "($n): Executing $Task on $target" 
			} else {
				"$time, $target, Scheduling $Task on $target" >> $OPDATADIR\log.txt
				Write-Host "($n): Scheduling $Task on $target" 		
			}
		}
	
		# Test connectivity
		if (!(TCPConnect $target 445)) {
			if (!(TCPConnect $target 139)) {
				# Write-Error "Fail: System did not respond on port 445 or 139"
				Write-Verbose "($n): $target connectivity test failed (TCP port 445 or 139)!" 
				"$time, $target, Error: System did not respond on port 445 or 139" >> $OPDATADIR\log.txt
				continue
			}
		}
		
		############## Deploy and Execute #############
		if (!$Pickup) {	
			# Not a pickup task, Sending scripts to target
			Write-Verbose  "Deploying psTHS to $Target"
			
			try {

				Write-Verbose "Copying $Task to: $RemotePath"
				copy -Path $Task -Destination $RemotePath -container -Force -ea stop | Out-Null

			} catch [System.UnauthorizedAccessException] {
				# Access Denied (credential issue or not on same domain)
				Write-Verbose "$_.Exception.Message"
				"$time, $target, Error: Access Denied" >> $OPDATADIR\log.txt
				return "($n):Error: Access Denied"
			} catch {
				# Most others are connection issues of various shapes and sizes (system not up, firewall block on port 139/445, etc)
				Write-Verbose "$_.Exception.Message"
				"$time, $target, Error: $_.Exception.Message" >> $OPDATADIR\log.txt
				return "($n):Error: Connection Error"
			}
			
			
			# Task Execution
			
			# Method: WMI
			if ($WMI) {
			
				$results = Execute_WMITask $Target $RemoteTempDir\$TaskFileName
				Write-Verbose "Process Executed on PID $results"
				
			# Method: Scheduled Task
			} else {
				
				Write-Verbose "Executing $RemoteTempDir\$TaskFileName via remote scheduled task"
				$TaskToRun = "Powershell.exe -ExecutionPolicy bypass -NoProfile -File $RemoteTempDir\$TaskFileName" 
				$results = Execute_SchTask $Target $RemotePath $TaskToRun $TaskName
				
				# Log success/fail
				Write-Verbose "Task Scheduled and executed with result: $results"
				if ($PSBoundParameters['verbose']) { Start-Sleep 0.5; schtasks /query /s $Target /tn $TaskName /v }
				write-verbose "to query whether done type: schtasks /query /s $Target /tn $TaskName /v"
			
			} 
 			if ($results -like "Error:*") { return $results }
		
		############ Pickup #############
		} else {
			Write-Verbose  "Recovering psTHS output and cleaning up $Target"
			# Picking up Survey Output
			Write-Verbose "Copying $RemotePath\$Outfile to: $OPDATADIR\"
			
			copy $RemotePath\$Outfile -Destination $OPDATADIR -container -Force | Out-Null
			
			# Cleanup Schtask
			# Delete Scheduled Task
			if ( (gc $OPDATADIR\log.txt) -match "Scheduling" ) {
				Write-Verbose "Deleting $TaskName"
				try {
					schtasks /delete /s $Target /tn $TaskName /F | Out-Null
					if (!($?)) { Throw System.Exception }
				} catch {	
					Write-verbose "Error: Could not delete task - it may not exist"
					"$time, $target, Error: Could not delete task - it may not exist" >> $OPDATADIR\log.txt
				}
			}
			
			# Cleanup remote host
			try {
				Write-Verbose "Deleting $RemotePath\$TaskFileName and $RemotePath\$Outfile"
				del $RemotePath\$TaskFileName -Force -ea 0 | Out-Null
				del $RemotePath\$Outfile -ea 0 | Out-Null
			} catch [System.Management.Automation.ItemNotFoundException] {
				Write-verbose "Error: $_.Exception.Message"
				"$time, $target, Error: $_.Exception.Message" >> $OPDATADIR\log.txt
				return "($n): Error: Clean up unsuccessful"
			} catch {
				Write-verbose "Error: $_.Exception.Message"
				"$time, $target, Error: $_.Exception.Message" >> $OPDATADIR\log.txt
				return "($n): Error: Clean up unsuccessful"			
			}
		}
	}
}

END {
	Write-Verbose "Remote Transport and execution complete."
}
