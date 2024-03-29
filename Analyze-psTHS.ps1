<#
.NAME	
	psTHS - System Integrity Survey Analyzer
	Analyze-psTHS.ps1
	
.SYNOPSIS 
	Used to analyze output from the psTHS - Threat Hunter Survey (survey.ps1)  
	
.DESCRIPTION 
	Companion script to psTHS (Survey.ps1). Analyze-psTHS.ps1 will process and display data from the $SurveyFileName output from the psTHS. 
	Analyze-psTHS will compare data recieved from a host against white/black lists as well as query a local copy of the NIST database.  
	
	All data will be displayed with logic and coloring to be able to quickly decide if a system is clean or not. 

	Scope: Medium ( < 1000 hosts )
	Intensity: Semi-Intense
	The psTHS - Threat Hunter Survey is a Powershell implimented collection of scripts meant for remote interactive operators 
	to interrogate a remote windows host for information and pass it back for processing and analysis.  Survey is intended 
	to rapidly determine "if" a windows host or group of hosts has been compromised/implanted but not necessarily how or 
	by what.  

	Output for a host is in XML format and is called a "HostObject".  A HostObject is an object that contains all the
	collected data for a host.  The Survey Analyzer can process multiple HostObjects into a "BaseObject" XML file which
	contains selected datapoints and statistics for an entire enclave or collection of surveyed hosts.

	psTHS is a comprehensive host scanner for systems containing the .NET framework and Powershell v2+ (ie. Vista+/Win2k8+)
	Due to restrictions for many of the functions, execution is performed on the remote host directly via first transfering
	the script to it (ie. remote host execution). Every effort has been made in the execution/transport code to ensure a 
	clean exit.

	Remote Execution Methodology:
	psTHS Survey is used to survey all enclave hosts in (semi-)parallel fashion using scheduled tasks and coming back to collect
	the output after (fire and forget execution).  Script generally runs in around 2-3 mins on a workstation.  For servers,
	all scheduled tasks are scheduled with below-normal priority by default so script can take up to 20 mins on a busy
	server.  To be safe, wait 20 minutes before running any "Pickup" script.

.NOTES   
	Name: 			Analyze-psTHS.ps1	
	Author:  		Aaron Ferrell
	DateCreated: 	01 Feb 2019
	Version: 		0.1
		
.EXAMPLE   
		
	Usage:
    	Display HostObject: 		.\Analyze-psTHS.ps1 .\OPDATA\Hostname\HostSurvey.xml
    	Display/Build BaseObject: 	.\Analyze-psTHS.ps1 -StartOp .\OPDATA
	
			[-Verbose]					- Verbose/Debug messages
			[-StartOp <OPDATAFolder>]	- Process all OPDATA and build BaseObject - Displays BaseObject.  Works with all options except baseline
			[-Reprocess]				- Reprocess an already processed $SurveyFileName file (in case of updated white/black lists or NIST Database)
			[-Baseline] 				- Create whitelists using specified HostObject output as a baseline
			[-NoNIST] 					- Do not import NIST Database (saves processing time, but messy output)
			[-Advanced] 				- Display Filter: Displays verbose Survey output
			[-FilterGreen] 				- Display Filter: Removes whitelisted items

#>
[CmdletBinding()]  
Param(	[Parameter(Position=0, Mandatory=$false)]
		[string]$SurveyPath,
		[string]$StartOp,
		[switch]$Help,
		[string]$OPDATAFolder = "$pwd\OPDATA",
		[switch]$Baseline,
		[switch]$Reprocess,
		[switch]$NoNIST,
		[switch]$Advanced,
		[switch]$FilterGreen,
		[switch]$Threaded
		)

function Display_Help {
	$UI.ForegroundColor = $LabelColor
	Write-Host ""
	Write-Host "	psTHS - Powershell Threat Hunter Survey"
	Write-Host ""
	Write-Host "		- Used to analyze output from the psTHS (survey.ps1)"
	Write-Host ""	
	Write-Host "	Usage:"
    Write-Host "		Display HostObject: 		.\Analyze-psTHS.ps1 .\OPDATA\52MPLSW3-114321\$SurveyFileName"
    Write-Host "		Display/build BaseObject: 	.\Analyze-psTHS.ps1 -StartOp .\OPDATA"	
	Write-Host ""
	Write-Host "		[-Verbose]			- Verbose/Debug messages" 
	Write-Host "		[-StartOp <OPDATAFolder>]	- Process all OPDATA and build BaseObject - Displays BaseObject.  Works with all options except baseline"
	Write-Host "		[-Reprocess]			- Reprocess an already processed $SurveyFileName file (in case of updated white/black lists or NIST Database)"
	Write-Host "		[-Baseline] 			- Create whitelists using specified HostObject output as a baseline" 
	Write-Host "		[-NoNIST] 			- Do not import NIST Database (saves processing time, but messy output)" 
	Write-Host "		[-Advanced] 			- Display Filter: Displays verbose Survey output"
	Write-Host "		[-FilterGreen] 			- Display Filter: Removes whitelisted items" 	
	Write-Host ""
	$UI.ForegroundColor = $ForegroundColor
    Exit
}


#region ########### Variables ###########:
	$List = @(
		"Name"
		"PathName"
		"Hash"
		"DateAdded"
	)	

	$NullHash = "D41D8CD98F00B204E9800998ECF8427E"
	$SurveyFileName = "HostSurvey.xml"
	$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
	$version = 2.0
	$logfile = "$ScriptPath\LOG_psTHSAnalyzer.txt"
	$datestamp = get-date -uformat "%D"
	
#endregion

#region ########### Initialize Shell ###########:
	
	# Colors
	$ForegroundColor = "Green"
	$BackgroundColor = "Black"
	$BadBackground = "DarkMagenta"
	$LabelColor = "Cyan"
	$GoodColor = "DarkGreen"
	$NISTColor = "DarkGreen"
	$NeutralColor = "Grey"
	$UnknownColor = "Yellow"
	$SunkColor = "DarkGray"
	$OkColor = "DarkCyan" # White
	$SemiBadColor = "Magenta"
	$BadColor = "Red"

	#Setup User Interface
	$UI = (Get-Host).UI.RawUI
	$oldFGColor = $UI.ForegroundColor
	$oldBGColor = $UI.BackgroundColor
	$UI.WindowTitle = "psTHS Survey Analyzer"
	$b = $UI.BufferSize
	$b.Width = 1500
	$b.Height = 9000
	$UI.BufferSize = $b
	$UI.ForegroundColor = $ForegroundColor
	$UI.BackgroundColor = $BackgroundColor
	
	# Manage Error output
	if (!$PSBoundParameters['verbose']) { 
		$AdvancedPreference = "Continue"
	} 
	if (!$PSBoundParameters['debug']) { 
		# Supress Error
		$ErrorActionPreference  = "SilentlyContinue"
        Set-StrictMode -off
	} else {
		Set-StrictMode -version 2.0
		$ErrorActionPreference  = "Continue"
	}
	
	# Set-StrictMode -version 2.0
	# $ErrorActionPreference  = "Continue"	

#endregion
	
#region ########### Display functions ###########:

	function generate_OpNotes ($BaseObject, $Uniques)  {
		" " | Out-File -Encoding "UTF8" $StartOp\OpNotes.txt -Force
		"Op: {0}" -f $BaseObject.Opfolder | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Date: {0}" -f $BaseObject.Date | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Hosts: {0}" -f $BaseObject.Hosts.count | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"-----------------------------------------------------------------------------" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Processes:	 	{0}	 Unique Processes: 	{1}" -f $BaseObject.ProcessList.count, $Uniques.ProcessList_Unique.count | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Modules: 	 	{0}	 Unique Modules: 	{1}" -f $BaseObject.ModuleList.count, $Uniques.ModuleList_Unique.count | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Services: 	 	{0}	 Unique Services: 	{1}" -f $BaseObject.ServiceList.count, $Uniques.ServiceList_Unique.count | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Drivers: 	 	{0}	 Unique Drivers: 	{1}" -f $BaseObject.DriverList.count, $Uniques.DriverList_Unique.count | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Accounts: 	 	{0}	 Unique Accounts: 	{1}" -f $BaseObject.Accounts.count, $Uniques.Accounts_Unique.count | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Autoruns:		{0}	 Unique Autoruns:	{1}" -f $BaseObject.Autoruns.count, $Uniques.Autoruns_Unique.count | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		" " | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Cnx to Hot IPs:	{0}" -f $BaseObject.Connections.count | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Arma Malfind:  	{0}" -f $BaseObject.ArmaMalfind.count | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		" " | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt	

		"=========================== OP Notes ========================================" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		" " | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		" " | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		" " | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt	
		
		"=========================== OP Data =========================================" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		"Note: OpData.csv has been exported for checking against a software reputation hash database" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		" " | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt	
		"=============================================================================" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		" " | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt	

		$AutoEXE = @()
		$AutoDLL = @()
		$AutoSYS = @()
		
		$date = get-date -format d
		
		# Unknown Autostarts
		_ConvertTo_CsvExportList $Uniques.Autostarts_Unique | foreach {
			if ($_.PathName -like "*.dll") {
				$AutoDLL += $_
			} elseif ($_.PathName -like "*.sys") {
				$AutoSYS += $_
			} else {
				$AutoEXE += $_
			}
		}
		
		# Unknown Autoruns
		_ConvertTo_CsvExportList $Uniques.Autoruns_Unique | foreach {
			if ($_.PathName -like "*.dll") {
				$AutoDLL += $_
			} elseif ($_.PathName -like "*.sys") {
				$AutoSYS += $_
			} else {
				$AutoEXE += $_
			}
		}
		
		# Unknown Services
		_ConvertTo_CsvExportList $Uniques.ServiceList_Unique | foreach {
			if ($_.PathName -like "*.dll") {
				$AutoDLL += $_
			} elseif ($_.PathName -like "*.sys") {
				$AutoSYS += $_
			} else {
				$AutoEXE += $_
			}
		}

		
		"Unknown Processes" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt	
		"=============================================================================" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		_ConvertTo_CsvExportList $Uniques.ProcessList_Unique | foreach {
			$AutoEXE += $_
		}	
		$AutoEXE | Sort-Object Hash -unique | foreach {
			"{0}`t{1}`t{2}" -f $_.Name, $_.PathName, $_.Hash | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		}
		" " | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt	

		"Unknown Modules" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt	
		"=============================================================================" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		_ConvertTo_CsvExportList $Uniques.ModuleList_Unique | foreach {
			$AutoDLL += $_
		}
		$AutoDLL | Sort-Object Hash -unique | foreach {
			"{0}`t{1}`t{2}" -f $_.Name, $_.PathName, $_.Hash | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		}
		" " | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt	
		
		"Unknown Drivers" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt		
		"=============================================================================" | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		_ConvertTo_CsvExportList $Uniques.DriverList_Unique | foreach {
			$AutoSYS += $_
		}
		$AutoSYS | Sort-Object Hash -unique | foreach {
			"{0}`t{1}`t{2}" -f $_.Name, $_.PathName, $_.Hash | Out-File -Encoding "UTF8" -append $StartOp\OpNotes.txt
		}

		
		# Export to CSV for checking against hash database
		$AutoEXE + $AutoDLL + $AutoSYS | Sort-Object Hash -unique | Select-Object $List | Export-CSV -Encoding "UTF8" -append $StartOp\OpData.csv

	}

	function Display_BaseObject ($BaseObject, $Uniques)  {
		#region Display Op Stats
		Write-Host -ForegroundColor $LabelColor  =============================================================================
		Write-Host -ForegroundColor $LabelColor  =============================================================================
		Write-Host -ForegroundColor $LabelColor  =============================================================================
		Write-Host " "
		# Display stats collected
		$UI.ForegroundColor = $ForegroundColor
		Write-Host Op: $BaseObject.Opfolder
		Write-Host Date: $BaseObject.Date
		Write-Host Hosts: $BaseObject.Hosts.count 
		Write-Host -----------------------------------------------------------------------------
		"Processes:	 	{0}	 Unique Processes: 	{1}" -f $BaseObject.ProcessList.count, $Uniques.ProcessList_Unique.count
		"Modules: 	 	{0}	 Unique Modules: 	{1}" -f $BaseObject.ModuleList.count, $Uniques.ModuleList_Unique.count
		"Services: 	 	{0}	 Unique Services: 	{1}" -f $BaseObject.ServiceList.count, $Uniques.ServiceList_Unique.count
		"Drivers: 	 	{0}	 Unique Drivers: 	{1}" -f $BaseObject.DriverList.count, $Uniques.DriverList_Unique.count
		"Accounts: 	 	{0}	 Unique Accounts: 	{1}" -f $BaseObject.Accounts.count, $Uniques.Accounts_Unique.count
		"Autoruns:		{0}	 Unique Autoruns:	{1}" -f $BaseObject.Autoruns.count, $Uniques.Autoruns_Unique.count
		write-host ""
		"Cnx to Hot IPs:	{0}" -f $BaseObject.Connections.count
		"Arma Malfind:  	{0}" -f $BaseObject.ArmaMalfind.count
		$UI.ForegroundColor = $ForegroundColor
		Write-Host -ForegroundColor $LabelColor  =============================================================================
		Write-Host -ForegroundColor $LabelColor  =============================================================================
		Write-Host " "
		_Wait
		#endregion
		
		#region Display Processes
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Processes ================================================

		#Format Display
		$format_table = "{0,-18} {1,5} {2,-40} {3,-100} {4,20} {5,-13} {6,-33}"
		$format_table -f "Sample Host", "n", "Name", "PathName", "Signature", "Check", "Hash"
		
		#Format Table
		$cformat = 	@{Expression={$_.Host}			;Label="Host"		;width=18	;alignment="left"},
					@{Expression={$BaseObject.Stats.Process_stats[$_.Hash]}	;Label="n"			;width=5	;alignment="right"},
					@{Expression={$_.Name}			;Label="Name"		;width=40	;alignment="left"},
					@{Expression={$_.PathName}		;Label="PathName"	;width=100	;alignment="left"},
					@{Expression={$_.Signature}		;Label="Signature"	;width=20	;alignment="right"},
					@{Expression={$_.Check}			;Label="Check"		;width=13	;alignment="left"},
					@{Expression={$_.Hash}			;Label="Hash"		;width=33	;alignment="left"}

						
		foreach ($item in ($Uniques.ProcessList_Unique | Sort-Object PathName)) {
			$linecolor = _Color_Display_Check2 $item
			
			# Print formatted line with proper colors
			Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
				($item | format-table $cformat -hidetableheaders | out-string).Trim()
		}
		_Wait
		#endregion
		
		#region Display Modules
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Displaying Loaded DLLs =============================================

		#Format Display
		$format_table = "{0,-18} {1,5} {2,-40} {3,-100} {4,20} {5,-13} {6,-33}"
		$format_table -f  "Sample Host", "n", "ModuleName", "PathName", "Signature", "Check", "Hash"
		
		#Format Table
		$cformat = 	@{Expression={$_.Host}			;Label="Host"		;width=18	;alignment="left"},
					@{Expression={$BaseObject.Stats.Module_stats[$_.Hash]}	;Label="n"			;width=5	;alignment="right"},
					@{Expression={$_.ModuleName}	;Label="ModuleName"	;width=40	;alignment="left"},
					@{Expression={$_.PathName}		;Label="PathName"	;width=100	;alignment="left"},
					@{Expression={$_.Signature}		;Label="Signature"	;width=20	;alignment="right"},
					@{Expression={$_.Check}			;Label="Check"		;width=13	;alignment="left"},
					@{Expression={$_.Hash}			;Label="Hash"		;width=33	;alignment="left"}

		foreach ($item in ($Uniques.ModuleList_Unique | Sort-Object PathName)) {
			$linecolor = _Color_Display_Check2 $item
			
			# Print formatted line with proper colors
			Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
				($item | format-table $cformat -hidetableheaders | out-string).Trim()
		}
		_Wait
		#endregion
		
		#region Display Services
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Services =================================================

		#Format Display
		$format_table = "{0,-18} {1,5} {2,-30} {3,-50} {4,-100} {5,20} {6,-13} {7,-33}"
		$format_table -f "Sample Host", "n", "Name", "Caption", "PathName", "Signature", "Check", "Hash" 
		
		#Format Table
		$cformat = 	@{Expression={$_.Host}			;Label="Host"		;width=18	;alignment="left"},
					@{Expression={$BaseObject.Stats.Service_stats[$_.Hash]}	;Label="n"			;width=5	;alignment="right"},
					@{Expression={$_.Name}			;Label="Name"		;width=30	;alignment="left"},
					@{Expression={$_.Caption}		;Label="Caption"	;width=50	;alignment="left"},
					@{Expression={$_.PathName}		;Label="PathName"	;width=100	;alignment="left"},
					@{Expression={$_.Signature}		;Label="Signature"	;width=20	;alignment="right"},
					@{Expression={$_.Check}			;Label="Check"		;width=13	;alignment="left"},
					@{Expression={$_.Hash}			;Label="Hash"		;width=33	;alignment="left"}
					
		foreach ($item in ($Uniques.ServiceList_Unique | sort-object State, PathName)) {
			$linecolor = _Color_Display_Check2 $item
			
			# Print formatted line with proper colors
			Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
				($item | format-table $cformat -hidetableheaders | out-string).Trim()
		}
		_Wait
		#endregion

		#region Display Drivers
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Drivers ==================================================

		#Format Display
		$format_table = "{0,-18} {1,5} {2,-25} {3,-80} {4,-100} {5,20} {6,-13} {7,-33}"
		$format_table -f "Sample Host", "n", "Name", "PathName", "Description", "Signature", "Check", "Hash"

		#Format Table
		$cformat = 	@{Expression={$_.Host}			;Label="Host"			;width=18	;alignment="left"},
					@{Expression={$BaseObject.Stats.Driver_stats[$_.Hash]}	;Label="n"			;width=5	;alignment="right"},
					@{Expression={$_.Name}			;Label="Name"			;width=25	;alignment="left"},
					@{Expression={$_.PathName}		;Label="PathName"		;width=80	;alignment="left"},
					@{Expression={$_.Description}	;Label="Description"	;width=100	;alignment="left"},
					@{Expression={$_.Signature}		;Label="Signature"		;width=20	;alignment="right"},
					@{Expression={$_.Check}			;Label="Check"			;width=13	;alignment="left"},
					@{Expression={$_.Hash}			;Label="Hash"			;width=33	;alignment="left"}
					
		foreach ($item in ($Uniques.DriverList_Unique | sort-object State, PathName)) {
			$linecolor = _Color_Display_Check2 $item
			
			# Print formatted line with proper colors
			Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
				($item | format-table $cformat -hidetableheaders | out-string).Trim()
		}
		_Wait
		#endregion
		
		#region Display Autoruns
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Registry Autoruns =================================================

		#Format Display
		$format_table = "{0,-18} {1,5} {2,-25} {3,-80} {4,-100} {5,20} {6,-13} {7,-33}"
		$format_table -f "Sample Host", "n", "Name", "PathName", "Key", "Signature", "Check", "Hash"
	
		#Format Table
		$cformat = 	@{Expression={$_.Host}			;Label="Host"			;width=18	;alignment="left"},
					@{Expression={$BaseObject.Stats.Driver_stats[$_.Hash]}	;Label="n"	;width=5	;alignment="right"},
					@{Expression={$_.Name}			;Label="Name"			;width=25	;alignment="left"},
					@{Expression={$_.PathName}		;Label="PathName"		;width=80	;alignment="left"},
					@{Expression={$_.Key}			;Label="Key"			;width=100	;alignment="left"},
					@{Expression={$_.Signature}		;Label="Signature"		;width=20	;alignment="right"},
					@{Expression={$_.Check}			;Label="Check"			;width=13	;alignment="left"},
					@{Expression={$_.Hash}			;Label="Hash"			;width=33	;alignment="left"}	
					
		foreach ($item in ($Uniques.Autoruns_Unique)) {
			$linecolor = _Color_Display_Check2 $item
			
			# Print formatted line with proper colors
			Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
				($item | format-table $cformat -hidetableheaders | out-string).Trim()
		}
		_Wait	
		#endregion
		
		#region Display Connections
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Network Connections ======================================
		# Label any connection from a red process or to/from a Hot IP
			
		#Format Display
		$format_table = "{0,-18} {1,-25} {2,8} {3,17} {4,8} {5,-11} {6,17} {7, 8}"
		$format_table -f "Sample Host", "Name", "Protocol", "Src_Addr", "Src_Port", "State", "Dst_Addr", "Dst_Port"

		#Format Table
		$cformat = 	@{Expression={$_.Host}			;Label="Host"		;width=18	;alignment="left"},
					@{Expression={$_.ProcessName}	;Label="Name"		;width=25	;alignment="left"},
					@{Expression={$_.Protocol}		;Label="Protocol"	;width=8	;alignment="right"},
					@{Expression={$_.Src_Address}	;Label="Src_Addr"	;width=17	;alignment="right"},
					@{Expression={$_.Src_Port}		;Label="Src_Port"	;width=8	;alignment="right"},
					@{Expression={$_.State}			;Label="State"		;width=11	;alignment="left"},
					@{Expression={$_.Dst_Address}	;Label="Dst_Addr"	;width=17	;alignment="right"},
					@{Expression={$_.Dst_Port}		;Label="Dst_Port"	;width=8	;alignment="right"}	
					
		foreach ($item in ($BaseObject.Connections | sort-object Protocol,State)) {
			$linecolor = _Color_Display_Check2 $item
			
			# Print formatted line with proper colors
			Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
				($item | format-table $cformat -hidetableheaders | out-string).Trim()
		}
		_Wait
		#endregion
		
		#region Display Arma	
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Process Memory ===========================================

		Write-Host -ForegroundColor $LabelColor "Detecting process-injected malware"
		$results = $BaseObject.ArmaMalfind | ft Host, Protection, Length, MemorySnip, PathName -auto | out-string
		Write-Host -ForegroundColor $BadColor $results
		_Wait
		#endregion
		
		#region Display Accounts
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Displaying Accounts=================================================

		$Accounts_Unique | ft Host, UserId, Caption, NumberOfLogons, LastLogonUTC, Comment  -auto | more
		#endregion
		
		Write-Host -ForegroundColor $LabelColor "Op Survey Complete!"
	} #END Display_BaseObject

	function Display_HostObject ($HostObject) {
		
		# Begin Survey Analysis
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Starting System Survey =============================================
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host 
		
		#region Displaying Host Information
		Write-Host -ForegroundColor $LabelColor "===================================================================================================="
		Write-Host -ForegroundColor $LabelColor "=============================== Displaying Host information ========================================"

			$HostObject | Format-List HostName,DNSHostname,Architecture,CurrentTimeZone

			Write-Host -ForegroundColor $LabelColor "------- OS Info -------"
			$HostObject.OS | Format-List Caption, Version, OSArchitecture, CSDVersion 

			Write-Host -ForegroundColor $LabelColor "------- Disk Info -------"
			$HostObject.Disks | format-table -auto

			Write-Host -ForegroundColor $LabelColor "------- Oldest Event Log Date -------"
			$HostObject.OldestEventlog | format-table -auto

			Write-Host -ForegroundColor $LabelColor "-  ------ Survey Time Stamps -------"
			"Start:`t{0} `n`rStop:`t{1} `n`rTotal Runtime(sec): {2:N2}" -f $HostObject.ScanStart, $HostObject.StopTime, $HostObject.RunTime
			
			_Wait

		#endregion Host Information
		
		#region Displaying Account Information	
		Write-Host -ForegroundColor $LabelColor "===================================================================================================="
		Write-Host -ForegroundColor $LabelColor "=============================== Displaying Account Information ====================================="

			Write-Host -ForegroundColor $LabelColor "------ Current User ------"
			$HostObject.Accounts.CurrentUser | out-default
			" " | out-default

			Write-Host -ForegroundColor $LabelColor "------ Local Admins ------"
			$HostObject.Accounts.Admins | out-default

			Write-Host -ForegroundColor $LabelColor "------ RDP History ------"
			$HostObject.Accounts.RDPHistory | out-default

			Write-Host -ForegroundColor $LabelColor "------ Login History ------"
			$HostObject.Accounts.LoginHistory | Format-Table -auto

			_Wait
		#endregion Host Information

		#region Displaying Processes
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Processes ================================================

			if ($FilterGreen) {
				$ProcList = $HostObject.ProcessList | where {$_.Check -ne "Whitelist"} | Sort-Object ParentProcessId, PathName
			} else {
				$ProcList = $HostObject.ProcessList | Sort-Object ParentProcessId, PathName			
			}
			
			#Format Display
			$format_headers = "{0,-7} {1,5} {2,3} {3,-40} {4,-90} {5,-20} {6,-13} {7,-33}"
			$format_headers -f "Parent", "PID", "SID", "Name" , "PathName","Signature", "Check", "Hash" 
			
			#Format Table
			$cformat = 	@{Expression={$_.ParentProcessId}	;Label="Parent"		;width=7	;alignment="left"},
						@{Expression={$_.ProcessId}			;Label="PID"		;width=5	;alignment="right"},
						@{Expression={$_.SessionId}			;Label="SID"		;width=3	;alignment="right"},
						@{Expression={$_.Name}				;Label="Name"		;width=40	;alignment="left"},
						@{Expression={$_.PathName}			;Label="PathName"	;width=90	;alignment="left"},
						@{Expression={$_.Signature}			;Label="Signature"	;width=20	;alignment="left"},
						@{Expression={$_.Check}				;Label="Check"		;width=13	;alignment="left"},
						@{Expression={$_.Hash}				;Label="Hash"		;width=33	;alignment="left"}

			
			foreach ($item in $ProcList) {
				$linecolor = _Color_Display_Check2 $item
				
				# Print formatted line with proper colors
				Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
					($item | format-table $cformat -hidetableheaders | out-string).Trim()
			}
			_Wait
			

		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Displaying Commandline invocation ==================================
		Write-Host -ForegroundColor $LabelColor "Analyst: Review command line arguements for anything out of the ordinary."
			## Display Process Command Line invocation, no need for logic, Mark 1 Eyeball this for wierd CLI parameters

			#Format Headers
			$format_headers = "{0,-6} {1,-40} {2,-30} {3,-250}"
			$format_headers -f "PID", "Name", "Owner", "CommandLine" 
			
			#Format Table
			$cformat = 	@{Expression={$_.ProcessId} 	;Label="PID"			;width=6 	;alignment="left"},
						@{Expression={$_.Name} 			;Label="Name"			;width=40 	;alignment="left"},
						@{Expression={$_.Owner} 		;Label="Owner"			;width=30 	;alignment="left"},
						@{Expression={$_.CommandLine} 	;Label="CommandLine" 	;width=250 	;alignment="left"}
				
			if ($FilterGreen) {
				$ProcList = $HostObject.ProcessList | where {$_.Check -ne "Whitelist"} | Sort-Object ParentProcessId, PathName
			} else {
				$ProcList = $HostObject.ProcessList | Sort-Object ParentProcessId, PathName	
			}
			
			foreach ($item in $ProcList) {
				$linecolor = _Color_Display_Check2 $item
				
				# Print formatted line with proper colors
				Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
					($item | format-table $cformat -hidetableheaders | out-string).Trim()
			}
			_Wait
		#endregion Processes
		
		#region Displaying Modules
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Displaying Loaded DLLs =============================================

			#Format Display
			if ($Advanced) {
				$temp = $HostObject.ModuleList
			} else {
				Write-Host -ForegroundColor $LabelColor "Filtering out whitelisted items. Use -Advanced to see them"
				Write-Host " "
				$temp = $HostObject.ModuleList | where { ($_.Check -ne "Whitelist") -AND ($_.PathName -notlike "*NativeImages*") -AND ($_.PathName -notlike "*WinSxS*")}
			}
			
			if ($FilterGreen) {
				$ModList = $temp | where {$_.Check -ne "Whitelist"} | Sort-Object PathName
			} else {
				$ModList = $temp | Sort-Object PathName
			}		
			
			#Format Headers
			$format_headers = "{0,-35} {1,-80} {2,-25} {3,-40} {4,-50} {5,20} {6,-13} {7,-33}"
			$format_headers -f "ModuleName", "PathName",  "Company", "FileVersion", "Description", "Signature", "Check", "Hash"
			
			#Format Table
			$cformat = 	@{Expression={$_.ModuleName}	;Label="ModuleName"		;width=35	;alignment="left"},
						@{Expression={$_.PathName}		;Label="PathName"		;width=80	;alignment="left"},
						@{Expression={$_.Company}		;Label="Company"		;width=25	;alignment="left"},
						@{Expression={$_.FileVersion}	;Label="FileVersion"	;width=40	;alignment="left"},
						@{Expression={$_.Description}	;Label="Description"	;width=50	;alignment="left"},
						@{Expression={$_.Signature}		;Label="Signature"		;width=20	;alignment="right"},
						@{Expression={$_.Check}			;Label="Check"			;width=13	;alignment="left"},
						@{Expression={$_.Hash}			;Label="Hash"			;width=33	;alignment="left"}
					
			foreach ($item in $ModList) {
				$linecolor = _Color_Display_Check2 $item
				# Print formatted line with proper colors
				Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
					($item | format-table $cformat -hidetableheaders | out-string).Trim()
			}
			_Wait
		#endregion Modules

		#region Displaying Services
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Services =================================================

			#Format Display
			if ($Advanced) {
				$temp = $HostObject.ServiceList
			} else {
				Write-Host -ForegroundColor $LabelColor "Filtering for currently running items. Use -Advanced to see more"
				Write-Host " "
				$temp = $HostObject.ServiceList | where {$_.State -eq "Running"}
			}
			
			if ($FilterGreen) {
				$SvcList = $temp | where {$_.Check -ne "Whitelist"} | sort-object State, PathName
			} else {
				$SvcList = $temp | sort-object State, PathName
			}	
			
			#Format Headers
			$format_headers = "{0,-30} {1,-80} {2,-10} {3,5} {4,-50} {5,-70} {6,-8} {7,-20} {8,-13} {9,-33}"
			$format_headers -f "Name", "PathName", "StartMode", "PID", "Caption", "Description", "State", "Signature", "Check",  "Hash"
		
			#Format Table
			$cformat = 	@{Expression={$_.Name}			;Label="Name"			;width=30	;alignment="left"},
						@{Expression={$_.PathName}		;Label="PathName"		;width=80	;alignment="left"},
						@{Expression={$_.StartMode}		;Label="StartMode"		;width=10	;alignment="left"},
						@{Expression={$_.ProcessId}		;Label="PID"			;width=5	;alignment="right"},
						@{Expression={$_.Caption}		;Label="Caption"		;width=50	;alignment="left"},
						@{Expression={$_.Description}	;Label="Description"	;width=70	;alignment="left"},
						@{Expression={$_.State}			;Label="State"			;width=8	;alignment="left"},
						@{Expression={$_.Signature}		;Label="Signature"		;width=20	;alignment="left"},
						@{Expression={$_.Check}			;Label="Check"			;width=13	;alignment="left"},
						@{Expression={$_.Hash}			;Label="Hash"			;width=33	;alignment="left"}
			
			
			foreach ($item in $SvcList) {
				$linecolor = _Color_Display_Check2 $item
				# Print formatted line with proper colors
				Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
					($item | format-table $cformat -hidetableheaders | out-string).Trim()
			}
			_Wait
		#endregion Services

		#region Displaying Drivers
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Drivers ==================================================

			#Format Display
			if ($Advanced) {
				$temp = $HostObject.DriverList
			} else {
				$temp = $HostObject.DriverList | where {$_.State -eq "Running"}
			}

			if ($FilterGreen) {
				$DvrList = $temp | where {$_.Check -ne "Whitelist"} | sort-object State, PathName
			} else {
				$DvrList = $temp | sort-object State, PathName
			}	
			
			#Format Headers
			$format_headers = "{0,-30} {1,-80} {2,-10} {3,-70} {4,-8} {5,-20} {6,-13} {7,-33}"
			$format_headers -f "Name", "PathName", "StartMode", "Description", "State", "Signature", "Check", "Hash"	
		
			#Format Table
			$cformat = 	@{Expression={$_.Name}			;Label="Name"			;width=30	;alignment="left"},
						@{Expression={$_.PathName}		;Label="PathName"		;width=80	;alignment="left"},
						@{Expression={$_.StartMode}		;Label="StartMode"		;width=10	;alignment="left"},
						@{Expression={$_.Description}	;Label="Description"	;width=70	;alignment="left"},
						@{Expression={$_.State}			;Label="State"			;width=8	;alignment="left"},
						@{Expression={$_.Signature}		;Label="Signature"		;width=20	;alignment="left"},
						@{Expression={$_.Check}			;Label="Check"			;width=13	;alignment="left"},
						@{Expression={$_.Hash}			;Label="Hash"			;width=33	;alignment="left"}
			
			foreach ($item in $DvrList) {
				$linecolor = _Color_Display_Check2 $item
				# Print formatted line with proper colors
				Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
					($item | format-table $cformat -hidetableheaders | out-string).Trim()		
			}
			_Wait
		#endregion Drivers
		
		#region Displaying Connections
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Network Connections ======================================
			# Label any connection from a red process or to/from a Hot IP

			if ($FilterGreen) {
				$cList = $HostObject.Netstat | where {$_.Check -ne "Whitelist"} | sort-object Protocol, ProcessId, State
			} else {
				$cList = $HostObject.Netstat | sort-object Protocol,ProcessId, State
			}
			
			#Format Display
			$format_headers = "{0,-5} {1,-25} {2,8} {3,17} {4,10} {5,-11} {6,17} {7, 10}"
			$format_headers -f "PID", "Name", "Protocol", "Src_Addr", "Src_Port", "State", "Dst_Addr", "Dst_Port"
			
			#Format Table
			$cformat = 	@{Expression={$_.ProcessId}		;Label="PID"		;width=5	;alignment="left"},
						@{Expression={$_.ProcessName}	;Label="Name"		;width=25	;alignment="left"},
						@{Expression={$_.Protocol}		;Label="Protocol"	;width=8	;alignment="right"},
						@{Expression={$_.Src_Address}	;Label="Src_Addr"	;width=17	;alignment="right"},
						@{Expression={$_.Src_Port}		;Label="Src_Port"	;width=10	;alignment="right"},
						@{Expression={$_.State}			;Label="State"		;width=11	;alignment="left"},
						@{Expression={$_.Dst_Address}	;Label="Dst_Addr"	;width=17	;alignment="right"},
						@{Expression={$_.Dst_Port}		;Label="Dst_Port"	;width=10	;alignment="right"}	
								
			foreach ($item in $cList) {
				$linecolor = _Color_Display_Check2 $item
				# Print formatted line with proper colors
				Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
					($item | format-table $cformat -hidetableheaders | out-string).Trim()	
			}
			_Wait
		#endregion Connections 
		
		#region Displaying Arma
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Process Memory ===========================================

			Write-Host -ForegroundColor $LabelColor '------ Comparing running executable memory to disk images (Indicates packed/encrypted executable) ------'
			$HostObject.ArmaImage | where {$_.Protection -like "*read*"} |
				sort-object Difference | ft Protection, Length, ProcessId, PathName, @{Expression=("{0:N2}" -f $_.Difference)} -auto
			_Wait

			Write-Host -ForegroundColor $LabelColor '------ Detecting process-injected malware (Looks for MZ Headers) ------'
			$UI.ForegroundColor = $BadColor
			$HostObject.ArmaMalfind | Where { $_.MemorySnip -like "*MZ*" } |
				sort-object PathName | ft Protection, Length, MemorySnip, ProcessId, PathName -auto
			Write-Host " "
			$UI.ForegroundColor = $ForegroundColor
			
			Write-Host -ForegroundColor $LabelColor '------ Displaying all Read/Write/Execute memory ------'
			if ($Advanced) {
				$HostObject.ArmaMalfind |
					sort-object PathName | ft Protection, Length, MemorySnip, ProcessId, PathName -auto
			} else {
				$HostObject.ArmaMalfind | Where { $_.Protection -eq "Executable/read/write." } |
					sort-object PathName | ft Protection, Length, MemorySnip, ProcessId, PathName -auto
			}
			_Wait
		#endregion Arma
		
		#region Displaying Scheduled Tasks
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Scheduled Tasks ==========================================

		# $HostObject.SchTasks | where {($_.ScheduledTaskState -eq "Enabled") -AND ($_.ScheduleType -ne "On demand only") -AND ($_.TaskToRun -ne "COM Handler")} |
		# 	ft TaskName, ScheduleType, Author, TaskToRun, LastRunTime, StartDate, StartTime, RepeatEvery -auto
		 
			if ($Advanced) {	
				$temp = $HostObject.Autoruns | where { $_.Category -eq "Tasks" }
			} else {
				$temp = $HostObject.Autoruns | where { ($_.Category -eq "Tasks") -AND ($_.Signature -ne "Verified") }
			}

			if ($FilterGreen) {
				$autoruns = $temp | where {$_.Check -ne "Whitelist"}
			} else {
				$autoruns = $temp
			}	

			#Format Display
			$format_table_ar = "{0,-60} {1,-100} {2,-50} {3,-30} {4,13} {5,-33}"
			$format_table_ar -f "Name", "CommandLine", "Description", "Publisher", "Check", "Hash"

			#Format Table
			$cformat = 	@{Expression={$_.Name}			;Label="Name"			;width=60	;alignment="left"},
						@{Expression={$_.CommandLine}	;Label="CommandLine"	;width=100	;alignment="left"},
						@{Expression={$_.Description}	;Label="Description"	;width=50	;alignment="left"},
						@{Expression={$_.Publisher}		;Label="Publisher"		;width=30	;alignment="left"},
						@{Expression={$_.Check}			;Label="Check"			;width=13	;alignment="right"},
						@{Expression={$_.Hash}			;Label="Hash"			;width=33	;alignment="left"}
						
			foreach ($item in $autoruns) {
				$linecolor = _Color_Display_Check2 $item
				# Print formatted line with proper colors
				Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
					($item | format-table $cformat -hidetableheaders | out-string).Trim()
			}
			_Wait
			
		#endregion Scheduled Tasks

		#region Displaying Startups
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Startup Locations ========================================

			if ($FilterGreen) {
				$AutoList = $HostObject.Autostart.Startups | where { $_.Check -ne "WhiteList" | Sort-Object PathName}
			} else {
				$AutoList = $HostObject.Autostart.Startups | Sort-Object PathName
			}
			
			#Format Display
			$format_headers = "{0,-25} {1,-30} {2,-80} {3,-80} {4,13}"
			$format_headers -f "Caption", "User", "CommandLine", "Key", "Check"
		
			#Format Table
			$cformat = 	@{Expression={$_.Caption}		;Label="Caption"		;width=25	;alignment="left"},
						@{Expression={$_.User}			;Label="User"			;width=30	;alignment="left"},
						@{Expression={$_.CommandLine}	;Label="CommandLine"	;width=80	;alignment="left"},
						@{Expression={$_.Key}			;Label="Key"			;width=80	;alignment="left"},
						@{Expression={$_.Check}			;Label="Check"			;width=13	;alignment="right"}
						
			foreach ( $item in $AutoList ) {
				$linecolor = _Color_Display_Check2 $item
				# Print formatted line with proper colors
				Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
					($item | format-table $cformat -hidetableheaders | out-string).Trim()
			}	
			_Wait

			Write-Host -ForegroundColor $LabelColor '------ Displaying all files in autostart folders ------'
			$HostObject.Autostart.Startupfolders | Sort-Object CreationTime | ft -auto
			
			Write-Host " "
			Write-Host -ForegroundColor $LabelColor '------ Displaying AppInitDlls ------'
			$HostObject.Autostart.Appinit_dlls

			Write-Host " "
			Write-Host " "
			Write-Host -ForegroundColor $LabelColor '------ Displaying NullSessionPipes ------'
			$HostObject.Autostart.NullSessionPipes
			Write-Host " "
			Write-Host " "
			_Wait

		#endregion Startups

		#region Displaying Autoruns
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Autoruns Output ==========================================

			if ($Advanced) {
				$temp = $HostObject.Autoruns | where { 
					($_.Category -ne "Services") -AND `
					($_.Category -ne "Drivers") -AND `
					($_.Category -ne "Tasks") -AND `
					($_.PathName -notlike "File Not*")
					}
			} else {
				$temp = $HostObject.Autoruns | where { 
					($_.Category -ne "Services") -AND `
					($_.Category -ne "Drivers") -AND `
					($_.Category -ne "Tasks") -AND `
					($_.PathName -notlike "File Not*") -AND `
					($_.Signature -ne "Verified")
					}		
			}
			
			if ($FilterGreen) {
				$AutoList = $temp | where { $_.Check -ne "WhiteList" } | Sort-Object Category, PathName
			} else {
				$AutoList = $temp | Sort-Object Category, PathName
			}
			
			#Format Display
			$format_headers = "{0,-20} {1,-45} {2,-70} {3,-60} {4,-90} {5,-30} {6,13}"
			$format_headers -f "Category", "Name", "Description", "PathName", "Key", "Publisher", "Check"
			
			#Format Table
			$cformat = 	@{Expression={$_.Category}		;Label="Caption"		;width=20	;alignment="left"},
						@{Expression={$_.Name}			;Label="User"			;width=45	;alignment="left"},
						@{Expression={$_.Description}	;Label="CommandLine"	;width=70	;alignment="left"},
						@{Expression={$_.PathName}		;Label="Key"			;width=60	;alignment="left"},
						@{Expression={$_.Key}			;Label="CommandLine"	;width=90	;alignment="left"},
						@{Expression={$_.Publisher}		;Label="Key"			;width=30	;alignment="left"},
						@{Expression={$_.Check}			;Label="Check"			;width=13	;alignment="right"}
						
			foreach ( $item in $AutoList ) {
				$linecolor = _Color_Display_Check2 $item
				# Print formatted line with proper colors
				Write-Host -ForegroundColor $linecolor.FC -BackgroundColor $linecolor.BC `
					($item | format-table $cformat -hidetableheaders | out-string).Trim()
			}	
			
			Write-Host " "
			$UI.ForegroundColor = $UnknownColor				
			Write-Host "=============== Orphaned Keys (files no longer exist) =============================================="
			$HostObject.Autoruns | where { $_.PathName -like "File Not*" } | ft Category,Name,PathName,Key -auto
			$UI.ForegroundColor = $ForegroundColor
			$UI.BackgroundColor = $BackgroundColor
			
			if ($Advanced) {
				Write-Host " "
				Write-Host "===================================================================================================="
				Write-Host "	=== WMI vs Autorunsc Count ==="
				"	=== WMI ServiceList Count: {0}	Autorunsc Service Count: {1} " 	-f $HostObject.ServiceList.count, ($HostObject.Autoruns | where { $_.Category -eq "Services"}).count
				"	=== WMI DriverList Count: {0}	Autorunsc Driver Count: {1} " 	-f $HostObject.DriverList.count, ($HostObject.Autoruns | where { $_.Category -eq "Drivers"}).count
				Write-Host "===================================================================================================="
			}
			
			_Wait
		
		#endregion Autoruns
		
		#region Displaying Network Configuration
		Write-Host -ForegroundColor $LabelColor ====================================================================================================
		Write-Host -ForegroundColor $LabelColor =============================== Surveying Network Configurations ===================================

			Write-Host -ForegroundColor $LabelColor '------ Displaying ipconfig ------'
			$HostObject.NetworkConfig.ipconfig | Select IPAddress, DHCPEnabled, Description | out-default
			
			Write-Host " "
			Write-Host -ForegroundColor $LabelColor '------ Displaying static routes ------'
			$HostObject.NetworkConfig.Routes | out-string
			
			Write-Host " "
			Write-Host -ForegroundColor $LabelColor '------ Displaying Hosts file ------'
			$HostObject.NetworkConfig.hosts | out-default

			Write-Host " "
			Write-Host -ForegroundColor $LabelColor '------ Displaying Open Sessions ------'
			$HostObject.NetworkConfig.Sessions | out-default

			Write-Host " "
			Write-Host -ForegroundColor $LabelColor '------ Displaying Shares ------'
			$HostObject.NetworkConfig.shares | ft -auto
			
		#endregion Network Configuration	
		
		#region Displaying Named Pipes
		#Write-Host -ForegroundColor $LabelColor '===================================================================================================='
		#Write-Host -ForegroundColor $LabelColor '=============================== Surveying Named Pipes ==============================================='
			# TODO: Add log to compare against a named pipes blacklist
			#$HostObject.NamedPipes
		
		#endregion NamedPipes
		
		Write-Host -ForegroundColor $LabelColor '===================================================================================================='
		Write-Host -ForegroundColor $LabelColor Survey complete!
		
		if ($Advanced) {
			Write-Host -ForegroundColor $LabelColor '------ Advanced HostObject Instructions ------'
			
			$n = 0
			Write-Host "HostObject collects the following information"
			$HostObject | gm -MemberType NoteProperty | Select -ExpandProperty Name | foreach {
				Write-Host ($n): $_
				$HostObject.$_ | gm -MemberType NoteProperty | Select -ExpandProperty Name | foreach {
					Write-Host -ForegroundColor $SunkColor "	$_"
				}
				$n += 1
			}
			Write-Host "   "
			Write-Host "------Import HostObject into a powershell variable with the following command------"
			write-Host '	$YourVariablename = Import-CLIXML .\OPDATA\<System Name>\HostSurvey.xml' 
		}
			
		$UI.ForegroundColor	= $oldFGColor
		$UI.BackgroundColor = $oldBGColor
		
	}


	function _Color_Display_Check ($item) {
		if ($item.PSObject.Properties.Match('Check').count -gt 0) {	
			switch ($item.Check) { 
				"Blacklist" 		{ $UI.ForegroundColor = $BadColor }
				"Whitelist" 		{ $UI.ForegroundColor = $GoodColor } 
				"NIST" 				{ $UI.ForegroundColor = $NISTColor }
				"GoodPath"		 	{ $UI.ForegroundColor = $OkColor }
				"BadPath"		 	{ $UI.ForegroundColor = $SemiBadColor }													
				default 			{ $UI.ForegroundColor = $UnknownColor }
			}
		}
		if ($item.PSObject.Properties.Match('CheckIP').count -gt 0) {	
			switch ($item.CheckIP) { 
				"Bad" 				{$UI.BackgroundColor = $BadBackground }
				default 			{$UI.BackgroundColor = $BackgroundColor }
			}
		} else {
			if ($item.PSObject.Properties.Match('Signature').count -gt 0) {
				if ($item.Check -ne "Whitelist") {
					switch ($item.Signature) { 
						"Invalid_Signature" {$UI.BackgroundColor = $BadBackground }
						default 			{$UI.BackgroundColor = $BackgroundColor }
					}
				}
			}
		}
	}

	function _Color_Display_Check2 ($item) {
		if ($item.PSObject.Properties.Match('Check').count -gt 0) {	
			switch ($item.Check) { 
				"Blacklist" 		{ $fore = $BadColor }
				"Whitelist" 		{ $fore = $GoodColor } 
				"NIST" 				{ $fore = $NISTColor }
				"GoodPath"		 	{ $fore = $OkColor }
				"BadPath"		 	{ $fore = $SemiBadColor }													
				default 			{ $fore = $UnknownColor }
			}
		}
		if ($item.PSObject.Properties.Match('CheckIP').count -gt 0) {	
			switch ($item.CheckIP) { 
				"Bad" 				{$back = $BadBackground }
				default 			{$back = $BackgroundColor }
			}
		} else {
			if ($item.PSObject.Properties.Match('Signature').count -gt 0) {
				if ($item.Check -ne "Whitelist") {
					switch ($item.Signature) { 
						"Invalid_Signature" {$back = $BadBackground }
						default 			{$back = $BackgroundColor }
					}
				}
			}
		}
		return @{
			FC = $fore
			BC = $back
			}
	}

	
	function _Wait ([string]$Message="Press any key to continue ...") {
		$UI.ForegroundColor = $ForegroundColor
		Write-Host -ForegroundColor $SunkColor $Message
		$x = $UI.ReadKey("NoEcho,IncludeKeyDown")
		Write-host 
	}

	function _Ask_YesNo_Question ($title, $message, $yesmsg, $nomsg) {
		$UI.ForegroundColor = $SunkColor
		
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", $yesmsg
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", $nomsg
			
		$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		
		$result = $host.ui.PromptForChoice($title, $message, $options, 0) 
		$UI.ForegroundColor = $ForegroundColor
		switch ($result)
			{
				0 { return $true }
				1 { return $false }
			}
	}

	function _ContinueView {
		$UI.ForegroundColor = $SunkColor
		
		$title = "Continue"
		$message = "Do you want to view the remaining process dlls?"
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
			"Continues to next DLL."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
			"Skips to services."
			
		$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		
		$result = $host.ui.PromptForChoice($title, $message, $options, 0) 
		$UI.ForegroundColor = $ForegroundColor
		switch ($result)
			{
				0 { return $true }
				1 { return $false }
			}
	}

#endregion

#region ########### Import/Export functions ###########

	function export_Baseline ($HostObject){
		$List = @(
			"Name"
			"PathName"
			"Hash"
			"DateAdded"
		)
		$today = get-date -format d
		$processes = @()
		$drivers = @()
		$modules = @()
		
		foreach ($item in ($HostObject.ProcessList)) {
			if (($item.Hash -ne "") -AND ($item.Hash -ne $null) -AND ($item.Hash -ne $NullHash)) {
				$obj = New-Object PSObject -Property @{
					Name		= $item.Name
					PathName	= $item.PathName
					Hash		= $item.Hash
					DateAdded 	= $today
				}
				$processes += $obj
			}
		}
		
		foreach ($item in $HostObject.ModuleList) {
			if (($item.Hash -ne "") -AND ($item.Hash -ne $null) -AND ($item.Hash -ne $NullHash)) {
				$obj = New-Object PSObject -Property @{
					Name		= $item.ModuleName
					PathName	= $item.PathName
					Hash		= $item.Hash
					DateAdded 	= $today
				}
				$modules += $obj		
			}
		}		
		foreach ($item in ($HostObject.Autoruns)) {
			if (($item.Hash -ne "") -AND ($item.Hash -ne $null) -AND ($item.Hash -ne $NullHash)) {
				$obj = New-Object PSObject -Property @{
					Name		= $item.PathName.ToString().Substring($item.PathName.ToString().LastIndexOf('\')+1)
					PathName	= $item.PathName
					Hash		= $item.Hash
					DateAdded 	= $today
				}
				if ($obj.PathName -like "*.dll") {
					$modules += $obj
				} elseif ($obj.PathName -like "*.sys") {
					$drivers += $obj
				} else {
					$processes += $obj
				}
			}			
		}
		
		foreach ($item in ($HostObject.Autostart.Known_dlls)) {
			if (($item.Hash -ne "") -AND ($item.Hash -ne $null) -AND ($item.Hash -ne $NullHash)) {
				$obj = New-Object PSObject -Property @{
					Name		= $item.PathName.ToString().Substring($item.PathName.ToString().LastIndexOf('\')+1)
					PathName	= $item.PathName
					Hash		= $item.Hash
					DateAdded 	= $today
				}
				$modules += $obj
			}			
		}
		
		foreach ($item in ($HostObject.ServiceList)) {
			if (($item.Hash -ne "") -AND ($item.Hash -ne $null) -AND ($item.Hash -ne $NullHash)) {
				$obj = New-Object PSObject -Property @{
					Name		= $item.Name
					PathName	= $item.PathName
					Hash		= $item.Hash
					DateAdded 	= $today
				}
				$processes += $obj
			}			
		}

		foreach ($item in ($HostObject.DriverList)) {
			if (($item.Hash -ne "") -AND ($item.Hash -ne $null) -AND ($item.Hash -ne $NullHash)) {
				$obj = New-Object PSObject -Property @{
					Name		= $item.Name
					PathName	= $item.PathName
					Hash		= $item.Hash
					DateAdded 	= $today
				}
				$drivers += $obj
			}			
		}
		
		$processes 	| Sort-Object -Unique Hash | Select-Object $List | Export-Csv $ScriptPath\lists\base_executables.csv
		Write-Host Exported processes to $ScriptPath\lists\base_executables.csv
		$modules 	| Sort-Object -Unique Hash | Select-Object $List | Export-Csv $ScriptPath\lists\base_modules.csv
		Write-Host Exported modules to $ScriptPath\lists\base_modules.csv
		$drivers 	| Sort-Object -Unique Hash | Select-Object $List | Export-Csv $ScriptPath\lists\base_drivers.csv
		Write-Host Exported drivers to $ScriptPath\lists\base_drivers.csv
	}

	# Nist is great but if this could be ported to use some type of software reputation database that would be best for future
	function export_NIST_Baseline ($BaseObject) {
		$processes = @()
		$services = @()
		$drivers = @()
		$modules = @()
		$date = get-date -format d
		
		$processes += _ConvertTo_CsvExportList ($BaseObject.ProcessList | where {$_.Check -eq "NIST"})
		$services += _ConvertTo_CsvExportList ($BaseObject.ServiceList | where {$_.Check -eq "NIST"})
		$drivers += _ConvertTo_CsvExportList ($BaseObject.DriverList | where {$_.Check -eq "NIST"})
		$modules += _ConvertTo_CsvExportList ($BaseObject.ModuleList | where {$_.Check -eq "NIST"})
		
		foreach ($item in ($BaseObject.Autostarts | where {$_.Check -eq "NIST"})) {
			if (($item.Hash -ne "") -AND ($item.Hash -ne $null) -AND ($item.Hash -ne $NullHash)) {
				$obj = New-Object PSObject -Property @{
					Name		= ""
					PathName	= $item.PathName
					Hash		= $item.Hash
					DateAdded	= $date
				}
				if ($item.PathName -like "*.exe") {
					$processes += $obj
				} 
				elseif ($item.PathName -like "*.dll") {
					$modules += $obj
				}
				elseif ($item.PathName -like "*.sys") {
					$drivers += $obj			
				}
			}			
		}
		
		
		(import-csv $ScriptPath\list\good_processes.csv) + ($processes | Sort-Object Hash -Unique | Select-Object $List) | 
				Sort-Object -Unique Hash | Select-Object $List | export-csv $ScriptPath\lists\exportNIST_processes.csv
		Write-Host Added NIST-cleared processes to $ScriptPath\lists\exportNIST_processes.csv

		(import-csv $ScriptPath\list\good_processes.csv) + ($modules | Sort-Object -Unique Hash | Select-Object $List) | 
				Sort-Object -Unique Hash | Select-Object $List | export-csv $ScriptPath\lists\exportNIST_modules.csv
		Write-Host Added NIST-cleared modules to $ScriptPath\lists\exportNIST_modules.csv

		(import-csv $ScriptPath\list\good_services.csv) + ($services | Sort-Object -Unique Hash | Select-Object $List) | 
				Sort-Object -Unique Hash | Select-Object $List | export-csv $ScriptPath\lists\exportNIST_services.csv
		Write-Host Added NIST-cleared services to $ScriptPath\lists\exportNIST_services.csv

		(import-csv $ScriptPath\list\good_drivers.csv) + ($drivers | Sort-Object -Unique Hash | Select-Object $List) | 
				Sort-Object -Unique Hash | Select-Object $List | export-csv $ScriptPath\lists\exportNIST_drivers.csv
		Write-Host Added NIST-cleared drivers to $ScriptPath\lists\exportNIST_drivers.csv
	}


	function _ConvertTo_CsvExportList ($list) {
		$newList = @()
		$date = get-date -format d
		foreach ($item in $list) {
			if (($item.Hash -ne "") -AND ($item.Hash -ne $null) -AND ($item.Hash -ne $NullHash)) {
				$obj = New-Object PSObject -Property @{
					Name		= $item.Name
					PathName	= $item.PathName
					Hash		= $item.Hash
					DateAdded	= $date
				}
				$newList += $obj
			}
		}
		return $newList
	}

#endregion

#region ########### Processing functions ###########

	function _Add_Bad_Executables ($itemList, $Hostname) {
		# Remove good and nist items:
		$List = $itemList | where { ($_.Check -eq "Blacklist") -OR ($_.Check -eq "BadPath") -OR ($_.Check -eq "Unknown") }
		
		foreach ($item in $List) {
			$item | Add-Member -type NoteProperty -name Host -value $Hostname -Force
		}
		return $List
	}

	function Build_BaseObject ($StartOp, $Hosts) {
		"" | out-file -encoding UTF8 Analyzer_error.txt -force
		"" | out-file -encoding UTF8 WaitingToBeProcessed.txt -force
		
		# Creating BaseObject arrays
		# System.Collections.ArrayList
		$Base_ProcessList = @()
		$Base_ModuleList = @()
		$Base_ServicesList = @()
		$Base_DriversList = @()
		$Base_Autoruns = @()
		$Base_Autostart = @()
		$Base_Accounts = @()
		$Base_ArmaMalfind = @()
		$Base_ArmaImage = @()
		$Base_Connections = @()
		$Base_OSStats = @()
		$Base_ScanMetaData = @()

		# Build BaseObject
		$n = 0
		$nh = $Hosts.count
		$Hosts | foreach {
			# Import host Objects
			$n += 1
			Write-Host "($n of $nh): Parsing $StartOp\$_\$SurveyFileName into BaseObject"	
			$HostObject = Import-Clixml $StartOp\$_\$SurveyFileName
			
			# Sanity Checks
			if ($HostObject.Version -ne $version) {
				Write-Error "$_ (Version $HostObject.Version) is not compatible with this Analyzer (should be version $version). Skipping HostObject."
				"$_ (Version $HostObject.Version) is not compatible with this Analyzer (should be version $version). Skipping HostObject." | out-file -append -encoding UTF8 Analyzer_error.txt
				continue 
			}
			if ($HostObject.ObjectType -ne "Helix_HostObject") { 
				Write-Error "$_ is not compatible with this Analyzer (should be a Helix_Hostobject). Skipping."
				"$_ is not compatible with this Analyzer (should be a Helix_Hostobject). Skipping." | out-file -append -encoding UTF8 Analyzer_error.txt
				continue 			
			}
			if ($HostObject.ObjectStatus -ne "Processed") { 
				Write-Error "$_ has not been processed. Skipping."
				"$_ has not been processed. Skipping." | out-file -append -encoding UTF8 Analyzer_error.txt
				$_.ToString() | out-file -append -encoding UTF8 WaitingToBeProcessed.txt
				continue 			
			}
			
			$Base_ProcessList 	+= _Add_Bad_Executables $HostObject.ProcessList $HostObject.HostName
			$Base_ModuleList 	+= _Add_Bad_Executables $HostObject.ModuleList $HostObject.HostName
			$Base_ServicesList 	+= _Add_Bad_Executables $HostObject.ServiceList $HostObject.HostName
			$Base_DriversList 	+= _Add_Bad_Executables $HostObject.DriverList $HostObject.HostName
			$Base_Autoruns 		+= _Add_Bad_Executables $HostObject.Autoruns $HostObject.HostName
			$Base_Autostart 	+= _Add_Bad_Executables $HostObject.Autostart.Startups $HostObject.HostName
			
			# Add unique account logins
			foreach ($account in $HostObject.Accounts.LoginHistory) { 
				if (($account.Caption -ne "") -AND ($account.Caption -notlike "NT AUTHORITY*") -AND ($account.Caption -ne "USAF_Admin") -AND ($account.Caption -ne "SDC_Admin")) {
					$account | Add-Member -type NoteProperty -name Host -value $HostObject.HostName
					$Base_Accounts += $account
				}
			}
			
			# Add Injected Processes from ArmaMalfind scan
			foreach ($item in ($HostObject.ArmaMalfind | where { $_.MemorySnip -like "*MZ*" } )) { 
				$item | Add-Member -type NoteProperty -name Host -value $HostObject.HostName
				$Base_ArmaMalfind += $item
			}
			
			# Add Connections to bad IPs
			foreach ($item in ($HostObject.Netstat | where { $_.CheckIP -eq "Bad" } )) { 
				$item | Add-Member -type NoteProperty -name Host -value $HostObject.HostName
				$Base_Connections += $item
			}
			
			# Add OS Information
			$HostObject.OS | Add-Member -type NoteProperty -name Host -value $HostObject.HostName
			$Base_OSStats += $HostObject.OS
			
			# Add Scan time stats
			$Base_ScanMetaData += @{
				Hostname = $HostObject.HostName
				RunTime = $HostObject.RunTime
				}
		}

		# Build BaseObject 
		$BaseObject = New-Object PSObject -Property @{
			Opfolder			= $StartOp
			Date				= (Get-Date)
			Hosts				= $Hosts
			OS					= $Base_OSStats
			ProcessList			= $Base_ProcessList
			Connections			= $Base_Connections
			ModuleList			= $Base_ModuleList
			ServiceList			= $Base_ServicesList
			DriverList			= $Base_DriversList
			Accounts			= $Base_Accounts
			Autostarts			= $Base_Autostart
			Autoruns			= $Base_Autoruns
			ArmaMalfind			= $Base_ArmaMalfind
			ScanMetaData		= $Base_ScanMetaData
		}
		
		# Gather hash occurrences and stats into BaseObject:
		$Stats = New-Object PSObject -Property @{
			Process_stats 	= @{}
			Module_stats 	= @{}
			Service_stats 	= @{}
			Driver_stats 	= @{}
			Autostart_stats = @{}
			Autorun_stats 	= @{}
		}
		
		$BaseObject.ProcessList | foreach {
			$Stats.Process_stats[$_.Hash] += 1
			}
		$BaseObject.ModuleList | foreach {
			$Stats.Module_stats[$_.Hash] += 1
			}
		$BaseObject.ServiceList | foreach {
			$Stats.Service_stats[$_.Hash] += 1
			}
		$BaseObject.DriverList | foreach {
			$Stats.Driver_stats[$_.Hash] += 1
			}
		$BaseObject.Autostarts | foreach {
			$Stats.Autostart_stats[$_.Hash] += 1
			}			
		$BaseObject.Autoruns | foreach {
			$Stats.Autorun_stats[$_.Hash] += 1
			}		
			
		$BaseObject | Add-Member -type NoteProperty -Name Stats -Value $Stats
		
		return $BaseObject
	}
	
#endregion

########### MAIN ###########

	# Display Help
	if ( ($Help) -OR ($SurveyPath -AND $StartOp)) { Display_Help }

	# Test if path is container (OPDATA folder)
	if (!(Test-Path -ea 0 -PathType container -Path $StartOp)) { Write-Error '"StartOp" arguement is not an OPDATA directory'; Return "Error"}

	#region Process/Display BaseObject
	# Process all HostObjects within subdirectories and build BaseObject
	if ($StartOp) {
		# Process all HostObjects in OPDATA folder (recursive) and build BaseObject

		# Test if BaseObject.xml already exists
		if ((Test-Path -ea 0 -Path $StartOp\BaseObject.xml) -AND !$Reprocess) {
			
			# Import BaseObject
			Write-Host -Foreground $LabelColor BaseObject already exists, Importing BaseObject.xml and displaying data.
			"<$datestamp> $StartOp\BaseObject.xml exists, Importing BaseObject.xml and displaying data." >> $logfile
			$BaseObject = import-clixml $StartOp\BaseObject.xml
		
		# Process all HostObjects	
		} 
		else {
			
			# Counting number of existing HostObjects in OPDATA folder
			$Hosts = @()
			$Broken_Hosts = @()
			gci $StartOp | where { $_.PSIsContainer } | foreach {
				if (Test-Path -ea 0 $StartOp\$_\$SurveyFileName) {
					$Hosts += $_.Name
				} else {
					$Broken_Hosts += $_.name
				}
			}
			
			# Exporting list of failed hosts (Broken_hosts.txt)
			Write-Host "Listing failed target hosts in: $StartOp\Broken_hosts.txt"
			$Broken_Hosts | Out-File -Encoding "UTF8" $StartOp\Broken_hosts.txt
			
			# Print scan stats
			$nh = $Hosts.count
			$nbh = $Broken_Hosts.count
			Write-host -Foreground $LabelColor ==========================================
			Write-host -Foreground $LabelColor "Total # of hosts scanned: $nh"
			Write-host -Foreground $LabelColor "Number of failed scans: $nbh"
			Write-host -Foreground $LabelColor ==========================================

			if (!$Threaded) {
			
					# Build Command Arguments
					$CmdArgs = "-NoProfile"
					$CmdArgs = " gci $StartOp -include $SurveyFileName -recurse | $ScriptPath\Process-Survey.ps1"
					if ($Reprocess) { $CmdArgs += " -Reprocess" }
					if ($PSBoundParameters['Verbose']) { $CmdArgs += " -Verbose" }
					if ($PSBoundParameters['Debug']) { $CmdArgs += " -Debug" }			
					if ($NoNIST) { $CmdArgs += " -NoNIST" }

					Write-verbose "Starting Powershell job with args: $CmdArgs"	
					"<$datestamp> Starting Powershell job with args: $CmdArgs" >> $logfile
					$process = Start-Process Powershell.exe -ArgumentList $CmdArgs -WindowStyle Normal -Passthru
					$process | wait-process | stop-process
					
			}
			else {			
				# Split Hosts into multiple arrays for threading onto each core (for fastness)
				$nprocs = (gwmi win32_computersystem).NumberOfLogicalProcessors
				if ($nh -lt $nprocs) { 
					$n = $nh
				} else { 
					$n = $nprocs
				}	
				Write-Verbose "$nprocs cores exist"
				Write-Verbose "$n threads will be used"
				
				# Building HostObject list from StartOp subfolders
				$HostList = @{}
				$count = 0 
				gci $StartOp -include $SurveyFileName -recurse | foreach {
					$HostList[$count%$n] += @($_.FullName);
					$count++;
				}
				
				$processes = @()
				Write-Host -Foreground $LabelColor "Processing all HostObjects in $n arrays"
				# Processing all HostObjects as a job
				0..($n-1) | foreach { 
					# Export hostobject lists
					$HostList[$_] | Out-File $scriptpath\processTargets_$_.txt -Force
								
					# Build Command Arguments
					$CmdArgs = "-NoProfile"
					$CmdArgs += " gc $ScriptPath\processTargets_"+$_.ToString()+".txt | $ScriptPath\Process-Survey.ps1"
					if ($Reprocess) { $CmdArgs += " -Reprocess" }
					if ($PSBoundParameters['Verbose']) { $CmdArgs += " -Verbose" }
					if ($PSBoundParameters['Debug']) { $CmdArgs += " -Debug" }			
					if ($NoNIST) { $CmdArgs += " -NoNIST" }
					
					Write-verbose "Starting Powershell job with args: $CmdArgs"
					"<$datestamp> Starting Powershell job against $HostList[$_].count hostobjects with args: $CmdArgs" >> $logfile
					$processes += Start-Process Powershell.exe -ArgumentList $CmdArgs -WindowStyle Normal -passthru
				}
				
				# Wait for subprocesses to complete
				Write-Host -Foreground $LabelColor "Waiting for processes to complete..."
				$Processes | Wait-Process | Stop-Process
						
				Write-Verbose "Cleaning up processTargets"
				del $ScriptPath\processTargets_*.txt		
				Write-host -Foreground $LabelColor "Processes have finished"
			}
			
			
			# Build BaseObject
			Write-Host -Foreground $LabelColor "Building BaseObject"
			$BaseObject = Build_BaseObject $StartOp $Hosts
			
			# Export BaseObject to XML
			Write-Host -Foreground $LabelColor "Exporting BaseObject.xml.  This will take a long time with any more than 100 hosts."
			$BaseObject | Export-cliXML $StartOp\BaseObject.xml -Encoding UTF8 -Force
			Write-Host "BaseObject export complete!" 
		}
		
		# Finding uniques for better display
		Write-Host -Foreground $LabelColor Finding Uniques...
		$ProcessList_Unique = $BaseObject.ProcessList | Sort-Object Hash -unique
		$ModuleList_Unique 	= $BaseObject.ModuleList | where { ($_.PathName -notlike "*NativeImages*") -AND ($_.PathName -notlike "*WinSxS*")} | Sort-Object Hash -unique
		$ServiceList_Unique = $BaseObject.ServiceList | Sort-Object Hash -unique
		$DriverList_Unique 	= $BaseObject.DriverList | Sort-Object Hash -unique
		$Accounts_Unique 	= $BaseObject.Accounts | Sort-Object Caption -unique
		$Autostarts_Unique 	= $BaseObject.Autostarts | Sort-Object Hash -unique
		$Autoruns_Unique 	= $BaseObject.Autoruns | Sort-Object Hash -unique
		
		$Uniques = New-Object PSObject -Property @{
			ProcessList_Unique 	= $ProcessList_Unique
			ModuleList_Unique 	= $ModuleList_Unique
			ServiceList_Unique 	= $ServiceList_Unique
			DriverList_Unique 	= $DriverList_Unique
			Accounts_Unique 	= $Accounts_Unique
			Autostarts_Unique 	= $Autostarts_Unique
			Autoruns_Unique 	= $Autoruns_Unique
		}
		
		# Generate notepad OPNOTES and OPDATA for operator manipulation
		Write-Host -Foreground $LabelColor Generating OpNotes file
		generate_OpNotes $BaseObject $Uniques

		# Open Notepad for Operator
		Notepad.exe $StartOp\OpNotes.txt

		# NIST NSRL
		if ($Baseline) {
			Write-Host -Foreground $LabelColor Exporting NIST items for inclusion into whitelist
			export_NIST_Baseline $BaseObject 
		}
		
		# Display BaseObject
		Write-Host -Foreground $LabelColor Displaying Data
		Display_BaseObject $BaseObject $Uniques
		
		_Wait
		Return
	}
	#endregion Process/Display BaseObject

	#region Process/Display HostObject
	# Process and display single HostObject
	if ($SurveyPath -like "*$SurveyFileName") {
		
		# Error Check
		if (!(Test-Path $SurveyPath)) { Write-Host HostObject does not exist; Write-Error HostObject does not exist ; exit } 

		# Create Baseline
		if ($Baseline) {
			# Import host Objects
			Write-Host -Foreground $LabelColor Importing $SurveyPath
			$HostObject = Import-Clixml $SurveyPath
		
			# Sanity check for HostObject of proper version
			if ( ($HostObject.ObjectType -ne "Helix_HostObject") -OR ($HostObject.Version -ne $version) ) {
				Write-Error "($n): Not a HostObject with version: $version."
				return
			}

			
			Write-Host -Foreground $LabelColor "Exporting Host as whitelist Baseline..."
			Write-Host -Foreground $LabelColor "New whitelists exported to $ScriptPath\List (ie. base_<name>.csv)"
			export_Baseline $HostObject
			Return
		}

		# Reprocess HostObject
		if ($Reprocess -OR !(Test-Path $SurveyPath\..\Processed.txt)) {
			# Process HostObject
			Write-Host -Foreground $LabelColor Processing HostObject with Process-Survey.ps1...
			$CmdArgs = "-Reprocess"
			if ($PSBoundParameters['verbose']) { $CmdArgs += " -Verbose" }
			if ($NoNIST) { $CmdArgs += " -NoNIST" }
			
			# # Processing all HostObjects
			# Start-Process powershell -ArgumentList $CmdArgs -WindowStyle Normal -Wait
		
			Powershell -NoProfile $ScriptPath\Process-Survey.ps1 $SurveyPath -Reprocess
			Write-Host -Foreground $LabelColor Processing complete!	
		}

		# Import HostObject
		Write-Host -Foreground $LabelColor Importing $SurveyPath
		$HostObject = Import-Clixml $SurveyPath	
		
		# Display HostObject
		Display_HostObject $HostObject
		
		# $a | gm -Membertype NoteProperty | Select -ExpandProperty Name
		
		_Wait
		Return
		
	} 
	#endregion Process/Display HostObject

	# Handle bad input args
	Write-Warning "Incorrect input.  Please specify $SurveyFileName"
	Return








# Notes
# ===================================

#Formating custom aligned olumns
# {0,10} would create a column for the 1st item 10 characters wide and would right-align the contents because the 10 is positive.
# {2,-20} would create a column for the 3rd item 20 characters wide and would left-align the contents because the 20 is negative.

# "{0,28} {1, 20} {2,-8}" -f ` creates:
# A column for the 1st item of 28 characters, right-aligned and adds a space
# A column for the 2nd item of 20 characters right-aligned and adds a space
# A column for the 3rd item of 8 characters left-aligned.

# foreach ($Log in $EventVwr) {
# "{0,28} {1, 20} {2,8}" -f $Log.log, $Log.OverflowAction, $Log.MaximumKilobytes
# }


#$patterns = 'abc','def','ghi'
#$lines = 'abcdefghi','abcdefg','abcdefghijkl'
#
#foreach ($pattern in $patterns)
#{$lines = $lines -match $pattern}

#function pipelineFunction {
#    process {"The value is: $_"}
#}

		# $Result = Ask_YesNo_Question `
						# "DisplayOnly?", # $title
						# "BaseObject.xml already exists in folder, defaulting to Display Only.  Click No to reprocess HostObjects and build a new BaseObject",# $message
						# "Display processed BaseObject.xml",# $yesmsg
						# "Reprocess HostObjects and build new BaseObject"# $nomsg	
	# }