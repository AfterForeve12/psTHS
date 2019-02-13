[CmdletBinding()]  
Param(	[Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True)]
		[string[]]$PathNames,
		[switch]$Help,
		[switch]$Baseline,
		[switch]$Reprocess,
		[switch]$NoNIST
		)

BEGIN {
	##################### Variables
	$List = @(
		"Name"
		"PathName"
		"Hash"
		"DateAdded"
	)	
	$version = 2.0
	$SurveyFileName = "HostSurvey.xml"
	$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
	$NullHash = "D41D8CD98F00B204E9800998ECF8427E"
	$logfile = "$ScriptPath\LOG_psTHSAnalyzer.txt"
	$datestamp = get-date -uformat "%D"
	$Hashtype = "MD5"
	
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
	$UI.WindowTitle = "psTHS - Powershell Threat Hunter Survey Analyzer"
	$b = $UI.BufferSize
	$b.Width = 1500
	$b.Height = 9000
	$UI.BufferSize = $b
	$UI.ForegroundColor = $ForegroundColor
	$UI.BackgroundColor = $BackgroundColor

	
	if ($PSBoundParameters['Verbose']) { 
		# Show Verbose messages
		$VerbosePreference = "Continue"
	} else {
		#Suppress Verbose
		$VerbosePreference = "SilentlyContinue"
	}
	
	if ($PSBoundParameters['Debug']) { 
		Set-StrictMode -version 2.0
		# $ErrorActionPreference  = "Continue"
		$ErrorActionPreference = "Stop" 
		$WarningPreference = "Inquire"
	} else {
		#Suppress Error
		$ErrorActionPreference  = "SilentlyContinue"
		Set-StrictMode –off
	}


	####################### Display functions:

	function Display_Help {
		$UI.ForegroundColor = $LabelColor
		Write-Host ""
		Write-Host "	psTHS - Survey Analyzer"
		Write-Host ""
		Write-Host "		- Used to analyze output from the Helix System Integrity Scanner (survey.ps1)"
		Write-Host ""	
		Write-Host "	Usage:"
		Write-Host "		Single Host: 		.\Process-Survey.ps1 .\OPDATA\Hostname\$SurveyFileName"
		Write-Host "		Folder of Hosts: 	gci -recurse .\OPDATA -include "$SurveyFileName" | .\Process-Survey.ps1" 	
		Write-Host "" 
		Write-Host "		[-Verbose]			- Verbose/Debug messages" 
		Write-Host "		[-Reprocess]			- Reprocess an already processed $SurveyFileName file (in case of updated white/black lists or NIST Database)"
		Write-Host "		[-NoNIST] 			- Do not import NIST Database (saves processing time, but messier output)" 
		Write-Host ""
		$UI.ForegroundColor = $ForegroundColor
		Exit
	}
		
	function Wait ([string]$Message="Press any key to continue ...") {
		$UI.ForegroundColor = $ForegroundColor
		Write-Host -ForegroundColor $SunkColor $Message
		$x = $UI.ReadKey("NoEcho,IncludeKeyDown")
	}

	####################### Import/Export functions:
			

	####################### Formatting functions:

	function merge_Hashtables($htold, $htnew) {
		$keys = $htold.getenumerator() | foreach-object {$_.key}
		$keys | foreach-object {
			$key = $_
			if ($htnew.containskey($key))
			{
				$htold.remove($key)
			}
		}
		$htnew = $htold + $htnew
		return $htnew
	}

	
	function get_Hashlist ($path) {
    
		$hashlist = @{}
		$reader = [System.IO.File]::OpenText($path)
		
		# Test psTHS list
		try {
			$line = $reader.ReadLine()
			if (($line -notlike "#TYPE*") -AND ($line -notlike '"Name",*')) {
				Write-Error "Error: $path is not a readable psTHS list"
				$reader.Close()
				exit
			}
		} catch {
			$reader.Close()
			Write-Error "Error: Could not read from file: $path"
			exit
		} 
		
		while ($line = $reader.ReadLine()) {
			if ( ($line -eq $null) -OR ($line -like "#TYPE*") -OR ($line -like '"Name",*') ) { continue }
			
			# process the line
			$pathname = $line.split(",")[1].Trim('"')
			$hash = $line.split(",")[2].Trim('"')
            $sha1 = $line.split(",")[3].Trim('"')   
			
			if (($hash -ne "") -AND ($hash -ne $NullHash) -AND (-not $hashlist.ContainsKey($hash)) ) {
				$hashlist.Add($hash, $pathname)
			}
		}
		$reader.Close()
		
		return $hashlist
	}
	
	
	function Get_NIST ($path) { 
		$start = Get-Date
		$hashlist = New-Object Hashtable 2000000
		$reader = [System.IO.File]::OpenText($path)
		$n = 0
		$line = $reader.readline()
		if ( ($line -match "^[0-9a-Z][32]") -OR ($line -match "^[0-9a-Z][40]")) {
			$hashlist.Add($line, $true)
			$n += 1
		} else { Write-Verbose "File is not a list of hashes, $line is not a hash"; exit }
		
		while ($line = $reader.ReadLine()) {
			if ( ($line -eq $null) -OR ($line -eq $NullHash) ) { continue }	 
			if ( -not $hashlist.ContainsKey($line) ) {
				$hashlist.Add($line, $null)
			}
			$n += 1
			if ($n%1000 -eq 0) {
				Write-Progress -Activity "Reading from NIST" -percentcomplete "-1" -status "$n hashes added to Hashtable"
			}
		}
		Write-Progress -Activity "Reading from NIST" -percentcomplete "-1" -status "$n hashes added to Hashtable" -Completed
		$timetaken = ((Get-Date) - $start).totalseconds
		Write-Host "$n hashes added to Hashtable in $timetaken seconds"
		$reader.Close()
		return $hashlist
	}

	####################### Processing functions:

	# Check Hashes against white/black list or NIST
	function check_Hash ($InputList, [HashTable]$badlist, [HashTable]$goodlist, [HashTable]$NISTlist) {
		foreach ($item in $InputList) {
			# Check Null item
			if ($item -eq $null) { continue }
			
			# Zero 'Check' field
			$item | Add-Member -type NoteProperty -name Check -value "Unknown" -Force
			
			#Begin Checks
			if ( ($item.Hash -eq "") -OR ($item.Hash -eq $null)) {
				
				# Items that cannot be checked but should be there (Idle Process, System, etc):
				if ( (($item.ProcessId -eq 0) -OR ($item.ProcessId -eq 4)) -AND ($item.Name -eq "")) {
					$item.Check = "Whitelist"
					continue
				}
				
				#Check smss.exe
				if ( ($item.ParentProcessId -eq 4) -AND ($item.Name -eq 'smss.exe') -AND ($item.PathName -eq $null) ) {
					$item.Check = "Whitelist"
					continue						
				}
				
			} else {
			
				#Check Hash against black/white lists or query NIST database
				if ($badlist.Contains($item.Hash)) {
					$item.Check = "Blacklist"
				}
				elseif ($goodlist.Contains($item.Hash)) {
					$item.Check = "Whitelist"
				} 
				elseif ($NISTlist.Contains($item.Hash)) {
					#query NIST database
					$item.Check = "NIST"
				}
			}
			
			# Check Path
			if ( ($item.Check -eq "Unknown") -AND ($item.PathName -ne $null) -AND ($item.PathName -ne "") ) {
			
				#Check Pathnames if no hash (not to be fully trusted but can flag)
				if ($badlist.Values -contains $item.PathName) {
					$item.Check = "BadPath"
				}
				elseif ($goodlist.Values -contains $item.PathName) {
					#Indicates known path and file, but no hash in database
					$item.Check = "GoodPath"
				}
			}
			
		} #End Foreach
		
	}

	# Check Signatures from Arma's Sigcheck
	function check_Signature ($InputList, [HashTable]$ArmaSigCheck) {
	
		foreach ($item in $InputList) {
			if ($item -eq $null) { continue }
			
			$item | Add-Member -type NoteProperty -name Signature -value "N/A" -Force
			
			if (($item.PathName -ne $null) -AND ($ArmaSigCheck.ContainsKey($item.PathName))) {
				$item.Signature = $ArmaSigCheck[$item.PathName]
			}
		}
	}
	
	#Check signatures from Autorunsc.
	function check_SigVerify ($InputList, [HashTable]$SigVerify) {
	
		foreach ($item in $InputList) {
			if ($item -eq $null) { continue }
			
			$item | Add-Member -type NoteProperty -name Signature -value "N/A" -Force
			
			if (($item.Hash -ne $null) -AND ($SigVerify.ContainsKey($item.Hash))) {
				$item.Signature = $SigVerify[$item.Hash]
			}
		}			
	}

	# Process Connections against Bad_IPs list
	function Check_Connections ($ProcessList, $Netstat, [HashTable]$badIPs) {
		foreach ($cnx in $Netstat) { 
			$process = $ProcessList | where { $_.ProcessId -eq $cnx.ProcessId}
			
			# Assign process's check
			$cnx | Add-Member -type NoteProperty -name Check -value $process.Check -Force
			$cnx | Add-Member -type NoteProperty -name ProcessName -value $process.Name -Force
			$cnx | Add-Member -type NoteProperty -name CheckIP -value "Unknown" -Force
			
			# Check IPs against IP Blacklist
			if (($cnx.Src_Address -ne $null) -AND ($badIPs.ContainsKey($cnx.Src_Address))) {
				$newcnx.CheckIP = "Bad"
			}
			if (($cnx.Dst_Address -ne $null) -AND ($badIPs.ContainsKey($cnx.Dst_Address))) {
				$newcnx.CheckIP = "Bad"
			}
			
		}
	}



	#################### MAIN ##############################

	if ($Help) { Display_Help }
	
	# Import White and Black Lists ==============
		#Import White Lists
	Write-Verbose "Loading whitelists..."
	$whitelist	= get_Hashlist $ScriptPath\lists\whitelist.csv
	
	#Import Black Lists
	Write-Verbose "Loading blacklists..."
	$blacklist	= get_Hashlist $ScriptPath\lists\blacklist.csv
	
	$bad_IPs = @{}
	try { $IPs = gc $ScriptPath\lists\bad_IPs.txt } catch { Write-Error "Cannot find Bad_IPs.txt" }
	$IPs | foreach { $bad_IPs.Add($_,[int]0) }
		
	if (!$noNIST) {
		Write-Host -Foreground "Cyan" "Loading NIST Database..."
		if ($Hashtype -eq "MD5") {
			"Loading NIST MD5 Database - {0:N2} MB" -f ((Get-ItemProperty -path $ScriptPath\lists\NIST_MD5.txt).length/1000000)
			$NIST = get_NIST $ScriptPath\lists\NIST_MD5.txt
		} else {
			"Loading NIST SHA-1 Database - {0:N2} MB" -f ((Get-ItemProperty -path $ScriptPath\lists\NIST_SHA1.txt).length/1000000)
			$NIST = get_NIST $ScriptPath\lists\NIST_SHA1.txt	
		}	
	} else {
		$NIST = @{}
	}
	
	$n = 0
}

PROCESS {
	foreach ($PathName in $PathNames) {
		# Check inputs:
		if (($PathName -eq "") -OR ($PathName -eq $null)) {Write-Verbose 'Path to Survey HostObject was not specified';break}
		if ($PathName -notlike "*$SurveyFileName") { Write-Verbose 'Specified item is not a Survey HostObject or bad input format';break }
		if (Test-Path -pathtype Container -Path $PathName) {Write-Verbose 'Path to Survey HostObject is a container';break}
		
		$n += 1
		Write-Host "($n): Processing $PathName"	
		# Write-Verbose "($n): Processing $PathName"	
		"<$datestamp> Processing $PathName with options Reprocess: $Reprocess, NIST: $NoNIST." >> $logfile
		
		#Test if already processed
		if ($Reprocess -OR !(Test-Path $PathName\..\Processed.txt)) {
			# Import host Objects
			Write-Verbose "Importing $PathName"
			$HostObject = Import-Clixml $PathName
			
			# Sanity check for HostObject of proper version
			if ( ($HostObject.ObjectType -ne "Helix_HostObject") -OR ($HostObject.Version -ne $version) ) {
				Write-Verbose "($n): Not a HostObject with version: $version. Skipping"
				"<$datestamp> ($PathName): Not a HostObject with version: $version. Skipping" >> $logfile
				break
			}
			if (($HostObject.ObjectStatus -ne "Unprocessed") -AND !($Reprocess)) {
				Write-Verbose "($n): Already processed. Skipping"
				"<$datestamp> ($PathName): Already processed. Skipping" >> $logfile
				break
			}
			
			# Get uniques from ArmaSigCheck
			$Arma = @{}
			$HostObject.ArmaSigCheck | Sort-Object Hash -unique | foreach {
				if ($_.Signature -like "Valid*") {
					$sig = "Verified"
				} 
				elseif ($_.Signature -like "Invalid*") {
					$sig = "Invalid_Signature"
				}
				else {
					$sig = "N/A"
				}
				$Arma.Add($_.PathName, $sig)
			}
			
			$SigVerify = @{}
			$HostObject.Autoruns | Sort-Object Hash -unique | foreach {
				if ($_.Publisher -like "(Verified)*") {
					$sig = "Verified"
				} 
				elseif ($_.Publisher -like "(Not Verified)*") {
					$sig = "Invalid_Signature"
				}
				else {
					$sig = "N/A"
				}
				$SigVerify.Add($_.Hash, $sig)
			}

			# process ProcessList
			Write-Verbose "Processing ProcessList..."
			check_Hash $HostObject.ProcessList $blacklist $whitelist $NIST
			check_Signature $HostObject.ProcessList $Arma
			
			# process ModuleList
			Write-Verbose "Processing loaded DLLs..." 
			check_Hash $HostObject.ModuleList $blacklist $whitelist $NIST
			check_Signature $HostObject.ModuleList $Arma

			# process ServiceList
			Write-Verbose "Processing Services..."
			check_Hash $HostObject.ServiceList $blacklist $whitelist $NIST
			check_SigVerify $HostObject.ServiceList $SigVerify
			
			# process DriverList
			Write-Verbose "Processing Drivers..."
			check_Hash $HostObject.DriverList $blacklist $whitelist $NIST
			check_SigVerify $HostObject.DriverList $SigVerify
			
			# Process NetStat
			Write-Verbose "Processing connections..."
			Check_Connections $HostObject.ProcessList $HostObject.NetStat $bad_IPs
			
			# Process Autostart					
			Write-Verbose "Processing Autostarts..."
			$Startups = $HostObject.Autostart.Startups	
			check_Hash $Startups $blacklist $whitelist $NIST
			check_SigVerify $Startups $SigVerify
			$HostObject.Autostart.Startups = $Startups

			# Process Autoruns
			Write-Verbose "Processing Autoruns..."
			check_Hash $HostObject.Autoruns $blacklist $whitelist $NIST
			check_SigVerify $HostObject.Autoruns $SigVerify

			$HostObject.ObjectStatus = "Processed"	
			$HostObject.DateProcessed = Get-Date
			
			(Get-Date) >> $PathName\..\Processed.txt
			Write-Verbose "Updating $PathName"		
			$HostObject | Export-CLIXML -Encoding "UTF8" $PathName -Force
			
		} else {
			Write-Verbose "HostObject has already been processed, skipping"
			"<$datestamp> ($PathName): processed.txt exists in $PathName\..\ - Skipping" >> $logfile
		}
		
	}
}

END {
	# After complete
	write-verbose "Processing Complete"
	if ($PSBoundParameters['Debug']) { Wait }
	return
}