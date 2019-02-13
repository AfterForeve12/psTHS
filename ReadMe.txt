Name: psTHS - Powershell Threat Hunter Survey
====================================================================================================================
Instructions
====================================================================================================================
Note: All execution should be from an administrator Powershell prompt.  scan_targets_multi3.py should be run by first typing cmd to gain a standard command prompt.
Note: Powershell by default blocks the execution of scripts now. 
	So run from admintrator powershell.
		 PS > set-executionpolicy bypass
Note: Execute-RemoteTask will create a folder in the .\OPDATA folder for every target it attempts to scan.  Survey Analyzer will report all failed scans in a text file by
counting the number of folders with no HostObject XML file in it.


Deploy psTHS Scripts to single target:
===========================
Note: With all scripts there is a -Verbose option that is recommended till you understand what the script is doing.
Deploy:
PS > .\Execute-RemoteTask.ps1 <hostname/IP> 

...Query remote host using schtasks ("Ready" = done):
PS > schtasks /query /s <hostname/IP> /tn psTHS_task

Collect Output (wait 10 minutes or query remote host using schtasks):
PS > .\Execute-RemoteTask.ps1 <hostname/IP> -Pickup 


Deploy psTHS Scripts to multiple targets (single threaded - small scope):
===========================
Pipe targets in from targets.txt (single threaded):
PS > Get-Content targets.txt | .\Execute-RemoteTask.ps1

...Wait 10-20 minutes... or poll status via schtasks query:
PS > Get-Content targets.txt | % { schtasks /query /s $_ /tn dcc_task }

Note: (% = "foreach")
Note: ($_ = your iterator, aka current target)


Collection: 
PS > Get-Content targets.txt | .\Execute-RemoteTask.ps1 -Pickup


Deploy psTHS Scripts to multiple targets (threaded - wide scope):
===========================
Note: Load up your live hosts into targets2.txt
Note: Run python from cmd prompt rather than powershell prompt

Use python scan_targets_custom script to deploy to large target set (n threads):
C:\> scan_targets_helix_multi3.py Execute-RemoteTask.ps1 -n 32

...Wait 10-20 minutes... Do not try to ask status, it'll just take forever

Collect output using python scan_targets_custom script (n threads):
C:\> scan_targets_helix_multi.py Execute-RemoteTask.ps1 -a "-Pickup" -n 24




Process/Display single HostObject:
===========================
Note: Analyze-psTHS.ps1 actually calls Process-Survey.ps1 in the background if you haven't already processed a survey or if you select -Reprocess

PS > .\SurveyAnalyzer.ps1 .\OPDATA\hostname\HostSurvey.xml



Process/Display multiple HostObjects into a BaseObject (enclave):
===========================
Note: Will recursively enumerate every HostSurvey.XML file in specified OPDATA folder.  
Note: Process-Survey.ps1 takes a while for a lot of hostobjects (ex. 1000)

PS > .\Analyz-psTHS.ps1 -StartOp .\OPDATA

Pro Tip: Put all collected data in a specific date/enclave/company folder if you want to make sure only those hosts make it into the BaseObject



====================================================================================================================
====================================================================================================================
====================================================================================================================
Alternative uses:


Local Host Execution of Survey Script:
===========================

PS > .\Survey.ps1


Local Host Execution of Arma (VQuery.ps1) Script:
===========================

ARMAMALFIND:
Find RWX memory sections bigger than 12KB and print out first 16 bytes:
PS > .\VQuery.ps1 -ExecutableOnly -WriteableOnly -NoImages -MinSize 12 -Verbose 

Same command but output to a text file:
PS > .\VQuery.ps1 -ExecutableOnly -WriteableOnly -NoImages -MinSize 12 -Verbose -OutFileName outfile.txt

ARMASIGCHECK:
Verify signatures on dlls/exes that have executable memory sections bigger than 12KB:
PS > .\VQuery.ps1 -ExecutableOnly -ImagesOnly -MinSize 12 -VerifySignatures

ARMAIMAGE:
Compare disk images of running executables/DLLs to their memory representation:
PS > .\VQuery.ps1 -ImagesOnly -Modified 0.20 

Other capabilities:
Dump raw process memory from specified process ID for further analysis:
PS > .\VQuery.ps1 -procid 356 -DumpPath "C:\dumppath"

Print all ASCII strings from process memory of specified process ID:
PS > .\VQuery.ps1 -procid 365 -GetStrings