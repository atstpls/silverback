# Practical Security

The ultimate practical guide to security 

- [Workstation Security](#workstation-security)
    - [Files](#files)
    - [Processes](#processes)
    - [Network Connections](#network-connections)
    - [Logs](#logs)
    - [Checks](#checks)
- [Network Security](#network-security)
    - [Firewall](#firewall)
- [Web Application Security](#web-application-security)
- [Cloud Security](#cloud-security)
- [Wireless Security](#wireless-security)

<br>

- [Hunting and Detections](#hunting-and-detections)
- [Triage and Incident Response](#triage-and-incident-response)
- [Artifacts and Analysis](#artifacts-and-analysis)
- [Adversary Behavior](#adversary-behavior)

<br>

- [Windows Environments](#windows-environments)
- [Linux Environments](#linux-environments)
- [News and Training](#news-and-training)

<br>

## Workstation Security 


Code and Data
Simple HACKED program that represents untrusted code 



- [Access](#access)
- [Files](#files)
- [Processes](#processes)
- [Network Connections](#network-connections)
- [Logs](#logs)
- [Checks](#checks)


<br>

### Access 

Add-Type -AssemblyName System.Speech
$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
$speak.SelectVoice('Microsoft David Desktop')
$speak.Rate = +2
$speak.Speak("$phrase")

"Fasten your seatbelts..."

1. PowerShell 

"Let's start with the filesystem.  All files on this computer are a combination of code and data"

"There are many ways to interact with this filesystem but we're going to use an interactive shell called PowerShell because it's faster and easier."

"To open up a new PowerShell terminal, press Windows+R, type in powershell, and press Enter."

"Files that are code are called programs.  Let's run a program called Calculator."

"Starting the Calculator program opens it up in a new window."

"Switch back to PowerShell with Alt-Tab"

"We can use another program called tasklist to see that the Calculator program is running and who is using it"

"And another program called taskkill to terminate the Calculator program"

"These are old command line programs and each one has their own way of doing things.  An easier and faster way to get information about the system is to use PowerShell cmdlets."

"Lets start the calculator program again. This time use Get-Process to see the process.  And then pipe it to the Stop-Process to kill it."

"PowerShell is an object oriented scripting language as well so another way would be to start the program, capture the process object into a variable, and call a method to kill it."   

"PowerShell replaces hundreds of legacy tools and lets you quickly gather information about a Windows system."

"Files that are data are used to store information.  For example, text editor programs are used to open and read text files."

"We'll open up the VS code program and create a new text file called nothing2seehere.txt and add some data to it."

"I'll save it in the home directory.  We'll use this to simulate some important information that's stored on this computer."

"Now let's go over the most basic way you can get yourself hacked.  You leave the room without locking your computer and anyone with access to the room can run code on it."

"It only takes a few seconds for hackerman to run a quick one-liner on your system which searches your system for important information, finds it, and taunts you with it."

"Security lesson number one.  Never leave your computer unattended. Lock it or log off... otherwise there's nothing in place to prevent this"

"Now let's see what happened... open up PowerShell terminal and press the up arrow to see the last command that was run."




PowerShell - Intro, questions to answers, getting packages, using functions 

"We will be like water and calmly navigate around any obstacles in our way." 




Environment variables, aliases, 
Authentication    password, cert?
Lock Screen, wireless, suspend, hibernate, PowerShell
accounts and privileges    admin/root, user, service, groups, sudo  
USB 


### Files 

Text Editors, vscode, notepad  
Code and data 
scripting and languages 
Trusted code , verifying with signatures/hashes 
Encryption   disk, file 


### Processes 

Code and data
Trusted processes 
Untrusted processes, verifying with signatures/hashes
Abusing trusted processes


### Network Connections 

Services 
Ports 
Trusted network connections 
Incoming/Outgoing 
HTTP, HTTPS,  
SSH/PSremoting   certificate authentication 

### Logs 

Security
PowerShell

### Harden 

Implement
- Least privilege  for users, processes, 


|Mitigation|Description|
|-|-|
|[Least Privilege](#least-privilege)|Limit access to only information and resources necessary for normal operation|
|[Multi-factor Authentication](#multi-factor-authentication)|Requiring two or more factors to confirm an identity|
|[Daily Backups](#daily-backups)|Maintaining copies of system files and data at least every day|
|[Credential Hygiene](#credential-hygiene)|Proper creation, protection, and handling of passwords and password hashes|
|[Application Whitelisting](#application-whitelisting)|Allow and deny drivers, programs, and scripts from running based on characteristics|
|[Patch Management](#patch-management)|Keep operating system and applications at latest versions|
|[Disable Untrusted Office Features](#disable-untrusted-office-features)|Disable features that can run untrusted code such as Macros, OLE Object Execution, ActiveX, DDE|
|[Disable AutoRun-AutoPlay](#disable-autorun-autoplay)|Prevent applicatons from automatically executing when a device is plugged into the computer|


## Network Security 

Host to Router to Internet 
Diagram showing paths
Tools such as ping, tracert, traceroute, ping  

Layer 2 - Ethernet
Layer 3 - IPv4, IPv6, 
Layer 4 - TCP/UDP 
Layers 5-7 - DNS, WHOIS, OSINT 


Encrypted traffic, VPN, proxy tunnels 
reverse tunnels 
Tor 

Remote code, git


Implement:
- Least privilege - firewall rules ?  hosts file ? control incoming traffic , encrypt all traffic 


## Web Application Security 

Least privilege, run with nonroot 

Email client 
Browser, plugins 
Password manager 
AppArmor 
Remote logging, backups 
encryption (segregate sensitive data to encrypted disk and leave OS root partition unencrypted)

Load balancing 

Server languages 

Databases MySQL PostGres



## VMs and Containers 



