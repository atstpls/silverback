# Interview Questions 

- [Endpoint Security](#endpoint-security)
- [Network Security](#network-security)
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
<br>


## Endpoint Security

1.  a) What are your first three steps when hardening a Windows workstation? 

    [answer](#hardening-a-windows-workstation)

    b) And a Linux server? 
    
    [answer](#hardening-a-linux-server)

2.  Name some ways a user browsing the Internet can reduce their attack surface?

    [answer](#reducing-attack-surface)

3.  Name some ways JavaScript can be used to execute malicious code?

    [answer](#malicious-javascript)

4.  a) Explain the differences between VMs and Docker containers?

    [answer](#vms-and-docker-containers)
    
    b) What are some pros and cons of using Docker Containers?
    
    [answer](#pros-and-cons-of-containers)

    c) What are some security concerns of Docker containers?

    [answer](#security-concerns-of-containers)

5.  a) How do you change your DNS settings in Windows? 

    [answer](#changing-dns-settings-in-windows)

    b) How do you change your DNS settings in Linux?  
    
    [answer](#changing-dns-settings-in-linux)

 
6.  What’s the difference between encoding, encryption, and hashing?  

    [answer](#encoding-encryption-hashing)

7.  What is salting, and why is it used?

    [answer](#salts-and-slow-hashes)

8.  a) Why are Windows portable executables (PE) signed?

    [answer](#digital-signatures)
    
    b) How are Windows portable executables signed?

    [answer](#windows-pe-digital-signatures)

    c) How would you verify a Windows PE is signed?
    
    [answer](#verifying-windows-pe-digital-signatures)
   

<br>
<br>


## Network Security 

1. What port does ping work over?  

    [answer](#ping)

2. a) How does tracert work at the protocol level?

    [answer](#how-tracert-works)

   b) How does traceroute work at the protocol level?
    
    [answer](#how-traceroute-works)

3.  What is the difference between a proxy tunnel and a VPN tunnel?

    [answer](#proxy-and-vpn-tunnels)    

4.  a) What are ads, trackers, and script servers?

    [answer](#ads-trackers-and-script-servers)
    
    b) Name and describe the different methods browsers are used to track user activity?
    
    [answer](#tracking-techniques)
    
    c) What are some tools that can be used to block ads, trackers, and script servers?
    
    [answer](#blocking-ads-trackers-and-script-servers)


5.  a) Explain how a system resolves a DNS name?

    [answer](#resolving-a-dns-name)
    

6.  What’s more secure, SSL, TLS, or HTTPS?  

    [answer](#ssl-tls-https)


7.  Explain how smart cards, Active Directory, and Kerberos work together to authenticate clients on a domain?

    [answer](#authentication-using-smart-cards-and-kerberos)

8.  You plug in your network cable and run a Unix traceroute to twitter.com. How many packets were required to complete this?

    [answer](#traceroute-to-twitter)

    
<br>
<br>


## Web Application Security 

1.  Name some common web application attacks?

    [answer](#web-application-attacks)

2.  a) What is Cross-Site Request Forgery?

    [answer](#cross-site-request-forgery)

    b) How do you defend against CSRF?

    [answer](#common-defenses-against-csrf)

    c) How do you look for CSRF attacks?

    [answer](#csrf-detection)

3.  a) Explain Cross Site Scripting?

    [answer](#cross-site-scripting)

    b) Explain the different types of Cross Site Scripting (XSS)?

    [answer](#cross-site-scripting-types)
    
    c) What are the common defenses against XSS?
    
    [answer](#common-defenses-against-xss)

    d) How do you look for XSS attacks?

    [answer](#xss-detection)
    
4.  Explain the difference between Cookie-based and Token-based session management?

    [answer](#cookie-and-token-session-management)
    
5.  a) Name and describe different methods used for authenticating to a web application?

    [answer](#web-authentication)
    
    b) Name some challenges associated with web authentication and how they've been addressed over time?

    [answer](#web-authentication-challenges)

6.  Name the different ways an adversary can gain unauthorized access to a web service?

    [answer](#unauthorized-access-to-web-service)


<br>

## Cloud Security

1.  a) Name some cloud assets that could be the target of reconnaissance if public?

    [answer](#targeted-cloud-assets)
    
    b) If resources were inadvertently made public, what would be some next steps to mitigate impact?
    
    [answer](#assessing-the-impact-of-exposed-resources)
    
    
2.  Name some best practices for cloud accounts?

    [answer](#cloud-account-best-practices)

<br>
<br>

## Wireless Security


1.  What are some types of wireless security and some concerns with each?

    [answer](#wireless-security-types)
    
2.  Name and describe some ways a wireless network can be attacked?

    [answer](#wireless-attack-techniques)
    
<br>
<br>


## Hunting and Detections 


1.  a) Explain the traditional Incident Response cycle?

    [answer](#incident-response-cycle)
    
    b) Explain the traditional intelligence cycle?

    [answer](#intelligence-cycle)
    
    c) Describe an intelligence-driven IR cycle?

    [answer](#intelligence-driven-ir-cycle)

1. What are some hunting techniques you've found to be successful?

    [answer](#hunting-techniques)

    
2. Name and describe different types of detections?

    [answer](#detection-types)
    

3. a) Which detection types are most easily avoidable by advanced actors?

    [answer](#easy-to-avoid-detection-types)
    
   b) What are some problems associated with detections based on indicators and anomalies?
    
    [answer](#problems-with-indicators-and-anomalies)


4. Which detection types are the hardest to avoid by advanced actors?

    [answer](#hard-to-avoid-detection-types)


5. Give example detections based on threat behavior analytics?

    [answer](#threat-behavior-analytics)
    
6. Give example detections based on configuration changes?

    [answer](#configuration-changes)
    
7. Give example detections based on threat indicators?

    [answer](#threat-indicators)
    
8. Give example detections based on modeling?

    [answer](#modeling)


<br>
<br>

## Triage and Incident Response 

1.  a) What is the difference between DNS and WHOIS data?

    [answer](#dns-and-whois-data)
    
    b) How can each be used to support an investigation?
    
    [answer](#dns-and-whois-data-investigations)
    
1.  When investigating an endpoint during a possible incident, what are some key questions that need to be answered for an initial assessment?

    [answer](#interrogating-an-endpoint)

2.  How would you investigate a suspicious website?

    [answer](#investigating-suspicious-websites)
    
3.  How would you identify a "trojaned" file?

    [answer](#identifying-a-trojaned-file)

4.  What are some ways you could gather information about a rogue host?

    [answer](#gathering-information-about-a-rogue-host)

5.  Name some ways to evade whitelisting rules and run malicious code (EXEs, DLLs, scripts, shellcode) by using a trusted binary? 

    [answer](#whitelist-bypass-trusted-binaries)
    
6.  a) Name some common ways malware can persist on a Windows system?

    [answer](#windows-persistence-methods)

    b) Name some methods of persistence on a Linux system?
    
    [answer](#linux-persistence-methods)

7. Name some ways a phishing payload can lead to process injection?

    [answer](#phishing-to-injection)

8. Name some methods of authenticated remote code execution (RCE)?

    [answer](#authenticated-rce)

9.  What are some ways malware can indirectly communicate with its C2 server?

    [answer](#indirect-c2)
    
10.  Name some different ways C2 is utilized?

    [answer](#c2-functions)


<br>
<br>

## Artifacts and Analysis

1.  Give a short description of each phase in the Kill Chain?
    
    [answer](#kill-chain-phases)

2.  What are the general steps taken during malware analysis?

    [answer](#malware-analysis)

3.  Name some types of self-defending techniques used by malware?

    [answer](#malware-self-defending-techniques)

4.  Give a short definition of unmanaged PowerShell?

    [answer](#unmanaged-powershell)
    
5.  Name some examples of memory-only artifacts?

    [answer](#memory-only-artifacts)

6.  What are some things post-exploitation tools have in common?

    [answer](#advanced-post-exploitation-tools)

7.  Name and describe some common privilege escalation tools?

    [answer](#privilege-escalation-tools)

8.  a) Name several evasion techniques used on the network?

    [answer](#evasion-techniques-on-network)
    
    b) How are some ways we can identify the use of each?

    [answer](#identify-network-evasion-techniques)
    
9.  a) Name several evasion techniques used on disk?

    [answer](#evasion-techniques-on-disk)
    
    b) How are some ways we can identify the use of each?
    
    [answer](#identify-disk-evasion-techniques)
    
10.  Name some ways an adversary could exploit a host with an exposed Docker API?

    [answer](#exploiting-the-docker-api)
   
11.  Explain the differences between an adversary who has obtained single command execution, one who has obtained an interactive shell, and one who has deployed a post-exploitation agent on a victim system?

    [answer](#levels-of-code-execution)

12. Name some different ways to perform process injection?

    [answer](#process-injection)

13. Give a short description of WMI and explain how it can be used for persistence.

    [answer](#wmi-subscriptions)

14. Name the different ways to interact with the Windows API?

    [answer](#interacting-with-windows-api)

<br>
<br>


## Adversary Behavior

1.  Explain a general methodology used by an adversary attempting to compromise a system or network.

    [answer](#adversary-general-methodology)

2.  a) Name some ways an adversary can get an intial foothold on a system/network and control a low-privilge account?

    [answer](#foothold-methods)
    
    b) Name some ways an adversary can perform lateral movement?

    [answer](#lateral-movement-methods)
    
    c) Name some ways an adversary can obtain Domain Admin?
    
    [answer](#domain-admin-methods)
    
3.  a) Name some methods for privilege escalation on Linux?

    [answer](#privilege-escalation-on-linux)

    b) Name some methods for privilege escalation on Windows?
    
    [answer](#privilege-escalation-on-windows)

4.  Explain a general methodology used by an adversary attempting to compromise a web application?

    [answer](#general-adversary-methodology-web-application)
    
   
5. What are some ways an adversary with a low-privilege account can escalate privileges using Active Directory?

    [answer](#privilege-escalation-using-active-directory)
    
6. a) Name the scripting technologies used on Windows systems and the processes that host them?

    [answer](#windows-script-hosts)
    
    b) Give an example of how each is typically used by an adversary?
    
    [answer](#windows-script-malware)
    
7. What are batch files and how can they be used to support adversary operations?

    [answer](#batch-files)
    
8. What is VBScript/JScript and how is it used to support adversary operations?

    [answer](#vbscript-and-jscript)
    
9. What is VBA and how is it used to support adversary operations?

    [answer](#visual-basic-for-applications)
    
10. What is PowerShell and how is it used to support adversary operations?

    [answer](#powershell)
    
11. What are some ways a .NET Assembly can be injected into the memory of a target process?

    [answer](#injecting-a-dotnet-assembly) 



<br>
<br>

## News and Training

1. Who do you look up to within the field of Information Security? Why?

    [answer](#information-security-leaders)

2. Where do you get your security news from?

    [answer](#security-news-sources)

3. What kind of systems do you have at home or in the cloud to tinker with?

    [answer](#systems-to-tinker-with)

4.  a) Describe the last program or script that you wrote.

    [answer](#programs-and-scripts)


<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>


# Answers 

## Hardening a Windows Workstation

Any of the following:

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

<br>

## Hardening a Linux Server 


<br>

## Reducing Attack Surface 

- Use a password manager [Keepass](http://keepass.info/) [LastPass](https://lastpass.com/)
- Use a security/privacy-focused browser ([Tor Browser Bundle]())
- Use a VPN [NordVPN](https://go.nordvpn.net/aff_c?offer_id=38&aff_id=1764&url_id=633), [PIA](https://bit.ly/privateVPNanonymous), [ExpressVPN](https://bit.ly/exprvpnreview), [TorGuard](https://bit.ly/torguardvpn), [SlickVPN](https://www.slickvpn.com/#a_aid=570ec1e3eb913), [ProtonVPN](https://protonvpn.com/)
- Use a security/privacy-focused search engine ([DuckDuckGo](https://duckduckgo.com/), [Quant](https://www.qwant.com/), [StartPage](https://www.startpage.com/))
- Use a trusted DNS server [1.1.1.1](), [8.8.8.8]()
- Use an Ad blocker plugin [uBlock Origin](https://ublock.org), [Ghostery](https://www.ghostery.com/) or use hosts file
- Force HTTPS [HTTPS Everywhere](https://www.eff.org/https-everywhere)
- Block cookies, trackers [Privacy Badger](https://privacybadger.org/), [Decentraleyes](https://decentraleyes.org/), [Cookie AutoDelete](https://github.com/Cookie-AutoDelete)
- Block Flash [Flash Control]()
- Block WebRTC [WebRTC Blocking]()
- [Compartmentalization](https://medium.com/@privacyhivesoftware/why-compartmentalisation-is-the-key-to-protecting-your-online-privacy-b91d86482cd) - Using multiple browsers, profiles, VMs, containers, live OS, etc.

<br>

Check your browser with [Browser Leaks](https://www.browserleaks.com/) and your VPN with [WITCH](http://witch.valdikss.org.ru/)

<br>

[reference](https://gist.github.com/atcuno/3425484ac5cce5298932)

<br>






## Ads Trackers and Script Servers

- **Ads** are images, buttons, or HTML elements on a web page being served from a third party server for the purpose of advertising a product or collecting customer information 

- **Trackers** are scripts on third-party sites that collect and organize information about user browsing habits. This data is combined and mined to make user profiles so that personalized (targeted) ads can be served via ad networks (Adsense, Admob, and DoubleClick) that are embedded in millions of websites

- **Script servers** are used by third-party servers for many different purposes including tracking, serving ads, serving website content, or all of the above

<br>

## Tracking Techniques

|Technique|Description|
|-|-|
|Cookies|Set either by JavaScript (local storage) or by HTTP responses that include a Set-Cookie header. The browser stores the user-specific cookie which is retrieved and transmitted to third-party domains on future visits|
|Web bugs|Files or HTML elements embedded in a web page or email that force a client application to make a request containing identifying information to a third-party server. These can be images, graphics, banners, buttons, and other HTML elements such as frames, styles, scripts, input links, etc.|
|Fingerprinting|Passively collecting and profiling browser characteristics in order to distinguish and recognize individual browsers (and users). This technique uses User agent strings, screen resolution/depth, timezones, fonts, plugins and versions, etc. to create a signature that can be used to identify and track user activity across multiple websites|
|Supercookies|Also called *zombie cookies* --- any technology other than a standard HTTP Cookie that is used by a server to identify clients. Examples include Flash LSO cookies, DOM storage, HTML5 storage, and other methods of storing information in caches or etags|

<br>

## Blocking Ads Trackers and Script Servers

[Privacy Badger](https://www.eff.org/privacybadger), [uBlock Origin](https://www.ublock.org), [Ghostery](https://www.ghostery.com), and [NoScript]() are examples of tools that block third-party ads, trackers, and script servers and allow an analyst to control the execution of third-party scripts

<br>




## Resolving a DNS Name

A system resolves a DNS name by doing the following:

1. Local host name
2. DNS cache
3. Hosts file
4. DNS server
5. NetBIOS name cache
6. WINS server
7. Broadcast
8. Lmhosts file

<br>

## DNS and WHOIS Data

The Domain Name System (DNS) is a naming structure for online resources and mapping those names to the addresses where the resources reside.

The WHOIS database is a directory of the registered users for Internet resources such as domain names, IP address blocks, and autonomous systems (AS).


## Changing DNS Settings in Windows

|Method|Description|
|-|-|
|Control Panel|Change adapter settings| 
|Settings App |Change IP settings | 
| `netsh.exe` | `netsh interface ip set dns name="<adapter>" source=static address=8.8.8.8 index=1`|
| Powershell  |`Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 8.8.8.8`|
|`wmic`|`wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("8.8.8.8")`|

<br>

### Changing DNS Settings in Linux

|Method|Description|
|-|-|
| System Settings | Network > IPv4 Settings > DNS |
|`resolv.conf`| `echo nameserver 8.8.8.8 | sudo tee /etc/resolv.conf` |
| `dnsmasq.conf` | `echo server=/dns.google/8.8.8.8 | sudo tee /etc/dnsmasq.conf` |

<br>

## Encoding Encryption Hashing

|Term|Definition|
|-|-|
|Encoding|Transforms data into a different format using a publicly available scheme for the purpose of usability.  It is easily reversed |
|Encryption|Transforms data into a different format for the purpose of confidentiality.  A key is required to reverse |
|Hashing|Transforms a string of characters into a value of fixed length called a hash for the purpose of integrity.  One change in the string of characters will produce a different hash|

<br>

## SSL TLS HTTPS

They are all equally secure.  Secure Sockets Layer (SSL) is the old version of Transport Layer Security (TLS), essentially the same protocol which was designed to provide privacy and data integrity between two parties.  HyperText Transfer Protocol Secure (HTTPS) is a session where HTTP data is exchanged over an SSL/TLS connection.

<br>

## Salts and Slow Hashes 

These are countermeasures for password cracking:

Salts - an additional random string that is combined with a password when it's hashed to counter rainbow tables

Slow Hashes - hashing algorithms that are optimized to be slow to increase the time to crack

<br>


## Ping

Ping does not use ports. Ping uses Internet Control Message Protocol (ICMP) echo requests and echo replies which operate on Layer 3 of the OSI model.  Ports are used in TCP and UDP owhich operate on Layer 4.

<br>

## How tracert Works

`tracert` is a utility found on Windows systems that traces the route taken by network packets to reach a specific destination IP address.

1. An *ICMP echo request* is sent to a chosen destination with a Time to Live (TTL) value of 1
2. The first hop reduces the TTL by 1 (to zero) and sends back a TTL Time Exceeded message  
3. A second *ICMP* packet is sent to the destination, this time with a TTL value of 2
4. The second hop receives this packet, reduces the TTL by 1 (to zero) and sends back a TTL Time Exceeded message
5. A third *ICMP* packet is sent to the destination, this time with a TTL of 3

This process continues until a packet reaches the destination and a TTL Time Exceeded message is sent back to the source machine.  The output shows every hop that is made from source to destination. 

<br>

## How traceroute Works 

`traceroute` is a utility found on Linux systems that traces the route taken by network packets to reach a specific destination IP address.

1. A *UDP* packet is sent to a chosen destination with a Time to Live (TTL) value of 1
2. The first hop reduces the TTL by 1 (to zero) and sends back a TTL Time Exceeded message  
3. A second *UDP* packet is sent to the destination, this time with a TTL value of 2
4. The second hop receives this packet, reduces the TTL by 1 (to zero) and sends back a TTL Time Exceeded message
5. A third *UDP* packet is sent to the destination, this time with a TTL of 3

This process continues until a packet reaches the destination and a TTL Time Exceeded message is sent back to the source machine.  The output shows every hop that is made from source to destination. 

<br>

## Cross Site Request Forgery

Cross Site Request Forgery (CSRF) occurs when a malicious site, email, or other application causes a victim web browser to perform unwanted actions on a trusted site while the user is authenticated. 

Once authenticated to the target site, a browser can be made to send an HTTP request performing a state-changing transaction, such as a password change or a purchase, which will contain the user's session token. Since the request performing the change contains the user's session token, it will look similar to all the other legitimate requests the user has made during his authenticated session. The target site has no way of knowing the request actually came from the attacker.

<br>

## Cross Site Scripting

Cross Site Scripting (XSS) occurs when an attacker is able to cause a victim's browser to execute arbitrary JavaScript in the context of a legitimate website. JavaScript code can be injected into the browser and run to access cookies, tokens, geolocation coordinates, webcam data, and other sensitive information.

<br>


<br>

## Common Defenses Against XSS

Common defenses include sanitizing the data submitted by users via script tag removal, string replacements, regular expressions, and various escaping functions for special characters such as single quotes, double quotes, backslashes, and NULL bytes.

Also:

|Mitigation|Description|
|-|-|
|HttpOnly|Ensures client scripts cannot access cookies to mitigate XSS attacks|
|secure=true|Ensures cookies can only be set over an encrypted connection|
|Signed Cookies|Prevents clients from modifying cookies|


<br>

## Systems To Tinker With

This can be any kind of lab environment geared towards one of the following:

- investigating malicious sites and files
- security testing/operation of systems, applications, environments
- any one of the many [penetration testing practice and vulnerable app platforms](https://www.amanhardikar.com/mindmaps/Practice.html) available

<br>

## Traceroute to Twitter

The following packets are required for a successful traceroute to twitter.com:

|Step|Layer|Description|
|-|-|-|
|1||Application|HTTP, DNS, SMTP data|
|2|Transport|TCP, UDP segments|
|3|Internet|IP packets|
|4|Link|Ethernet frames|


<br>

## VMs and Docker Containers

A VM 

A Docker container is an instance of an application that contains the software and all its dependencies with its own runtime environment---its own filesystem, process listing, network stack, etc.  It shares the host's OS kernel instead of having its own and therefore is not as isolated as a VM.

## Pros and Cons of Containers

Pros:

- Separates code from data---store data on the underlying host, run application code in the isolated container
- You can quickly deploy an app, run it, then tear it down without losing customizations or data
- Security patches don't break the app and rebuilding an image automatically updates the application's dependencies
- Apps with conflicting dependencies can run on the same host since they are isolated
- Easier to control what data and software components are installed
- No unwanted files lying around after you finish analysis

Cons:

- Running multiple application instances with varying security patch levels
- Segregation is good but not as robust as virtual machines

<br>

## Windows Persistence Methods

|Method|Description|
|-|-|
|Startup Folder and Registry Keys|Programs in a user's Startup folder and registry Run keys will execute at user logon|
|Scheduled Tasks|Tasks can be created to execute a malicious program on system startup or at certain days and times|
|Accessibility Features|Accessibility features can be abused by an attacker to maintain access to a system|
|File and Folder Permissions|If a program uses a file or folder that has weak permissions, an attacker can overwrite a legitimate program file with a malicious one|
|Logon Scripts|A logon script can be configured to run whenever a user logs into a system|
|Shortcuts|A shortcut for a legitimate program can be modified and used to open a malicious program when accessed by a user|
|Service Registry Permissions|If an attacker can modify registry keys, the image path value of a service can be changed to point to a different executable|
|Service Permissions|If an attacker can modify a service, the binary path can be changed to any executable on the system|
|New Service|A new service can be created and configured by an attacker to execute at startup|
|Default File Associations|Default file associations determine which programs are used to open certain file types. These can be changed so that an arbitrary program is called when a specific file type is opened|

<br>

## Memory-Only Artifacts

Examples of memory-only artifacts:

|Type|Description|
|-|-|
|Residual data|Data from disconnected external media devices, previous boots, terminated shells, wiped event logs and browser history no longer available on disk|
|Volatile data|Registry keys manipulated directly in memory are not written to disk and can be used to track user activity or locate malware persistence|
|Network data|Evidence of proxy or port redirection, network share data, traffic traversing SSH/VPN tunnels, encrypted communications, connected wireless devices|
|Hidden services|Services can be running with no traces in event log, registry, or memory of services.exe, but running process, DLL, or kernel driver is still in memory|
|File data|Recently used files, deleted files, executable paths and timestamps allow evidence of file execution/knowledge, directory traversal|
|Application data|Data an application received over the network, decompressed and/or decrypted instructions in memory, encryption keys|
|Command History|Extract full console input and output, data from user/attacker sessions such as usernames, passwords, programs/files accessed|
|SIDs/Privileges obtained|User, group, and privilege information associated with user and attacker-controlled accounts and malicious processes|
|Malware-created artifacts|Parameters of the infection, C2 and exfiltration data, hidden files and processes, hooked drivers, injected code|
|Anti-forensic artifacts|Evidence of file wiper use, programs run from removable devices, event log modifying/deleting, resetting timestamps|
|Passwords|Plaintext passwords stored by OS/applications that may be reused on other systems/services, passwords for encrypted files and containers|

<br>

## Gathering Information About A Rogue Host

Here are some examples:

|Tool|Description|
|-|-|
|Splunk|Review logs for DHCP, DNS, HTTP traffic associated with the host|
|Wireshark|Network captures may contain traffic to/from the host that can assist in identification|
|Nmap|Scan ports and perform active OS/service fingerprinting on the host|

<br>

## Web Application Attacks


|Attack|Description|
|-|-|
|Path Traversal|Client is able to successfully request files on the server that aren't meant to be shared. This can be used to read or modify sensitive and critical files as well as execute code|
|Local File Inclusion|A webapp is tricked into retrieving and rendering files on the server.  This can be used to view files that contain sensitive data or execute files that contain code|
|Remote File Inclusion|A webapp is tricked into retrieving and rendering files hosted on a remote server. This can be used to execute arbitrary code on the server under the privileges of the web application|
|OS Command Injection|when an actor is able to submit arbitrary commands as part of user input that get executed by the application..  A webapp is tricked into executing arbitrary OS commands on the server. When the web application does not perform input validation on data supplied by the client, gets passed as an argument for an OS command.
|SQL Injection|SQL Injection (SQLI) is most commonly due to a lack of sanitized user input in HTML forms. When this happens, a user can dynamically affect the SQL statements being passed on to database and can possibly read, create, modify, and delete the data stored there. Common uses are to bypass authentication, enumerate and dump a database, and to execute code on the victim server|
|Cross-Site Scripting|Cross-Site Scripting (XSS) takes advantage of servers not encoding data properly and injects arbitrary HTML and JavaScript in order to run a payload in the user's browser. It can be used to steal a user's cookie and session info, bypass authentication, or redirect a user's browser to a malicious page|
|Brute Force Guessing|A brute force password attack tries every possible combination of letters, numbers, and special characters until the correct password is found|
|Dictionary Attack|A more realistic attack using either a custom or well-know password dictionary to guess valid credentials for a webapp|
|File Upload|A file upload vulnerability allows a user to write arbitrary files to the server, usually in the form of a web shell providing the ability to run system commands on the server|

<br>

## Privilege Escalation on Linux 

|Method|Description|
|-|-|
|File system|Setuid and Setgid, Dylib hijacking, modify plist, startup items/launch daemons|
|Configurations|Sudo commands, wildcards, modify job, new job|
|Discover credentials|User files, installation/configuration files|
|Password attack|Guess or brute force local admin password|
|Local exploit|OS or application|

<br>

|Sudo commands|Using a program that can be run in an elevated context to spawn a command shell (or some other action) which is also executed in an elevated context|
|SUID/SGID Permissions|If an executable has SUID permissions, a non-privileged user can execute it in the context of the owner of the program. If the executable has SGID permissions, a non-privileged user can execute it in the context of the group|
|Wildcards|If a program references a wildcard (`/tmp/*.sh`)that the adversary has permission to write to, an executable script can be made to be included in the wildcard (`/temp/script.sh`) and will be executed in an elevated context along with the others that match the wildcard|

<br>

## Privilege Escalation on Windows

|Method|Description|
|-|-|
|File system|Path interception, DLL Hijack, modify service, new service|
|Registry|AlwaysInstallElevated, autologons, autoruns|
|Configurations|Modify task, new task|
|Discover credentials|User files, installation/configuration files|
|Password attack|Guess or brute force local admin password|
|Local exploit|OS or application|

<br>

|Unquoted Service Paths|When the path to a service's binary is not enclosed in quotes, the service path can be hijacked and made to run an arbitrary executable in an elevated context|
|DLL Order Hijacking|If a program's file path has weak file or folder permissions, a low-priv user can place a malicious DLL in one of several different places where it may be found and loaded by the vulnerable program in an elevated context|
|Auto-Elevation|If the `AlwaysInstallElevated` registry keys are present on the system and their value is "1", an low-priv user can install a program in an elevated context|

<br>

## Foothold Methods

|Method|Description|Example|
|-|-|-|
|Server exploit (external)|External service compromised by external host|Cloud,OnPrem,Third-Party|
|Server exploit (internal)|Internal service compromised by internal host|Internal service/apps|
|Client exploit (external)|Client app exploited by external host|Browser, Java, PDF reader, Flash, MS Office|
|Client exploit (internal)|Client app exploited by internal host|ARP poisoning, DNS cache poisoning, WPAD|
|User-driven (external)|User is tricked into running malicious code|Java applet, Office macro, zip file, executable, HTA, script, etc.|
|User-driven (internal)|User is tricked into running malicious code|Program, script, UNC path|
|Physical items|Device is used to execute malicious code|USB devices, CDs, external drives|
|Physical access|Adversary/Insider executes malicious code|Unlocked computers, unsecured devices|

<br>

## Lateral Movement Methods

|Method|Description|Tool|
|-|-|-|
|Remote session|Use stolen or created credentials to create session|PS Remote, PSExec, RDP, Pass-the-Hash/Pass-the-Ticket, VNC, SSH|
|Remote code execution|Use stolen or created credentials to execute code|Invoke-Command, WMIC, Psexec, at, schtasks, sc|
|Remote file copy|Use stolen or created credentials to copy files|scp, rsync, ftp, cifs, sftp, Logon scripts/hooks, Admin shares, shared drives, DLL preloading, shortcut hijacks|
|Removable media|Execute code via USB, CD, other external media|Rubber Ducky/HID, autorun|
|Third-party software|Use a tool account’s privileges to access a remote host|Nessus, Mcafee, FireEye, SCCM|

<br>

## Domain Admin Methods

|Method|Description|Tool|
|-|-|-|
|Steal token/hash/ticket|Keylog or dump credentials from DA logins (RunAs, RDP)|Mimikatz, Windows Credential Editor|
|Logon DC with other admin account|Dump all domain credentials|Mimikatz, Task Manager, NTDS.dit|
|Forge token/hash/ticket|Create fake/forged credentials|MS14-068|
|Password attack|Offline cracking|Kerberoast|
|Discover credentials|Installation/configuration files|SYSVOL, GPP|

<br>


## Identifying a Trojaned File

Hash	used to verify the file's integrity
Digital Signature	used to verify the publisher's identity

Code signing does not tell you whether the file is malicious or not, it only confirms the identity of the publisher and if the code has been modified.

Digitally signed code is backed by a certificate issued by a trusted third party (CA)

Unsigned code may include publisher data but if it doesn't provide any evidence of origin or file integrity, we cannot trust that it is what it says it is

Time-stamp signing allows code to be trusted after a private key is compromised or the certificate is revoked.  It proves the certificate was valid and trusted at the time of the timestamp.

<br>

## Malware Self-Defending Techniques

|Category|Description|
|-|-|
|Packer|compresses a file's original data to conceal information such as strings and imports|
|Crypter|uses obfuscation and encryption to hide information such as file paths, URLs, shellcode, etc.|
|Protector|uses anti-analysis techniques such as anti-debugging, anti-virtualization, anti-dumping, and anti-tampering to prevent reverse engineering and analysis|

<br>

## Kill Chain Phases

|Phase|Description|
|-|-|
|Reconnaissance|Researching the target, scanning, passive recon|
|Weaponization|Preparing a tool for use in intrusion, exploit in PDF, phishing site|
|Delivery|Threat delivers capability to target environment, email with malicious PDF|
|Exploit|Vulnerability or functionality exploited to gather data/gain access|
|Installation|Functionality is modified or installed to maintain persistence|
|Command & Control|Enables threat to interact with target environment|
|Actions on Objectives|Threat works toward its desired goal, exfil, monitoring|

<br>

## Whitelist Bypass Trusted Binaries

|Binary|Technique|
|-|-|
|powershell|Reflective loading to load and run scripts, EXEs, or DLLs from memory rather than from disk|
|cmd|Piping output to `cmd.exe -k`|
|mshta|Running HTML Application (HTA) files which use JavaScript or VBScript to execute arbitrary code|
|regsvr32|Running a scriptlet that contains arbitrary JavaScript code|
|rundll32|Runs DLLs and scripts by passing the binary a script/entry point as an argument|
|MSbuild|Provide an XML project file containing JavaScript, VBScript, or .NET assemblies|
|InstallUtil|command line utility that can be used to run .NET executables|
|IEExec.exe||
|regsvcs.exe||
|regasm.exe||
|BGinfo.exe||
|MSDT.exe||
|PresentationHost.exe||
|dfscv.exe||
|cdb.exe||
|dnx.exe||
|rcsi.exe||
|csi.exe||
|msxsl.exe||
|msiexec.exe||
|cmstp.exe||
|xwizard.exe||
|fsi.exe||
|odbcconf.exe||

<br>

## Unmanaged PowerShell

Executing PowerShell functionality without using a traditional PowerShell process (`powershell.exe`, `powershell_ise.exe`). A common way to do this is to use .NET assemblies and libraries to create a custom PowerShell runspace in which to execute PowerShell scripts.

<br>

## WMI Subscriptions

WMI is an administration tool that is used to query, change, and manage the components that make up the operating system. It uses classes and objects to represent different OS components such as processes, file systems, and registry keys.

Event Subscriptions are a group of WMI classes contained within the root\subscription namespace that can be used to respond asynchronously to almost any OS event.

There are three components involved:

|Component|Description|
|-|-|
|Event Filters|Represent an event of interest to alert on when certain conditions exist|
|Event Consumers|Contain the actions to be performed when an event of interest is observed|
|Filter-Consumer Bindings|Bind a Filter to a Consumer, linking the trigger event with the action to be performed|

<br>

## Interrogating an Endpoint

An initial assessment requires answering some basic questions about the system, the most common ones being:

1. What network connections is the host making?
2. What processes are currently running on the host?
3. What users are active on the system?
4. What files have been recently created, modified, or accessed?
5. Have any persistence methods have been configured on the host?

<br>

## Digital Signatures

On Windows 7 and later versions, all native PE files, including EXEs and DLLs, that are running in processes, device drivers, and services should be signed by Microsoft.

A file signed with a valid, trusted certificate confirms **authenticity** and **origin**:

1. Microsoft signs a file to prove it is authentic
2. Microsoft signs a file with their private key to prove it came from Microsoft

<br>

## Windows PE Digital Signatures

Windows PE files are signed in one of two ways:

1. Embedded - A digital signature (Microsoft uses Authenticode) is embedded inside the PE
2. Catalog - A hash of the PE can be found in a security catalog (.CAT) file

<br>

## Verifiying Windows PE Digital Signatures

Embedded signatures are placed at the end of the signed file and can be verified various ways such as `Get-AuthenticodeSignature`, `sigcheck.exe`, `signtool.exe`, `DigiCertUtil.exe`, `explorer.exe`, and others.

Catalog-signed files do not have an embedded digital signature so they may not pass verification on all the tools above.  Verifying them on Windows 7 hosts requires a tool such as SysInternals `sigcheck.exe` which looks up the Authenticode hash of the file in its associated catalog file and verifies the signature of the catalog file.

<br>

## Indirect C2 

Indirectly communicating with a C2 server requires placing some type of asset between the victim and the C2 server to obscure the identity and location of the C2 server as well as circumvent proxy restrictions.

|Method|Description|
|-|-|
|Domain Fronting|Uses the front end servers of CDNs such as Amazon, Google, Microsoft Azure to relay C2 traffic|
|Third Party Services|Uses webmail, cloud storage, and social media platforms to relay traffic to/from the C2 server|
|Redirectors|This could be an EC2 micro instance or server at any location whose only job is to pass on traffic it receives to/from the C2 server
|DNS C2|Hostnames from a domain an attacker controls are passed to various DNS servers to be resolved.  The requests and responses contain C2 traffic|

<br>

## Proxy and VPN Tunnels

Proxy tunnels (HTTP, SOCKS, etc) pass Layer 4 (TCP/UDP) traffic to/from the source and destination. An application on the source machine works with an application on the proxy host creating a tunnel that passes Layer 4 traffic between the two.

VPN tunnels	pass Layer 2 (ETH) traffic between two systems or networks. A network interface on one system is bridged to the network interface on another system creating a tunnel that passes Layer 2 traffic between the two.

<br>

## C2 Stealth and Resilience 

C2 is more stealthy and resilient when the C2 servers use [redirectors](#redirectors) and are [segregated by function](#segregated-by-function).

### Redirectors

With advanced C2 infrastructure, implants are provided with multiple redirectors for calling home, none of which are the actual C2 servers.  This allows attack operations to continue in the event a domain/IP is discovered and blocked by defenders.  If one redirector is blocked, another is used and the implants can continue to check in and receive tasks from their C2 servers.

Redirectors also obfuscate the identity and location of the actual C2 servers using domain fronting, third party services, or stand-alone serverw whose only function is to relay traffic between the victim and C2 server.  Even if the redirectors are discovered and located, the true location of the C2 servers remains hidden.

### Segregating by Function 

Advanced C2 infrastructure utilizes different C2 servers for hosting payloads, interactive operations, and maintaining persistence.

|Function|Description|
|-|-|
|Staging|Hosts the payloads for client-side attacks and initial callbacks|
|Operations|Used for interactive operations, installing persistence, expanding foothold, and performing actions on objectives|
|Long-haul|Maintains long-term access to the victim. Uses low and slow callbacks such as a single DNS A record request for a different domain once or twice a week. In case a C2 server is burned, or implant fails or is terminated, this is used to regain control of the victim|

<br>

A compromise may involve a payload request to `badsite.com` but be controlled by domain fronting C2 via HTTPS to `cloudhoster.com`. If you verify the payload was downloaded from `badsite.com` (Staging) and are looking for C2 traffic to `badsite.com`, you won't find anything. If you happen to find the C2 via domain fronting through `cloudhoster.com` (Operations), you still need to find the persistence that has been configured to call out to `persistence-site.com` (Long-haul).

<br>

## Hunting Techniques

1. Frequency Analysis is comparing different characteristics of data to identify anomalies and interesting events. This is a very effective technique when searching large sets of data and can be used to spot newly observed/registered domains, external services, and unusual port and protocol usage.

2. Link Analysis is using the relationships between nodes or events to locate anomalies, outliers, or related traffic.

3. Time Series Analysis looks at patterns of data points across time intervals such as beaconing and other unusual events or sequences.

<br>

## Malicious JavaScript

|Method|Example|
|-|-|
|Session Hijacking|A vulnerability on a legitimate site is exploited to capture a visitor's session token|
|Cross-Site Request Forgery|A vulnerability is exploited to induce an unwanted action using the visitor's session token|
|Profiling and Probing|An attacker-owned landing page that uses JS to enumerate the browser, host, and network|
|Redirecting the Browser|Compromised sites are injected with JS code that forces a request to a landing page|
|Cryptocurrency Mining|Legitimate and untrusted sites use JS to run a cryptominer in the background until the page closes|
|Man in the Browser|JS code is used to control, or "hook" a browser, executing arbitrary JS code using a C2 channel|

<br>

## Process Injection 

|Method|Description|
|-|-|
|Shellcode Injection|A target process is made to run malicious machine code|
|DLL Injection|A target process is made to run a malicious DLL on disk|
|Reflective DLL injection|Target process is made to run a malicious DLL which loads itself into memory|
|Memory Module|Target process is made to run a malicious DLL which is loaded into memory using an injector or loader that mimics the `LoadLibrary` function|
|Process Hollowing|A new process is started in a suspended state, replace with malicous code, and resumed
|Module Overwriting|A legitimate module is loaded into the target process and then overwritten with a malicious module|

<br>

## Interacting with Windows API

|Method|Description|
|-|-|
|Built-In Programs|GUI applications (`explorer.exe`) and command line programs (`netsh.exe`) are built into the OS and use Windows API functions to interact with the system|
|Compiled Programs|Custom programs can be written and compiled to interface with the Windows API|
|COM Objects|DLLs are written to interface with programs that understand the C language. Component Object Model (COM) objects were created to allow DLLs to be accessed from any programming language. Scripting languages like PowerShell, VBA/VBScript, and JScript use COM objects in order to interact with the Windows API|
|Dynamic .NET Assemblies|PowerShell can compile C# on the fly which allows the Platform Invoke (P/Invoke) service to call DLLs through .NET with the `Add-Type` cmdlet.  PSReflect is a script created by Matt Graeber that uses .NET reflection to dynamically define methods that call Windows API functions|

<br>

## Phishing To Injection 

API access is traditionally reserved for processes running on the system that were started from executables present on the filesystem.  Scripting languages used for system administration like PowerShell, VBA/VBScript, and JScript can access Windows APIs using COM objects. The .NET Framework is used to run managed code and can also access the Windows API. Because of these capabilities, scripts and .NET assemblies are frequently used by malware to perform memory injection.

|Method|Description|
|-|-|
|VBA Code|Office Doc uses VBA macro to create a new process and inject shellcode into it which will download and reflectively inject a DLL in memory|
|PowerShell|Script/Doc uses a COM Object to create a PowerShell process which injects shellcode that will download the payload into memory|
|.NET Assembly|Script/Doc uses a COM Object to run a .NET assembly in memory which injects shellcode into a created process|

<br>

## Windows Script Hosts

|Script Host|Technology|File Types|Access Types|
|-|-|-|-|
|`cmd.exe`|Batch|`.bat` `.cmd` `.btm`|CLI|
|`wscript.exe`<br>`cscript.exe`|VBScript<br>JScript|`.vbs` `.vbe` `.js` `.jse` `.hta` `.wsf` `.sct`|COM, .NET, WinAPI|
|`winword.exe`<br>`excel.exe`<br>`powerpnt.exe`|Visual Basic<br>for Applications|`.docm` `xlsm` `.pptm`|COM, .NET, WinAPI|
|`powershell.exe`<br>`powershell_ise.exe`<br>or others|PowerShell|`.ps1` `.psm1` `.psd1`|CLI, COM, .NET, WinAPI|

<br>

## Windows Script Malware

- Batch files use `cmd.exe` to run commands
- VBScript and JScript files can create hidden COM objects and use WinAPI functions by loading .NET assemblies in memory
- VBA code can be used to create hidden COM objects and call WinAPI functions on systems where Office is installed
- PowerShell code can run in non-traditional hosts to avoid restrictions/monitoring of traditional hosts such as `powershell.exe` and `powershell_ise.exe`


## Batch Files

A batch file (`.bat`) contains a list of commands that are executed one by one using the Windows command line interpreter `cmd.exe`.

Batch files can be downloaded and executed or PowerShell can be used to pipe the contents of a text file to `cmd.exe` so that it executes as a batch file.


## VBScript and JScript 

VBScript and JScript are scripting languages built in to Windows operating systems. They were initially client-side scripting languages for Internet Explorer without the capability for file managment tasks. Later, Windows Scripting Host (WSH) was introduced to allow scripting for outside the browser to support system administration. The console-based script host is `cscript.exe` and the windows-based script host is `wscript.exe`.

Here are a few ways scripts are used to perform malicious actions:

|Method|Description|
|-|-|
|COM Objects|Internet Explorer COM objects can be used to download and run a file|
|Obfuscation|Script Encoding can be used to obfuscate code and commands|
|Containers|VBScript/JScript can be run from containers such as Windows Scripting Files (.wsf) and HTML Applications (.hta)|
|API Access|.NET assemblies can be embedded into JScript files using serialization and can directly access the Windows API|

<br>

## Visual Basic for Applications

VBA is an embeddable programming environment used to automate and extend the functionality of applications. Office applications such as Word, Excel, and PowerPoint are used to host VBA code via macros. VBA is closely related to Visual Basic, a programming language and IDE used to create stand-alone windows applications.

|Method|Description|
|-|-|
|COM Objects|Internet Explorer COM objects can be used to download and run a file|
|Obfuscation|VBA code can use obfuscation to deter code analysis|
|Containers|VBA code is traditionally launched from an Office document but can also use other filetypes as containers such as a VBScript file which creates a hidden Office object, adds a macro to it, and runs it|
|API Access|VBA natively has direct access to the Windows API|

<br>

## PowerShell

PowerShell is a command-line shell and scripting language based on the .NET Framework which is installed by default on Windows 7/2008 R2 and later.  It has become a major component of adversary tradecraft and is increasingly seen in targeted attacks as well as commodity malware.

These are som of PowerShell's capabilities that offer adversaries the greatest tactical advantage:

|Capability|Description|
|-|-|
|Scope of Influence|PowerShell is a trusted program providing an interactive command-line shell and scripting language for automating a wide range of administrative tasks|
|Dynamic Code Generation|PowerShell has access to .NET & Windows APIs and can be used to compile and run C# code on the fly|
|Process Agnostic|Unmanaged PowerShell allows custom and native programs to run in any process|
|Memory-Only Execution|PowerShell can use memory modules and reflective injection to execute code in memory without ever touching disk|
|Cradle Options|PowerShell has multiple ways to download content from remote systems to disk or to memory|
|Post-Exploitation Modules|Multiple scripts and modules exist designed specifically to enhance and support adversary operations|

<br>

## Authenticated RCE

Authenticated Remote Code Execution (RCE) can be performed several different ways:

|Technique|Description|
|-|-|
|[Windows Management Instrumentation](#windows-management-instrumentation)|Use WMI to execute a command on a remote system|
|[Service Control Manager](#service-control-manager)|Create a service that will execute a command when started|
|[Windows Remoting](#windows-remoting)|Use Windows Remoting (WinRM) to execute command|
|[Remote Registry](#remote-registry)|Write command to execute to a registry key|
|[Remote File Access](#remote-file-access)|Write file containing command to execute to an administrative share|
|[Task Scheduler](#task-scheduler)|Schedule a command to run at the provided time|
|[Remote Desktop](#remote-desktop)|Log in with credentials and execute code in an interactive session|
|[MMC20.Application DCOM](#mmc20.application-dcom)|Instantiate a COM object remotely and call ExecuteShellCommand method|

<br>

## Cookie and Token Session Management

|Method|State|Description|
|-|-|-|
|Cookie-Based|Stateful|- User authenticates<br>- Server verifies and creates a session<br>- Cookie with session ID is placed in browser and stored on server<br>- For each request, session ID is included and verified in database<br>- Session is destroyed upon logout|
|Token-Based|Stateless|- User authenticates<br>- Server verifies and returns a signed token<br>- Token is only stored client-side<br>- All future requests include the signed token<br>- Server decodes token and if valid processes request<br>- Client destroys token on logout|

<br>

## Web Authentication 

**Single Factor Authentication**

|Method|Description|
|-|-|
|Basic Authentication|Base64-encoded username and password included in each request. If not included, the server sends a response with a `WWW-authenticate` attribute in the header|
|Digest Authentication|Username, password, and nonce is used to create hash which is sent to the server. If not included, the server sends a response with a `WWW-authenticate` attribute in the header and a nonce|
|Windows Integrated Authentication|Also called NTLM authentication, the server sends either a Negotiate (Kerberos) or NTLM `WWW-authenticate` header and a nonce.  Browser returns Base64-encoded username, hostname, domain, service, and the results of the hashing functions which the server can validate with the domain controller|
|Form-based Authentication|Uses code external to the HTTP protocol for authenticating the user. The application is left to deal with prompting the user for credentials, verifying them, and deciding their authenticity|
|Certificate Authentication|Client application holds a certificate with a private key and the remote web application maps that certificate's public key to an account. Client sends its certificate to the application which checks the digital signature, certificate chain, expiration/activation date and validity period, and a revocation status check|

<br>

**Second Factor Authentication**

|Method|Description|
|-|-|
|One-Time Passwords|One-time passwords are shared on-the-fly between two digital entities using an out-of-band (OOB) communication such as SMS, email, or application. After a server validates the username and password, it generates an OTP that can only be used once and sends it to the client via the chosen OOB method|
|Hardware Tokens|The hardware token contains an algorithm, a clock, and a seed or a unique number which is used to generate the numbers displayed for a specific time window. A user must provide the hardware token's current value along with username and password to gain access to the application|
|Tamper-resistant Hardware Devices|Smart Cards and U2F devices can store X.509 certificates and private keys that can't be read or exported---all cryptographic operations are performed on the card. Physical possession of the device is required as well as knowledge of a PIN in the case of Smart Cards|

<br>

**Session Management**

|Method|Description|
|-|-|
|Cookies|- User authenticates<br>- Server verifies and creates a session<br>- Cookie with session ID is placed in browser and stored on server<br>- For each request, session ID is included and verified in database<br>- Session is destroyed upon logout|
|Tokens|- User authenticates<br>- Server verifies and returns a signed token<br>- Token is only stored client-side<br>- All future requests include the signed token<br>- Server decodes token and if valid processes request<br>- Client destroys token on logout|

<br>

**Delegated Authorization**

|Method|Dscription|
|-|-|
|Oauth|Anyone presenting this token to the web application has access to the resources associated with the token|

<br>

## Web Authentication Challenges

|Method|Example|Problem|
|-|-|-|
|Password Authentication|Username and Password|Can be guessed, cracked, sniffed, stolen, etc.|
|Public Key Authentication|Digital certificate|Can be lost, copied, compromised, stolen, etc., not practical for most web apps|
|Multi-Factor Authentication|Password + Time-based One Time Password, SMS|Can be phished for a one time web session|
|MFA with Tamper-resistant Hardware Devices|Smart Card, U2F|Browser compromise required for an unauthorized web session|

<br>

Tamper-resistant hardware devices are designed so that the private key never leaves the device.  This ensures that someone must have possession of the device *and* know its PIN in order to use it.

<br>

## Investigating Suspicious Websites

|Method|Description|
|-|-|
|Direct|Use browser or honeyclient tool such as Thug to visit and perform reconnaissance|
|Indirect|Use various reputation sites to gather OSINT and artifacts|

<br>

## Incident Response Cycle

With the traditional [Incident Response Cycle](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final), the focus is on decreasing response time, reducing the impact of the security incident, and ensuring systems are safely returned to the production environment.  The weaknesses that were exploited are mitigated and capabilities are improved, however not much focus is given to building a complete picture of adversary operations:  

|Step|Description|
|-|-|
|Preparation |Understand organization's risk profile and security posture, position to resist intrusions or counter weaknesses being exploited by ongoing intruder activity|
|Identification|Maintain SA of indications, warnings, intelligence, fuse or correlate information, Evaluate environment for presence of attacker activity or compromise, Detect incidents and analyze incident-related data to respond quickly and effectively, Scope, investigate|
|Containment|FIRST AID – Prevent attacker from getting deeper, spreading to other systems, resolve incidents while minimizing loss and destruction|
|Eradication|Determine cause, symptoms, and vector of attack and Mitigate the weaknesses that were exploited|
|Recovery|Validate system, safely return to production, and monitor|
|Lessons Learned|Document what happened, improve capabilities|

<br>

## Intelligence Cycle 

The [Intelligence Cycle](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/books-and-monographs/analytic-culture-in-the-u-s-intelligence-community/chapter_4_systems_model.htm) is used to identify relationships between different pieces of information and draw correlations for improved decision-making.  By using this process, we improve our understanding of adversary operations and can use it to prepare for the most likely attack scenarios and predict how and when they are most likely to occur.  This entails collecting raw data and using it to create actionable intelligence: 

|Step|Description|
|-|-|
|Planning and Direction|Establishing requirements, what to do and how to do it|
|Collection|Gathering raw data from an operational environment|
|Processing|Collected data is converted to information analysts can use|
|Analysis and Production|Analysis of processed intelligence shows implications and patterns|
|Dissemination|The report is delivered to and consumed by decision makers|

<br>

## Intelligence-Driven IR Cycle

A combination of the [Incident Response Cycle](#incident-response-cycle) with the [Intelligence Cycle](#intelligence-cycle) where the Operations and Intelligence functions are used together to anticipate and predict adversary operations. 

Implementing this cycle with the [F3EAD](https://medium.com/@sroberts/intelligence-concepts-f3ead-964a0653be13) process has **Operations** directing the **Intelligence** effort which in turn provides **Operations** with information necessary for improving network defenses for future attacks.

|Function|Phase|Description|
|-|-|-|
|Find|[Monitoring and Hunting](#monitoring-and-hunting)	|Detect using alerts, analytics, endpoint interrogation|
|Fix |[Triage](#triage)|Make decisions on prioritization, remediation, countermeasures|
|Finish|[Incident Response](#incident-response)|Scope incidents, contain and eradicate threats|
|Exploit|[Threat Research](#threat-research)|Obtain data from artifacts and adversary tradecraft for intelligence purposes |
|Analyze|[Operationalize Intelligence](#operationalize-intelligence)|Produce actionable intelligence for decision advantage|
|Disseminate|[Disseminate Intelligence](#disseminate-intelligence)|Feed intelligence to partners, analysts, tools, processes|

<br>

## Detection Types 

Here is a description of each type of detection:

|Type|Description|
|-|-|
|Threat Behaviorial Analytics|Patterns in logs and data resulting from overall tradecraft used|
|Configuration Changes|New changes on a system such as new processes, new connections, new protocols|
|Threat Indicators|IP addresses, domain names, file hashes, etc. known to be malicious|
|Modeling|Baseline anomalies that stand out from normal activity in the environment|

<br>

## Threat Behavior Analytics

These are patterns in data resulting from adversaries doing what they do. A common technique used in phishing attacks is emailing the victim a link to an HTA file which will run a malicious PowerShell command on the victim’s system. The `mshta.exe` process spawning a `powershell.exe` process is an unique pattern that indicates that particular technique in use and we can use that pattern to search for every time this happens in our environment. 

<br>

## Configuration Changes

These are new changes that occur on a system. Using the same example, when a malicious `powershell.exe` process runs, it will most likely attempt to download malicious code from an attacker-owned IP address and run it in memory. The new network connection is a configuration change we can search for across all systems.

We can use the base64-encoded version of the string "IEX " to look for network connections from `powershell.exe` processes.

<br>

## Threat Indicators

These are files and infrastructure that is known to be associated with malicious activity. In our same example, good indicators would be the URL used to host the HTA file, the IP address used to deliver the malicious code, or a file hash of the HTA file. We can search for or configure our tools to alert each time the hash/ip address/domain is seen in our environment.

<br>

## Modeling

These are baseline anomalies, events or groups of events that are not considered normal for the environment. Keeping with our example, when the `powershell.exe` process runs an implant in memory, this could be used to run a module that attempts to log on to every host discovered on the network. This would create an unusually high number of logon attempts for different hosts which we could search for across our environment.

<br>

## Easy-to-Avoid Detection Types 

[Threat Indicators](#threat-indicators) and [Modeling](#modeling) are easily avoidable by a skilled or determined adversary. 

Advanced actors know if they use files or infrastructure that are known to be malicious by reputation, they’re likely to be caught. Instead they will use completely unknown tools and infrastructure to avoid detection.

Creating anomalies in the environment is also something advanced actors know will be caught by modeling-based detections.  For this reason, they'll make an effort to leverage legitimate programs, utilize approved protocols, and disguise their traffic to look like it originated from a legitimate application.

<br>

## Problems with Indicators and Anomalies

Relying solely on these two types for detections produces false positives that consume an analyst's time and prevent them from working actionable alerts. 

Relying solely on these two types for scoping and containment produces false negatives--that means hosts are checked with the detections and established as clean when they are not. When this happens, the SOC doesn't have a way to find the adversary on a system and therefore can't kick them out.

<br>

## Hard-to-Avoid Detection Types

Detections based on threat behavior analytics and configuration changes are very difficult to avoid.

As the adversary attempts to manipulate and control systems, they will be forced to create configuration changes such as new network connections, new processes, and new events on the system. 

As they use the various techniques they've become accustomed to, they will create observable patterns in logs and data that we can search for with our tools and use to detect them.

<br>


<br>

## Evasion Techniques on Network

|Technique|Description|
|-|-|
|[Encryption](#encryption)|Used to hide the contents of traffic|
|[Proxy Tunnels](#proxy-tunnels)|Used to hide the true destination of an application's traffic|
|[VPN Tunnels](#vpn-tunnels)|Used to hide the true destination of all traffic|
|[VPN With Cloaking Device](#vpn-with-cloaking-device)|Used to hide the true source of the traffic|

<br>

## Identify Network Evasion Techniques

- Hosts creating large amounts of traffic with little or no DNS requests 
- Hosts that make the majority of connections to one or several external servers on specific ports
- Hosts that are using protocols that are unusual for the ports being used (UDP on 443 in this example)
- Hosts having little or no listening ports and services

<br>

## Evasion Techniques on Disk

|Technique|Description|
|-|-|
|Using an Encrypted VM|Encrypt VM hard disk or store the machine's disk image file (VDI, VMDK, VHD, HDD) and settings file (.vbox) in an encrypted container|
|Using a Hidden VM|VM files can also be stored in a hidden volume which is a volume that's created within the free space of another encrypted volume|
|Booting to a Hidden OS|Hard drive has two partitions, the first is a decoy OS and the second holds both an encrypted filesystem and a hidden OS. The second partition appears to be and functions as storage and only runs the hidden OS when provided with a specific password|
|Booting to a Live OS|Live OS's run using only the filesystem on the device (USB, CD/DVD) and the computer's RAM to operate. These can be used to make changes to the existing system as well as operate without making any changes to the system|

<br>

## Identify Disk Evasion Techniques

|Technique|Controls|
|-|-|
|[Encrypted VM](#using-an-encrypted-vm)|Large amounts of encrypted data, presence of VM/disk encryption software|
|[Hidden VM](#using-a-hidden-vm)|Large amounts of encrypted data, presence of VM/disk encryption software|
|[Hidden OS](#booting-to-a-hidden-os)|Large encrypted partitions on hard drive or additional drives with disk encryption|
|[Live OS](#booting-to-a-live-os)|Unified Extensible Firmware Interface (UEFI) Secure Boot is a successor of Basic Input Output System (BIOS).  When UEFI is enabled, only signed bootloaders are allowed to run and booting from a CD/USB is not possible|

<br>

## Authentication Using Smart Cards and Kerberos

PKI is authentication based on digital certificates and a chain of trust. Trusted certificate authorities issue X.509 digital certificates to all entities, hosts, and services so they can authenticate each other.

Smart cards are tamper-resistant hardware devices that store X.509 certificates and private keys that can't be read or exported. A PIN is required to unlock and use the private key providing 2FA.

Active Directory contains account info such as group memberships, security identities, user details used to build TGTs determining access rights for accounts.

Keberos is a SSO mechanism which uses a third party (KDC) to authenticate clients and resources.  Once a user is verified using their digital certificate, the KDC finds the account in AD and builds a TGT containing their user and group SIDs. The TGT is then sent to the user which is used to request Service Tickets for accessing hosts and services on the network.

<br>


## Targeted Cloud Assets

Storage Buckets - S3 buckets (AWS), buckets (GCP), (Azure)

Snapshots are captures of EBS Volumes made at a specific point in time. By default they are not shared but changing a snapshot's permissions can make it available to any AWS account.

Similar to how EBS snapshots have a CreateVolumePermission attribute which controls which account can access it, Amazon Machine Images (AMI) have a LaunchPermission attribute.

Misconfigured SNS Topics and SQS Queues can allow any AWS account to send and receive messages to and from clients

<br>

## Assessing the Impact of Exposed Resources 

When sensitive information is exposed to the public:

- Identify all code and data that can be extracted by and exploited by an adversary 
- Use tools such as `bulkextractor` and manual searching to find usernames, email addresses, SSH keys, AWS credentials, URLs, domains, IP addresses, hostnames, etc.
- Provide management with an accurate assessment of what was available as a result of the exposure to guide initial response and corrective actions

<br>


## Wireless Security Types

WEP keys, no matter how complex, will be cracked when enough data packets encrypted with the key are captured and fed to a cracking tool like `aircrack-ng`. Common attacks against WEP-encrypted networks involve passively or actively collecting large amounts of ARP replies containing unique IVs.

WPA and WPA2-protected networks do not have WEP's cryptological vulnerabilities, but their keys can be discovered with a dictionary attack if the four-way handshake between client and access point is captured and fed to a password attack tool with a wordlist.

When keys are obtained, traffic on the network can be captured and decrypted. This allows monitoring all traffic on the network as well as follow-on attacks such as:

- Netbios and LLMNR Name Poisoning
- Relay/Man in the Middle
- Exploiting vulnerabilities

<br>

## Wireless Attack Techniques

|Technique|Description|
|-|-|
|Attacking Open WEP|Open WEP can be cracked if enough packets with unique IVs are captured. The primary way to do this is to capture an ARP request and replay it over and over causing the access point to generate lots of ARP replies, each containing a unique IV|
|WEP Client|If the access point has protections or is out of range of attacker, it is possible to replay an ARP request to the client so it will respond with ARP replies, each containing a unique IV|
|WEP Clientless|Attack a WEP network with no clients connected by obtaining a PRGA file from the AP and using it to build an encrypted packet that can be replayed on the network to generate IVs. Two common techniques are using the Fragmentation Attack and ChopChop Attack|
|Attacking Shared Key WEP|When Shared Key WEP is being used, the attacker must capture traffic resulting from a client joining the network which contains a PRGA file (.xor). This PRGA file is used to create encrypted packets that can be injected into the network|
|Attacking WPA and WPA2|For attacks against WPA/WPA2 networks, the encryption is too strong to use statistics and requires using a dictionary attack to identify the key once a 4 way handshake is captured|
|Guessing Passwords
|Decrypting Packets
|Attacking WPA Enterprise|A tool like `hostapd-wpe` can be used to prompt the user for credentials. When entered, the hashes are provided to the attacker which can be used to reveal the password using a dictionary attack|
|Evil Twin Access Point
|Man in the Middle Attack

<br>

## Injecting a Dotnet Assembly

DotNet assemblies can be dynamically loaded into memory using the `Assembly.Load(byte[])` function to run untrusted programs to bypass application whitelisting and avoid writing artifacts to disk.

Here are several examples:

Post-Exploitation tools such as Empire and Cobalt Strike can inject .NET assemblies (PowerShell runner DLLs) into any process in memory

Multiple Application Whitelisting Bypasses exist where signed applications that call the `Assembly.Load()` method like `MSBuild.exe` and `InstallUtil.exe` are made to run unsigned .NET assemblies which can access Windows APIs

JScript tools such as DotNetToJScript, Starfighters, and CactusTorch run .NET assemblies in memory providing Windows API access

<br>

## Advanced Post-Exploitation Tools

Created using staged or stageless payloads

Evade detection several ways:
- Fake thread start address
- Remove RWX Permissions
- Module Stomping
- Obfuscating and sleeping

Capable of:
- Migrating to other processes
- Executing programs/scripts with post-exploitation jobs

<br>

## Malware Analysis

These are general steps taken during malware analysis, discovering and extracting TTPs and indicators during each one:

|Step|Description|
|-|-|
|Automated Analysis|Sandbox check for suspicious APIs, reputation, dropped files, connections, SSL certs, mutexes|
|Static Analysis|Closer inspection of file structure, strings, imports, exports, metadata, encryption, obfuscation|
|Dynamic Analysis|Run file in controlled environment to observe file, registry, process, and network activity|
|Static Code Analysis|Fully map malware capabilities without running its code|
|Dynamic Code Analysis|Fully map malware capabilities by running and interacting with its code|
|Memory Analysis|Run malware and observe how samples interact with system memory|

<br>

## Exploiting the Docker API

- Gather Docker information
- Start containers on the host
- Create containers on the host
- Read files on the host 
- Create and change files on the host

<br>

## General Adversary Methodology

A general methodology used by an adversary attempting to compromise a system or network:

|Step|Description|
|-|-|
|[Reconnaissance](#reconnaissance)|Gather information about the network and environment|
|[Remote Enumeration](#remote-enumeration)|Scan target system to identify ports/services/versions|
|[Remote Exploit](#remote-exploit)|Gain access to the target machine|
|[Local Enumeration](#local-enumeration)|Search the target machine for opportunities to escalate privileges|
|[Local Exploit](#local-exploit)|Escalate privileges to gain full control of target machine|
|[Root Loot](#root-loot)|Search the target machine with admin/root privileges|
|[Install Persistence](#install-persistence)|Establish a way to maintain access to the target host|
|[Cover Tracks](#cover-tracks)|Delete logs, files, and all evidence of compromise|

<br>

## General Adversary Methodology Web Applications 

|Tactic|Description|
|-|-|
|[Vulnerability Scans](#vulnerability-scans)|Used to [Identify](#identify) and [Exploit](#exploit) web application vulnerabilities|
|[Dictionary Attacks](#dictionary-attacks)|Guessing and enumerating [Directories and Files](#directories-and-files), [Parameters](#parameters), and [Values](#values)|
|[Spidering](#spidering)|[Automated Mapping](#automated-mapping) of a web application and for [Gathering Data](#gathering-data) to support other attacks|
|[Passive Probing](#passive-probing)|Quiet [Passive Mapping](#passive-mapping) and slow [Manual Testing](#manual-testing) of a web application|
|[RCE via Webshell](#rce-via-webshell)|The [Deployment](#deployment) of custom webpages designed to provide code execution on the victim host|

<br>

## Privilege Escalation Tools

Here are some common privilege escalation scrips/programs:

|Tool|Description|
|-|-|
|[Metasploit modules](https://github.com/rapid7/metasploit-framework/tree/master/modules)|`use post/multi/recon/local_exploit_suggester`|
|[Windows Privesc Check](https://github.com/pentestmonkey/windows-privesc-check)|`windows-privesc-check2.exe --audit -a -o report`|
|[PowerUp](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/PowerUp.ps1)|`Import-Module PowerUp.ps1; Invoke-AllChecks`|
|[SharpUp](https://github.com/GhostPack/SharpUp)|`SharpUp.exe`|
|[Sherlock](https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1)|`Import-Module Sherlock.ps1; Find-AllVulns`|
|[Watson](https://github.com/rasta-mouse/Watson)|`Watson.exe`|
|[windows-exploit-suggester.py](https://github.com/GDSSecurity/Windows-Exploit-Suggester)|`python windows-exploit-suggester.py -u` <br> `python windows-exploit-suggester.py -d <xls> -i systeminfo.txt`|
|[linuxprivchecker.py](https://github.com/sleventyeleven/linuxprivchecker)|`python linuxprivchecker.py`|

<br>

## Levels of Code Execution

|Level|Description|
|-|-|
|Single command|The simplest way to execute code is a single command. This could be as a result of an application via command injection, SQL injection, LFI/RFI, stolen credentials, or a user opening a phishing document|
|Interactive shell|Shell sessions such as SSH, Command Prompt, PowerShell, Python, Javascript, Bash, etc. provide interactive access with more options and flexibility|
|Post-exploitation agent|Post-exploitation agents such as Meterpreter, Empire, PoshC2, and Beacon provide access to hundreds of built-in tools and the ability to run pre-built modules, pass sessions, and import custom scripts and programs from a single interface|

<br>

#
## Privilege Escalation Using Active Directory

### Permissions

An adversary with a low-privilge account will typically target users, computers, and groups that have more permissions than necessary.  Access to AD objects is determined by a combination of rights the account has which is made up of:

- AD Group Membership
- Local Group Membership
- AD Object ACLs
- GPO Permissions
- User Rights Assignments

<br>

### Kerberoasting

Since any user can request a ticket for a service, an adversary requests a ticket for a service associated with an AD user or computer account. A portion of the ticket received is encrypted with the NTLM hash of the account's plaintext password. This ciphertext can then be fed to a tool and cracked offline avoiding failed logon attempts and AD account lockouts.

<br>

## Unauthorized Access to Web Service 

|Method|Description|
|-|-|
|Find Single Factor|Current credentials can be searched for, discovered, and used to access accounts|
|Guess Single Factor|Users often employ weak or duplicate passwords that can be guessed or brute-forced|
|Steal Single Factor|Users can be tricked into providing credentials to an adversary or running malware that steals them|
|Bypass Single Factor|Account recovery procedures can allow an adversary to bypass the normal authentication process|
|Steal Session Creds|With XSS, the adversary is using the ability to run JavaScript in the victim's browser to send a cookie or session token to a remote server so they can create an authenticated session from there|
|Forge Session Creds|With CSRF, the adversary is taking advantage of the browser being authenticated to a target site. If the victim is logged in, any request made to the site originating from the victim's browser will be successful|
|Exploit Application|Vulnerability is exploited to gain access|

<br>

## Cloud Account Best Practices

Best practices for both corporate and personal cloud accounts:

|Best Practice|Description|
|-|-|
|Restrict Root Account Use|Each AWS account has a root user account with access to all services and resources in the account. This root account should not be used for normal, everyday activity|
|Prohibit Root Access Keys|Long term access keys provide account access using single factor authentication. That means if someone obtains the root user's secret key, they have complete control over everything in the account. For this reason, the root account should not have any access keys|
|Require MFA for Console Access|For console access, an account must have a password. When this password is set, all that's needed to log on as that user is the account name and password. Enabling MFA on the account will require the use of a second form of authentication before providing account access|
|Use Roles for API Access|Roles use temporary credentials which do not require an AWS identity, have a limited lifetime, are generated dynamically and provided to the instance when requested|
|Rotate Credentials Regularly|All long-term credentials should be rotated regularly---that includes both passwords and access keys. Password policies should be enabled to enforce this as well as provide complexity requirements|
|Attach Policies to Groups not Users|Attaching policies to a group and then assigning the user to that group is the proper way to assign permissions. This way, users can be added to or removed from different groups according to the permissions required by their job functions|
|Use AWS Managed Policies to Assign Permissions|AWS Managed policies should be utilized before making custom managed policies in order to avoid unintentionally assigning unnecessary permissions to entities. If an AWS managed policy can't be found that is exactly right, find one that's close, copy it, and then modify it to fit your requirements|
|Credential Requirements|Use a long, complex password with 2FA enabled|
|Recovery Info|Verify accurate and up-to-date account recovery info such as email, phone|
|Monitoring|Review recent activity, authorized/logged in devices, payments, subscriptions, 3rd party access authorizations|

<br>


<br>

### Common Defenses Against CSRF

CSRF defenses...

Also:

|Mitigation|Description|
|-|-|
|SameSite=strict|Ensures cookie can only be sent with requests originating from the same site|
|Anti-CSRF Tokens|Token unique to each request ensure they come from a trusted source|
|Session ID in Headers|Using HTTP Headers not accessible to the attacker for session management|

<br>

## Cross Site Scripting Types

There are three types of XSS:

|Type|Description|
|-|-|
|Stored XSS|Website or application contains the untrusted code|
|Reflective XSS|Link contains code that's echoed back to the browser and executed|
|DOM XSS|Client-side JavaScript dynamically modifies a rendered page based on content in the URL|

<br>

Also called Persistent Cross Site Scripting, Stored XSS actually changes the website's content so that any user that visits will load and run the JavaScript in their browser. This is commonly accomplished by adding a line of code into a blog comment or user profile but can be done with any part of a website that users have the ability to modify or write to.

Reflected XSS is performed by coaxing a victim to click on a link to a legitimate site that is vulnerable to XSS. The link contains malicious JS code that when visited, will be reflected back to the browser and executed as if it originated from the legitimate website.

DOM XSS...

<br>

## 




<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>

## References 

[60 Cybersecurity Interview Questions - 2019 Update](https://danielmiessler.com/study/infosec_interview_questions/)
