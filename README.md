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
### Enumerating SSH

## Vulnerability Scanning with Nessus
### Scanning with Nessus

## Exploitation Basics


## Attacking AD: Initial Attack Vectors
### LLMNR Poisoning

### SMB Relay Attacks


## Attacking AD: Post-Compromise Enumeration
### Domain Enumeration with Powerview
### Domain Enumeration with Bloodhound

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

