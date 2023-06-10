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

### Information Gathering with Burp Suite
### Utilizing Social Media

## Scanning and Enumeration
### Scanning with Nmap
### Enumerating HTTP and HTTPS
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

