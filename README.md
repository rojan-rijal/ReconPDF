# ReconPDF
PDF report generator for basic recon

# Installation 
1. Install ruby 
2. Install all dependencies in requirements.txt

# Requirement

1. If you want to find emails, you will need to use Hunter.io api key. You can get it by creating a free account over at https://hunter.io. Hunter.io gives 100 free scans per month so use it wisely. 

# Usage
1. Format:  `python scanner.py company COMPANY_NAME domain domain1.com domain2.com`
2. Example: `python scanner.py company HackerOne domain hackerone.com`


# Feature
1. Subdomain Bruteforce: Find subdomain through HostileSubBruteforcer and then runs them through nmap for ports. 
2. Emails and scans: Find top 10 employee emails of company X. This list is then crosschecked with haveibeenpwned.com to find which emails were previously breached. (This is mainly for pentesting when companies allow social engineering). 
