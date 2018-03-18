import json, urllib, time, subprocess, sys, os
from nmap_scanner import nmap_scan
from time import sleep
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

if os.getuid() != 0:
        print "You must run this tool as root. Exiting"
        exit(-1)

Story = []

company = sys.argv[2]
emailTableTop=['Emails','Stats']
subdomainTableTop=['Subdomains','Nmap']
subdomains_biglist=[]
output_report = []
emails = []

userDomains = []
userBuckets = []

# create .pdf file with the company name (Example: uber.pdf)
shell_command = 'mkdir tmp_result/{0}'.format(company)
subprocess.call(shell_command, shell=True)
pdffile = 'tmp_result/{0}/{0}.pdf'.format(company) 

# get user inputs
totalArgLength = len(sys.argv)
inputHasBucket = "bucket" in sys.argv
if ("domain" in sys.argv):
	locateDomain = sys.argv.index("domain")
	if inputHasBucket:
		locateBucket = sys.argv.index("bucket")
		for domains in sys.argv[locateDomain+1:locateBucket]:
			userDomains.append(domains)
		for buckets in sys.argv[locateBucket+1:]:
			userBuckets.append(buckets)
	else:
		for domains in sys.argv[locateDomain+1:]:
			userDomains.append(domains)
else:
	sys.exit("You did not pass any domain")

# initate creating document
doc = SimpleDocTemplate(pdffile,pagesize=letter,rightMargin=72,leftMargin=72,topMargin=70,bottomMargin=18)

formatted_time = time.ctime()

styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY))
ptext ='<font size=20 color=red><b>Scanner report for {0}</b></font>'.format(company)
Story.append(Paragraph(ptext, styles["Normal"]))
Story.append(Spacer(1,20))
ptext = '<font size=12>{0}</font>'.format(formatted_time)
Story.append(Paragraph(ptext, styles["Normal"]))

Story.append(Spacer(1,10))
ptext='<font size=18>Subdomains</font>'
Story.append(Paragraph(ptext, styles["Normal"]))
Story.append(Spacer(1,5))

for domain in userDomains:
	open_port = ""
	open_port = nmap_scan(domain, company)
	Story.append(Spacer(1,10))
	ptext='<center><font size=12 color=blue><b>{0}</b></font></center>'.format(domain)
	Story.append(Paragraph(ptext, styles["Normal"]))
	Story.append(Spacer(1,4))
	ptext='<font size=5>Open ports: {0}</font>'.format(open_port)
	Story.append(Paragraph(ptext, styles["Normal"]))
	Story.append(Spacer(1,5))
	del subdomains_biglist[:]
	subdomains_biglist.append(subdomainTableTop)
	run_scan = 'expect hostile/getdomain.sh {0}'.format(domain)
	subprocess.call(run_scan, shell=True)
	with open("hostile/output.txt","r") as ins:
		for line in ins:
			line = line.strip()
			temp_subdomains = []
			temp_subdomains.append(line)
			temp_subdomains.append(Paragraph(nmap_scan(line,company), styles["Normal"]))
			subdomains_biglist.append(temp_subdomains)
	t1=Table(subdomains_biglist,colWidths=[285,285])
	t1.setStyle(TableStyle([('ALIGN',(1,1),(-2,-2),'RIGHT'),('INNERGRID', (0,0), (-1,-1), 0.25, colors.black),('BOX', (0,0), (-1,-1), 0.25, colors.black)]))
	Story.append(t1)
	command = "rm hostile/output.txt"
	subprocess.call(command, shell=True)

Story.append(Spacer(1,12))

# get company emails and check if they were breached
ptext='<font size=18>Company Email Statistics</font>'
Story.append(Paragraph(ptext, styles["Normal"]))
Story.append(Spacer(1,5))
for domain in userDomains:
	Story.append(Spacer(1,10))
	ptext='<center><font size=12 color=blue><b>{0}</b></font></center>'.format(domain)
	Story.append(Paragraph(ptext, styles["Normal"]))
	Story.append(Spacer(1,5))
	del emails[:]
	emails.append(emailTableTop)
	response = urllib.urlopen('https://api.hunter.io/v2/domain-search?domain={0}&api_key=HUNTER_IO_API_KEY&limit=10'.format(domain))
	outputEmails = response.read()
	returnedValues = json.loads(outputEmails)
	returnedval = len(returnedValues['data']['emails'])
	i=0
	if returnedval == 0:
		ptext='<font size=10>No emails were found for this domain</font>'
		Story.append(Paragraph(ptext, styles["Normal"]))
		Story.append(Spacer(1,5))
	else:
		while i < returnedval:
			temp_emails = []
			temp_emails.append(returnedValues['data']['emails'][i]['value'])
			try:
				check2hacked = urllib.open('https://haveibeenpwned.com/api/v2/breachedaccount/{0}?truncateResponse=true'.format(returnedValues['data']['emails'][i]['value']))
				check2parse = json.loads(check2hacked.read())
				temp_emails.append('Hacked')
				sleep(2.0)
			except Exception as e:
				temp_emails.append('Email is safe')
				sleep(2.0)
				emails.append(temp_emails)
			i+=1
		t=Table(emails)
		t.setStyle(TableStyle([('ALIGN',(1,1),(-2,-2),'RIGHT'),('INNERGRID', (0,0), (-1,-1), 0.25, colors.black),('BOX', (0,0), (-1,-1), 0.25, colors.black)]))
		Story.append(t)

Story.append(Spacer(1,20))
doc.build(Story)
