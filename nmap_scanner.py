import json, subprocess
import xmltodict

def nmap_scan(domain, targets):
	filename = 'tmp_result/{0}/{1}.xml'.format(targets, domain)
	filename_json = 'tmp_result/{0}/{1}.json'.format(targets, domain)
	nmap_command = 'nmap -sS -T5 -O -oX {0} {1}'.format(filename, domain)
	try:
		subprocess.call(nmap_command, stdout=subprocess.PIPE, shell=True)
		with open(filename,'r') as f:
			xmlString = f.read()
		jsonOutput = json.dumps(xmltodict.parse(xmlString), indent=4)
		with open(filename_json, 'w') as f:
			f.write(jsonOutput)
		json_data=open(filename_json).read()
		data = json.loads(json_data)
		openports = ""
		if data["nmaprun"]["runstats"]["hosts"]["@up"] == "1":
			for port in data["nmaprun"]["host"]["ports"]["port"]:
				openports += port['@portid'] + ":" + port['state']['@state'] + ":" + port['service']['@name'] 
				openports += " "
		else:
			openports += "Host is down"
		command = 'rm {0} {1}'.format(filename_json, filename)
		subprocess.call(command, shell=True)
		return openports
	except:
		command = 'rm {0} {1}'.format(filename_json, filename)
		subprocess.call(command, shell=True)
		openports = "Error with Host"
		return openports

