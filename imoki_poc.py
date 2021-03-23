import requests
import config

http = 'http://'
https = 'https://'
targetpath = 'file/url.txt'
faillogpath = 'file/faillog'
successpath = 'file/success.txt'
successlogpath = 'file/successlog'

def allpoc(httphead, origintarget, flag):
	if flag < 0:
		print("\033[1;31m[-] " + origintarget + " DOWN\033[0m")
		return
	origintarget = origintarget.strip()
	url = poc.url(origintarget)
	if url[0:4] != 'http':
		target = httphead + origintarget
		posturl = httphead + url
	else:
		target = origintarget
		posturl = url
	print("\033[1;32m[+] \033[0mVERIFY \033[0m" + target)
	try:
		requests.packages.urllib3.disable_warnings()
		rep = requests.post(url=posturl, proxies=config.proxies, headers=poc.headers, data=poc.data, verify=False, timeout = config.timeout)
		#rep = requests.get(url=posturl, headers=poc.headers, timeout = config.timeout)
		reptext = rep.text
		successflag = poc.successflag(reptext)
		#successflag = reptext.find(config.verify)
		if successflag == -1:
			faillog = open(faillogpath, 'a+', encoding = 'utf-8')
			faillog.write('[-] ' + target + '\n' + reptext + '\n\n')
			faillog.close()
			print("\033[0;33m[-] " + target + " DOWN\033[0m")
		else:
			success = open(successpath, 'a+', encoding = 'utf-8')
			success.write(target + '\n')
			success.close()
			successlog = open(successlogpath, 'a+', encoding = 'utf-8')
			successlog.write('[+] ' + target + '\n' + reptext + '\n\n')
			successlog.close()
			print("\033[1;33m[+] " + target + " SUCCESS!\033[0m")
	except Exception as e:
		print("\033[0;31m" + str(e) + "\033[0m")
		flag = flag - 1
		allpoc(https, origintarget, flag)

if __name__ == '__main__':
	#config.readme()
	#pocid = input("Please input POC ID:")
	#poc = config.choicepoc(int(pocid))
	poc = config.choicepoc()
	f = open(targetpath, 'r', encoding = 'utf-8')
	targetlines = f.readlines()
	for target in targetlines:
		flag = 1
		allpoc(http, target, flag)
	f.close()