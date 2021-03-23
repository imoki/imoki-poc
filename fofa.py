import requests
from lxml import etree
import base64
import re
import time
from urllib.parse import quote,unquote

cookiepath = 'file/cookie.txt'
TimeSleep = 10
StartPage=1
StopPage=5

def spider():
	SearchKEY = input('[+] Please enter FOFA Keywords:\n')
	searchbs64 = quote(str(base64.b64encode(SearchKEY.encode()), encoding='utf-8'))
	# searchbs64 = (str(base64.b64encode(SearchKEY.encode('utf-8')), 'utf-8'))
	print("[+] FOFA URL https://fofa.so/result?&qbase64=" + searchbs64)
	try:
		html = requests.get(url="https://fofa.so/result?&qbase64=" + searchbs64, headers=headers, timeout = 30).text
		pagenum = re.findall('>(\d*)</a> <a class="next_page" rel="next"', html)
		print("[+] TOTAL PAGE "+pagenum[0])
		f = open("file/url.txt", "a+")
		for i in range(int(StartPage),int(pagenum[0])):
			print("[+] WRITING PAGE " + str(i))
			try:
				pageurl = requests.get('https://fofa.so/result?page=' + str(i) + '&qbase64=' + searchbs64, headers=headers, timeout = 30)
				tree = etree.HTML(pageurl.text)
				urllist=tree.xpath('//div[@class="re-domain"]//text()')
				urllist = [value.strip('\n').strip(' ').strip('\n') for value in urllist if len(value.strip('\n').strip(' ').strip('\n')) != 0]
				for urlline in urllist:
					print(urlline)
					f.write(urlline+"\n")
				if i==int(StopPage):
					break
				time.sleep(TimeSleep)
			except:
				pass
		f.close()
		print("[+] Finish!")
	except:
		pass

if __name__ == '__main__':
	try:
		with open(cookiepath, "r", encoding = "utf-8") as fa:
			COOKIE = fa.readline()
			COOKIE = COOKIE.strip()
			headers = {
				"Connection": "keep-alive",
				"Cookie": "_fofapro_ars_session=" + COOKIE,
			}
		fa.close()
		#print("[+] COOKIE: " + COOKIE)
		print("[+] READ COOKIE SUCCESS!")
	except:
		print("[-] READ COOKIE FAIL")
	spider()
