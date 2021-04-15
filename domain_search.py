#! -*- coding:utf-8 -*-

import random
import os
import urlparse
from bs4 import BeautifulSoup
import gevent
from gevent import monkey, pool
monkey.patch_all()
import requests
import dns.resolver

headers = {
	
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
	"Accept-Encoding": "gzip, deflate, br",
	"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,mt;q=0.7,zh-TW;q=0.6",
	"Cache-Control": "max-age=0",
	"Connection": "keep-alive",
	"Cookie": "BAIDUID=9F8F8C5499E080B4D2112DA21C4095ED:FG=1; BIDUPSID=9F8F8C5499E080B4D41BFD12195ED; PSTM=1535951702; BD_UPN=123253;",
	"Host": "www.baidu.com",
	"Upgrade-Insecure-Requests": "1",
	"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",

}




def link_urlparse(link):
	if "http://" not in link and  "https://" not in link:
		link = "http://" + link
	try:
		res = urlparse.urlparse(link)
	except Exception as e:
		print("[urlparse]" + str(e))
		domain = ""
	else:
		domain = res.netloc
	if ":" in domain:
		domain = domain.split(":")[0]
	return domain


def reuslt_number_page(searchKeyword):
	pageJudge = u'<span class="pc">10'
	try:
		url = "https://www.baidu.com" + searchKeyword
		#print(url)
		cur = requests.get(url=url, headers=headers, timeout=3)
	except Exception,e:
		print("[requests_baidu]"+str(e))
		return False
	else:
		body = cur.text
		if pageJudge in body:
			return True
		else:
			return False


def request_baidu(searchKeyword):
	with open("dict/baidu_server_ip_lists.txt","r") as w:
		baiduIpList = [i.strip("\n") for i in w.readlines() if i.strip("\n")]
	try:
		ip = random.choice(baiduIpList)
		url = "http://" + ip + searchKeyword
		cur = requests.get(url=url, headers=headers, timeout=3)
	except Exception as e:
		print("[requests_baidu]"+str(e))
		if ip in baiduIpList:
			baiduIpList.remove(ip) 
		request_baidu(searchKeyword) 
	else:
		body = cur.text
		soup = BeautifulSoup(body, "html.parser")
		linkList = [i.text for i in soup.find_all('a',{"class":"c-showurl"})]
		return linkList


class domain_search(object):
	
	def __init__(self, domain, flag):
		self.domain = domain
		self.flag = flag
		self.p = pool.Pool(20)
		self.tasks = []
		self.subDomainEngine = []
		self.zDomainList = []

	def domainMerge(blastPath, subDomainEngine):
		subDomainBlast = []
		tempDomain = []
		with open(blastPath, 'r') as f:
			line = f.readline()
			while line:
				if re.match('([a-zA-Z0-9]+\.)+' + self.domain, line):
					domain = line.partition('=>')[0].strip()
					if domain not in subDomainBlast:
						subDomainBlast.append(domain)
		for domain in subDomainEngine:
			if domain not in subDomainBlast:
				tempDomain.append(domain)
		with open("dict/dns_servers_lists.txt","r") as w:
			dnsServers = [ i.strip("\n") for i in w.readlines()]
		with open('sub_domain.txt', 'a') as f:
			for domain in tempDomain:
				try:
					dnsServer = random.choice(dnsServers)
					resolver = dns.resolver.Resolver()
					resolver.nameservers = [dnsServer]
					ip4 = str(resolver.query(domain, "A")[0])
					ip6 = str(resolver.query(domain, "AAAA", raise_on_no_answer=False)[0])
				except IndexError:
					continue
				f.write(domain + ' => ' + ip4)
				f.write(domain + ' => ' + ip6)

	def search(self):
		shell = "dnsdict6 -4 -d " + self.domain + " -smlxu >" + "./sub_domain.txt"
		os.system(shell)
		if self.flag:
			subDomainEngine = self.search_engine_exhaust()
			domainMerge("sub_domain.txt", subDomainEngine)
			

	def search_engine_exhaust(self):
		print("[Info]start search engine exhaustion scan domain:%s" % self.domain)
		if reuslt_number_page(searchKeyword="/s?wd=site%3A{}".format(self.domain)):
			print("[Info]start first scan type......")
			with open("dict/baidu_search_keyword_lists.txt","r") as w:
				keywordList = [i.strip("\n") for i in w.readlines()]
			for key in keywordList:
				self.tasks.append(self.p.spawn(self.site_inurl_search, key))
			self.p.join()
			gevent.joinall(self.tasks)
		else:
			print(u"baidu search number is low,so don't use first scan type......")

		print(u"[Info]start second scan type......")
		self.site_link_search()
		print(u"[Info]start third scan type......")
		self.site_search()

		self.subDomainEngine = list(set(self.sub_domain))

		return self.subDomainEngine

	def domain_(self, linkList, domain):
		for link in linkList:
			zDomain = link_urlparse(link)
			if zDomain not in self.zDomainList and domain in zDomain:
				self.zDomainList.append(zDomain)
				try:
					#print(zDomain)
					self.subDomainEngine.append(zDomain)
				except:
					pass

	def site_link_search(self):
		for page in range(76):
			linkList = request_baidu(searchKeyword="/s?wd=site%3A{}%20link:{}&pn={}&rn=50".format(self.domain, self.domain, page*10))
			if linkList:
				self.domain_(linkList, self.domain)
			else:
				break

	def site_inurl_search(self, key):
		linkList = request_baidu(searchKeyword="/s?wd=site%3A{}%20inurl:{}&rn=50".format(self.domain, key))
		if linkList:
			self.domain_(linkList, self.domain)


	def site_search(self):
		for page in range(76):
			linkList = request_baidu(searchKeyword="/s?wd=site%3A{}&pn={}&rn=50".format(self.domain, page*10))
			if linkList:
				self.domain_(linkList, self.domain)
			else:
				break
		

if __name__=="__main__":

	import sys
	if len(sys.argv)>1:
		domain = sys.argv[1]
		cur =search_domain(domain)
		print cur.run()
	else:
		print "[Help] For Example: python domain_baidu_search.py target_domain"









