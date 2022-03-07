import re
import math
import whois
import pickle
import gib_detect_train
import sys
import os
from collections import Counter
from sklearn import svm
from sklearn.externals import joblib
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from threading import Thread
import MySQLdb
import codecs
import json
import time
import geoip2.database
import datetime


fi = open('domainsuffix.txt','r')
DomainSuffix = []
for f in fi:
	DomainSuffix.append(f[:-1])
fi.close()
os.system("echo 'Suffix Loaded for Detecting..'")

def checkip(ip):  
	p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')  
	if p.match(ip):  
		return True  
	else:  
		return False  


def mainLabel(domain,DomainSuffix):
	PointSplitResult = domain.split('.')
	if domain.count('.') == 0:
		return domain
	res1 = '.' + PointSplitResult[-1]
	res2 = '.' + PointSplitResult[-2]
	if domain.count('.') == 1:
		return PointSplitResult[0]
	if (res2 in DomainSuffix):
		return PointSplitResult[-3]
	return PointSplitResult[-2]


def mainDomain(domain,DomainSuffix):
	PointSplitResult = domain.split('.')
	if domain.count('.') == 0:
		return domain
	if domain.count('.') == 1:
		return domain
	res1 = '.' + PointSplitResult[-1]
	res2 = '.' + PointSplitResult[-2]
	res3 = PointSplitResult[-3]
	if (res2 in DomainSuffix):
		return res3 + res2 + res1
	if (res1 in DomainSuffix):
		return PointSplitResult[-2] + res1
	return res1


def get_feature(domain):
	arr=domain.split('\n')
	domain=arr[0]
	lens=len (domain)
	separator=0.0
	bt_alpha=0.0
	max_alpha=0.0
	digit=0.0
	bt_digit=0.0
	max_digit=0.0
	special=0.0
	trans=0.0
	bt_separator=0.0
	bt=0.0
	flag=0
	upper=0.0
	hasip=0.0
	for i in range (lens):
		try:
			x=domain[i]
			#print x
			bt=bt+1
			if (bt_alpha>max_alpha):
				max_alpha=bt_alpha
			if (bt_digit>max_digit):
				max_digit=bt_digit
			
			if (x=='-'):
				bt_alpha=0.0
				bt_digit=0.0
				separator=separator+1
				if (bt-1>bt_separator and flag==1):
					bt_separator=bt-1
				bt=0.0
				flag=1
			elif (x.isalpha()):
				bt_alpha=bt_alpha+1
				bt_digit=0
			
			elif (x.isdigit()):
				digit=digit+1
				bt_digit=bt_digit+1
				bt_alpha=0.0
				j=i+1
				while (j<=lens) and (domain[j].isdigit()or domain[j]=='.'):
					j=j+1
					if checkip(domain[i:j]):
						hasip=1.0

			elif (not(x=='.')):
				#print x
				bt_alpha=0.0
				bt_digit=0.0
				special=special+1
			else:
				bt_alpha=0.0
				bt_digit=0.0
			if (x.isupper()):
				upper=upper+1
			if ((i>=1) and (not(x=='.'))):
				j=i-1
				while(domain[j]=='.'):
					j=j-1
				if ((x.isalpha() and domain[j].isdigit()) or (x.isdigit() and domain[j].isalpha())):
					trans=trans+1
		except :
			print 'URLError:'+domain
	f_len = float(len(domain))
	count = Counter(i for i in domain).most_common()
	entropy = -sum(j/f_len*(math.log(j/f_len)) for i,j in count)
	model_data = pickle.load(open('gib_model.pki', 'rb'))
	model_mat = model_data['mat']
	threshold = model_data['thresh']
	gib_value = int(gib_detect_train.avg_transition_prob(domain, model_mat) > threshold)

	if (not lens==0):
		rates=float(digit)/float(lens)
		trans_rates=float(trans)/float(lens)
	else:
		rates=0.0
		trans_rates=0.0
	return (float(lens),hasip,entropy,separator,special,digit,rates,trans_rates,upper,bt_separator,max_digit,max_alpha,float (gib_value))


def doubleCheck(logs,i):
	es = Elasticsearch([{'host': 'deepoceanes','port':9200}])
	for log in logs:
		fw = open('detected.txt','a')
		domain = log.split('\t')[-5].strip('.').lower()
		label = mainLabel(domain,DomainSuffix)
		mdomain = mainDomain(domain,DomainSuffix)
		res = es.search(
				index='sjtu',
				body = 
				{
					'size':10,
					'query':{
						'bool':{
							'must':[
								{'match':{'label':label}},
							]
						}
					}
				},
				request_timeout = 60)
		count = res['hits']['total']

		if (count > i/20000):
			fw.close()
			continue

		if (count > 500):
			fw.close()
			continue

		if (count < 100):
			fw.writelines(log)
			fw.close()
			continue
		
		try:
			a = whois.whois(mdomain)
			ctime = a["creation_date"]
		except:
			ctime = None

		if not(ctime == None):
			if type(ctime) == type([1]):
				ctime = ctime[0]
			ctime = ctime.strftime("%Y")
		
		if (ctime == None):
			fw.writelines(log)
			fw.close()
			continue

		if (int(ctime) > 2014):
			fw.writelines(log)
			fw.close()
			continue
		fw.close()


def getEsid():
	es = Elasticsearch([{'host': 'deepoceanes', 'port': 9200}])
	try:
		res = es.search(
				index='sjtu',
				body = 
				{
					'size':10,
					'query':{
						'bool':{
						}
					}
				},
				request_timeout = 60)
		count = res['hits']['total']
	except:
		count = 0
	os.system("echo 'current log num: " + str(count) + "'")
	return count


def getPaths():
	path = "/code/log/"
	pathlist = []
	dirs = os.listdir(path)
	dirs.sort()

	for allDir in dirs:
		filepath = os.path.join(path,allDir)
		if not(os.path.isfile(filepath)):
			filespath = os.listdir(filepath)
			for file in filespath:
				if 'rr' in file:
					pathlist.append(os.path.join(filepath,file))
		elif 'rr' in allDir:
			pathlist.append(filepath)
	pathlist.sort()
	return pathlist


def location(ip):
	try:
		reader = geoip2.database.Reader('./geo/GeoLite2-City.mmdb')
		response = reader.city(ip)
		return response.country.name.encode('ascii',errors='ignore'),response.city.name.encode('ascii',errors='ignore'),response.location.latitude,response.location.longitude
	except:
		return 'None','None','None','None'


if __name__ == '__main__':
	loglen = 8
	time.sleep(20)
	clf = joblib.load("train_model.m")
	es = Elasticsearch([{'host': 'deepoceanes', 'port': 9200}])
	db = MySQLdb.connect('deepoceandb','zjc','zjc13120709021','dns')

	#init systime
	systime = i = datetime.datetime.now()
	cursor = db.cursor()
	sql = 'insert into systime (year,month,day,hour,minute,second) values(%d,%d,%d,%d,%d,%d)' % (i.year,i.month-1,i.day,i.hour,i.minute,i.second)
	cursor.execute(sql)


	if not os.path.exists("processedlog.txt"):
		with open("processedlog.txt", "w") as fp:
			pass
	
	while True:
		#init
		i = getEsid()
		cursor = db.cursor()
		files = getPaths()

		#skipping processed log
		loglist = []
		with open('processedlog.txt', "r") as fp:
			for lines in fp:
				loglist.append(lines[:-1])


		for file in files:
			if file in loglist:
				continue
			if 'site40' in file:
				continue

			with open(file, "r") as fi:
				os.system("echo 'inserting " + file +" into es..'")
				actions = []
				for f in fi:
					parts = f[:-1].split('\t')
					if (len(parts) > loglen - 1):
						if not((parts[-2] == 'A') or (parts[-2] == 'AAAA') or (parts[-2] == 'NS')):
							continue
						i = i + 1
						domain = parts[-5][:-1].lower()
						label = mainLabel(domain,DomainSuffix)
						label = label.replace('-','')
						action = {
							"_index": 'sjtu',
							"_type": 'dns',
							"_id": str(i),
							"_source": {
								"time": parts[0],
								"srcip": parts[-7],
								"domain": parts[-5],
								"rdata": parts[-1],
								"label": label
							}
						}
						actions.append(action)
						if (len(actions) == 15000):
							a = helpers.bulk(es, actions)
							actions = []
							os.system("echo 'inserted " + str(i) + "'")
			a = helpers.bulk(es, actions)
			os.system("echo 'inserted " + str(i) + "'")
			actions = []
			

			with open(file, "r") as fi:
				os.system("echo detecting..")
				fw = open('detected.txt','w')
				fw.close()
				suspected = []
				j = 0
				for f in fi:
					line = f.split('\t')
					if len(line) < loglen:
						continue
					domain = line[-5].strip('.').lower()
					if ('ns' in domain) or ('cdn' in domain):
						continue
					#if not((line[-2] == 'A') or (line[-2] == 'AAAA')):
					if not (line[-2] == 'A'):
						continue
					feature = get_feature(domain)
					j += 1
					if clf.predict([feature]) == -1:
						suspected.append(f)
					if (len(suspected) == 300):
						threads = []
						for k in range(10):
							domains = []
							for m in range(30):
								domains.append(suspected[k * 10 + m])
							t = Thread(target = doubleCheck,args = (domains,i,))
							threads.append(t)
						for t in threads:
							t.start()
						for t in threads:
							t.join()
						suspected = []
					if not(j % 10000):
						os.system("echo 'detected " + str(j) + "'")

			
			with open('detected.txt') as fd:
				for f in fd:
					line = f.strip().split('\t')
					if line[-2] == 'A':
						sql = "select * from amallog where domain = '%s'"%line[-5].strip('.')
						res = cursor.execute(sql)
						if res == 0:
							sql = "insert into log1 (domain,ip,time,srcip) values('%s','%s','%s','%s') "%(line[-5].strip('.'),line[-1],line[0],line[-7])
							cursor.execute(sql)
							loc = location(line[-1])
							sql = 'insert into location (domain,country,city,latitude,longitude) values ("%s","%s","%s","%s","%s")' % (line[-5].strip('.'),str(loc[0]),str(loc[1]),str(loc[2]),str(loc[3]))
							cursor.execute(sql)
						sql = "insert into amallog (domain,ip,time,srcip) values('%s','%s','%s','%s') "%(line[-5].strip('.'),line[-1],line[0],line[-7])
						cursor.execute(sql)
						

			with open('detected.txt') as fd:
				malcount = len(fd.readlines())

			with open('detected.txt') as fd:
				for f in fd:
					t = f.split('\t')[0]
					date = t[5:10]
					hour = int(t[11:13])
					timeid = str(hour / 4 * 4) + ':00'
					
					sql = "select totalnum from logcount where logtype = 'log'"
					cursor.execute(sql)
					logcount = i - int(cursor.fetchall()[0][0])

					sql = "select * from tongji where date = '%s' and id = '%s'"%(date,timeid)
					if cursor.execute(sql) == 0:
						sql = "insert into tongji (date,id,malcount,logcount) values('%s','%s','%s','%s')"%(date,timeid,malcount,logcount)
						cursor.execute(sql)
					else:
						result = cursor.fetchall()[0]
						malcount += int(result[2])
						logcount += int(result[3])
						sql = "update tongji set malcount = '%s',logcount = '%s' where date = '%s' and id = '%s'"%(malcount,logcount,date,timeid)
						cursor.execute(sql)
					break

			sql = "update logcount set totalnum='%s' where logtype='log'"%str(i)
			cursor.execute(sql)
			db.commit()

			os.system("echo 'results inserted to mysql'")

			with open('processedlog.txt','a') as fp:
				fp.write(file + '\n')

		time.sleep(10)






	

	


				






