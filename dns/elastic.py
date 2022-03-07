import re
import codecs
import json
import sys
import os
from elasticsearch import Elasticsearch


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


fi = open('domainsuffix.txt','r')
DomainSuffix = []
for f in fi:
	DomainSuffix.append(f[:-1])
fi.close()


es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
path = "/code/log/"
files = os.listdir(path)
files.sort()
i = 0
for file in files:
	newDir = os.path.join(path,file)
	lines = codecs.open(newDir, 'r', encoding = 'utf-8').readlines()
	for line in lines:
		parts = line[:-1].split('\t')
		if (len(parts) > 7):
			i = i + 1
			t=['time','srcip','section','domain','ttl','rclass','rtype','rdata','label']
			domain = parts[3][:-1].lower()
			label = mainLabel(domain,DomainSuffix)
			parts.append(label)
			w=parts
			data_to_insert = json.dumps(dict(zip(t,w)))
			if not(i%50000):
				print "try ",i
			es.index(index='dns-sjtu-index', doc_type='dns-sjtu', id=str(i), body=data_to_insert)
	print file,' inserted ',i
#es.search(index='dns-sjtu-index',body={'from':0,'size':2500,'query':{'match':{'domain':'baidu.com'}}})
