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


def loadSuffix():
	fi = open('domainsuffix.txt','r')
	DomainSuffix = []
	for f in fi:
		DomainSuffix.append(f[:-1])
	fi.close()
	os.system("echo 'Suffix Loaded for Elasticsearch..'")
	return DomainSuffix



if __name__ == '__main__':
	while True:
		


	DomainSuffix = loadSuffix()
	es = Elasticsearch([{'host': 'zjces', 'port': 9200}])
	path = "/code/log/"
	files = os.listdir(path)
	files.sort()
	i = 0
	for file in files:
		newDir = os.path.join(path,file)
		lines = codecs.open(newDir, 'r', encoding = 'utf-8').readlines()
		os.system("echo 'processing " + file +"'")
		for line in lines:
			parts = line[:-1].split('\t')
			if (len(parts) > 7):
				i = i + 1
				t=['time','srcip','section','domain','ttl','rclass','rtype','rdata','label']
				domain = parts[3][:-1].lower()
				label = mainLabel(domain,DomainSuffix)
				parts.append(label)
				w = parts
				data_to_insert = json.dumps(dict(zip(t,w)))
				if not(i % 10000):
					os.system("echo 'try " + str(i) + "'")
				es.index(index='sjtu', doc_type='dns', id=str(i), body=data_to_insert)

