import nmap
import pandas as pd
import nmap
import os

class threat_detection():
	
	def __init__(self, subDomainFile, logger):
		self.subDomainFile = subDomainFile
		self.logger = logger

	def extract_info_ipv4(self, nm):
		with open('tmp.csv', 'w') as f:
			f.write(nm.csv())
		df = pd.read_csv('tmp.csv', sep=';', header=0)
		df = df[['host', 'hostname', 'protocol', 'port', 'name', 'state', 'product', 'extrainfo', 'reason']]
		
		os.remove('tmp.csv')
		return df
	
	def extract_info_ipv6(self, nm):
		with open('tmp.csv', 'w') as f:
			f.write(nm.csv())
		df = pd.read_csv('tmp.csv', sep=';', header=0)
		df = df[['host', 'hostname', 'protocol', 'port', 'name', 'state', 'product', 'extrainfo', 'reason']]
		df = df[df['state']=='open']
		os.remove('tmp.csv')
		return df

	def detection(self):
		df = pd.read_csv(self.subDomainFile, header=0)
		nm4 = nmap.PortScanner()
		nm6 = nmap.PortScanner()
		for row in df.itertuples():
			threat = []
			domain = getattr(row, 'subdomain')
			ipv4 = getattr(row, 'IPv4')
			ipv6 = getattr(row, 'IPv6')
			nm4.scan(hosts=ipv4, arguments='-sV -d')
			nm6.scan(hosts=ipv6, arguments='-6 -sV -d')
			df4 = self.extract_info_ipv4(nm4)
			df6 = self.extract_info_ipv6(nm6)
			df4NotOpen = df4[df4['state']!='open']
			dfInter = df6[df6[['port', 'name']].isin(df4NotOpen[['port', 'name']])]  #isin() requires the index and columns all match
			dfInter = pd.merge(df6[['port', 'name']], df4NotOpen[['port', 'name']])
			if not dfInter.empty:
				threat.extend(list(zip(dfInter['port'], dfInter['name'])))
			df4Open = df4[df4['state']=='open']
			dfInter = pd.merge(df6[['port', 'name']], df4Open[['port', 'name']])
			dfDiff = df6[['port', 'name']].append(dfInter).drop_duplicates(keep=False)
			threat.extend(list(zip(dfDiff['port'], dfDiff['name'])))
			threat = list(set(threat))
			if threat:
				self.logger.warn('Detection Dual-Stack Backdoor at Domain: %s!'%domain)
				self.logger.warn('%s has open services in IPv4: %s'%(domain, str(list(zip(df4Open['port'], df4Open['name'])))))
				self.logger.warn('%s has open services in IPv6: %s'%(domain, str(list(zip(df6['port'], df6['name'])))))
				self.logger.warn('Open service threat port: ' + str(threat))
