import re
import pandas as pd

class dual_stack_hosts_detection():

	def __init__(self, domain, subDomainFile):
		self.domain = domain
		self.csv = pd.DataFrame(columns=['subdomain', 'IPv4', 'IPv6'])
		self.subDomainFile = subDomainFile

	def detection(self):
		domains = {}
		with open("sub_domain.txt", 'r') as f:
			line = f.readline()
			while line:
				if re.match('([a-zA-Z0-9]+\.)+' + self.domain, line):
					ip = line.partition('=>')[-1].strip()
					domain = line.partition('=>')[0].strip()
					if domain not in domains:
						domains[domain] = []
					domains[domain].append(ip)
				line = f.readline()

		for domain in domains.keys():
			ips = domains[domain]
			if len(ips) == 2:
				if re.match('([a-zA-Z0-9]+\.)+', ips[0]):
					ipv4 = ips[0]
					ipv6 = ips[1]
				else:
					ipv4 = ips[1]
					ipv6 = ips[0]
				self.csv = self.csv.append({'subdomain':domain, 'IPv4':ipv4, 'IPv6':ipv6}, ignore_index=True)
		self.csv.to_csv(self.subDomainFile, header=['subdomain', 'IPv4', 'IPv6'])
