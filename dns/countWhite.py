import os


fi = open('domainsuffix.txt','r')
DomainSuffix = []
for f in fi:
	DomainSuffix.append(f[:-1])
fi.close()
os.system("echo 'Suffix Loaded for Detecting..'")


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


def loadLabel():
	whitelabel = []
	with open('whitelabel.txt','r') as fi:
		for f in fi:
			if not (f[:-1] in whitelabel):
				whitelabel.append(f[:-1])
	return whitelabel


def getPaths():
	path = "/home/data1/"
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


def main():
	pathlist = getPaths()
	whitelabel = loadLabel()
	print whitelabel[:10]
	count = 0
	log = 0
	for file in pathlist:
		with open(file,'r') as fi:
			for f in fi:
				domain = f.strip().split('\t')[3][:-1]
				label = mainLabel(domain,DomainSuffix)
				log += 1
				if mainDomain(domain,DomainSuffix) in whitelabel:
					count += 1
					if not(count % 10000):
						print log,count
			print file,log,count

if __name__ == '__main__':
	main()
