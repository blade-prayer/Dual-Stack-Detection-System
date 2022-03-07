import os

pathlist = []
path = './log'
dirs = os.listdir(path)
print dirs

for allDir in dirs:
	filepath = os.path.join(path,allDir)
	if not(os.path.isfile(filepath)):
		filespath = os.listdir(filepath)
		for file in filespath:
			if 'rr' in file:
				pathlist.append(os.path.join(filepath,file))

print pathlist