from sklearn import svm
from sklearn.externals import joblib
import re
import math
import whois
import pickle
import gib_detect_train
import sys
import os
from collections import Counter


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


def main():
	clf = joblib.load("train_model.m")
	while True:
		domain = raw_input()
		feature = get_feature(domain)
		print clf.predict([feature])

if __name__ == '__main__':
	main()