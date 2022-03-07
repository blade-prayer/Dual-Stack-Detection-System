import MySQLdb
import os


db = MySQLdb.connect('zjcmysql','root','123456','dns')
cursor = db.cursor()


fi = open('sort_logall.txt','r')
for f in fi:
	line = f.strip().split('\t')
	if line[-2] == 'A':
		sql = "insert into amallog (domain,ip,time,srcip) values('%s','%s','%s','%s') "%(line[3],line[-1],line[0],line[1])
		cursor.execute(sql)
db.commit()

os.system("echo 'results inserted to mysql'")

