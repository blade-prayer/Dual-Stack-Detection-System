import codecs
import json
from elasticsearch import Elasticsearch


if __name__ == '__main__':
	es = Elasticsearch([{'host':'zjces','port':9200}])
	while 1:
		domain = raw_input()
		res = es.search(
			index='sjtu',
			body = 
			{
				'size':10,
				'query':{
					'bool':{
						'must':[
							{'match':{'label':domain}}
						]
					}
				}

			},
			request_timeout = 60)

		# res = es.search(index='dns-sjtu-index0',body={'from':0,'size':2500,'query':{'match':{'domain':domain}}})
		for hit in res['hits']['hits']:
			print hit
		print res['hits']['total']
