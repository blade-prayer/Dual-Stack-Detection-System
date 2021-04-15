import argparse
import logging
from domain_search import domain_search 
from dual_detection import dual_stack_hosts_detection
from threat_detection import threat_detection

parser = argparse.ArgumentParser()
parser.add_argument("--domain", required=False, help="domain for detecting dual-stack hosts", type=str, default="sjtu.edu.cn")
parser.add_argument("--subDomainFile", help="file name for storing subdomain scan results of dual stack", type=str, default="./subdomain.csv")
parser.add_argument('--searchEngineScan', help="whether using search engine for subdomain scaning, may take a while...", action='store_true')
parser.add_argument("--logFile", help="file name for storing detection security log", type=str, default="./dual_stack.log")
args = parser.parse_args()

if __name__ == '__main__':
	subdomains = domain_search(args.domain, args.searchEngineScan)
	subdomains.search()
	dualStackHosts = dual_stack_hosts_detection(args.domain, args.subDomainFile)
	dualStackHosts.detection()
	logging.basicConfig(filename=args.logFile, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
	logger = logging.getLogger()
	threat = threat_detection(args.subDomainFile, logger)
	threat.detection()
