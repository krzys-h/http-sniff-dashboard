import time
from dnslib.server import DNSLogger, DNSServer
from dnslib.fixedresolver import FixedResolver

resolver = FixedResolver(". 60 IN A 10.15.0.9")
logger = DNSLogger(prefix=False)
server = DNSServer(resolver,port=53,address='',logger=logger)
server.start_thread()

while True:
    time.sleep(1)
    pass
