#!/usr/bin/env python

# modified somewhat from its form @ 
# https://mmishou.wordpress.com/2010/04/13/passive-dns-mining-from-pcap-with-dpkt-python/

import dpkt
import datetime
import socket
import sys
import qtypes

if len(sys.argv) < 2 or len(sys.argv) > 2:
	print "Usage:\n", sys.argv[0], "filename.pcap"
	sys.exit()

f = open(sys.argv[1])
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
	# make sure we are dealing with IP traffic
	# ref: http://www.iana.org/assignments/ethernet-numbers
	try: eth = dpkt.ethernet.Ethernet(buf)
	except: continue
	if eth.type == dpkt.ethernet.ETH_TYPE_IP:
		# make sure we are dealing with UDP
		# ref: http://www.iana.org/assignments/protocol-numbers/
		try: ip = eth.data
		except: continue
		if ip.p != 17: continue
		# filter on UDP assigned ports for DNS
		# ref: http://www.iana.org/assignments/port-numbers
		try: udp = ip.data
		except: continue
		if udp.sport != 53 and udp.dport != 53: continue
		# make the dns object out of the udp data and check for it being a RR (answer)
		# and for opcode QUERY (I know, counter-intuitive)
		try: dns = dpkt.dns.DNS(udp.data)
		except: continue
		if dns.qr != dpkt.dns.DNS_R: continue
		if dns.opcode != dpkt.dns.DNS_QUERY: continue
		if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
		if len(dns.an) < 1: continue
		# now we're going to process and spit out responses based on record type
		# ref: http://en.wikipedia.org/wiki/List_of_DNS_record_types
		for answer in dns.an:
			qtype_name = qtypes.qtypes[str(answer.type)]
			ip_src = socket.inet_ntoa(ip.src)
			if ip_src == "192.160.102.147" or ip_src == "104.131.53.95": continue
			print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(ts))
			print ip_src, " ", qtype_name, " ", answer.name
	elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
		# make sure we are dealing with UDP
		# ref: http://www.iana.org/assignments/protocol-numbers/
		try: ipv6 = eth.data
		except: continue
		if ipv6.get_proto != 17: continue
		# filter on UDP assigned ports for DNS
		# ref: http://www.iana.org/assignments/port-numbers
		try: udp = ipv6.data
		except: continue
		if udp.sport != 53 and udp.dport != 53: continue
		# make the dns object out of the udp data and check for it being a RR (answer)
		# and for opcode QUERY (I know, counter-intuitive)
		try: dns = dpkt.dns.DNS(udp.data)
		except: continue
		if dns.qr != dpkt.dns.DNS_R: continue
		if dns.opcode != dpkt.dns.DNS_QUERY: continue
		if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
		if len(dns.an) < 1: continue
		# now we're going to process and spit out responses based on record type
		# ref: http://en.wikipedia.org/wiki/List_of_DNS_record_types
		for answer in dns.an:
			qtype_name = qtypes.qtypes[str(answer.type)]
			ip_src = socket.inet_ntop(AF_INET6, ipv6.src)
			print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(ts))
			print ip_src, " ", qtype_name, " ", answer.name
	continue
