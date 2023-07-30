from threading import Thread
from scapy.all import *
from netaddr import *
from time import sleep
import netifaces as ni
import optparse
import smtplib
import sys
import sqlite3
from datetime import datetime


def startscreen():
	print('\033c')
	print("****************************************")
	print("* DNS-Sniffer  V.2.0 by Reto Schaedler *")
	print("****************************************")
	print()


def packetSniffer(pkt, c, conn):
	if pkt.haslayer(DNSQR):
		timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		dnsName=(str(pkt[DNS].qd.qname)[2:-2])
		if IPv6 in pkt:
			ipAddr=(str(pkt[IPv6].dst))
		else:
			ipAddr=(str(pkt[IP].dst))
		mac_address=pkt[Ether].dst
		c.execute("INSERT INTO dns_requests VALUES (?,?,?,?)", (timestamp, ipAddr, mac_address, dnsName))
		conn.commit()


def dnsSniffer():
	global intf
	####ni.ifaddresses(intf)
	#localIP = ni.ifaddresses(intf)[ni.AF_INET][0]['addr']
	#filterstr="udp and src port 53 and (host not " + localIP + ")"
    
	# Verbindung zur SQLite-Datenbank herstellen
	conn = sqlite3.connect('dns_requests.db')

	# Cursor erstellen
	c = conn.cursor()

	# Tabelle erstellen
	c.execute('''CREATE TABLE IF NOT EXISTS dns_requests
             (timestamp text, client_ip text, mac_address text, dns_request text)''')
    
	filterstr="udp and src port 53"
	sniff(filter=filterstr, iface=intf, store=0, prn=lambda pkt: packetSniffer(pkt, c, conn))


def get_option(dhcp_options, key):
	must_decode = ['hostname', 'domain', 'vendor_class_id']
	try:
		for i in dhcp_options:
			if i[0] == key:
				# If DHCP Server Returned multiple name servers 
				# return all as comma seperated string.
				if key == 'name_server' and len(i) > 2:
					return ",".join(i[1:])
				# domain and hostname are binary strings,
				# decode to unicode string before returning
				elif key in must_decode:
					return i[1].decode()
				else: 
					return i[1]        
	except:
		pass


def handle_dhcp_packet(packet, c, conn):
	# Match DHCP request
	if DHCP in packet and packet[DHCP].options[0][1] == 3:
		requested_addr = get_option(packet[DHCP].options, 'requested_addr')
		hostname = get_option(packet[DHCP].options, 'hostname')
		timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		if packet[IP].src == "0.0.0.0":		
		#	dhcpname[requested_addr]=hostname
			ipAddr=requested_addr
			mac_address=packet[Ether].dst            
		else:
			ipAddr=str(packet[IP].src)
			mac_address=packet[Ether].src
		#	dhcpname[str(packet[IP].src)]=hostname
		c.execute("INSERT INTO dhcp_name VALUES (?,?,?,?)", (timestamp, ipAddr, mac_address, hostname))
		conn.commit()
	return

def dhcpListener():
	global intf

	# Verbindung zur SQLite-Datenbank herstellen
	conn = sqlite3.connect('dhcp_name.db')

	# Cursor erstellen
	c = conn.cursor()

	# Tabelle erstellen
	c.execute('''CREATE TABLE IF NOT EXISTS dhcp_name
             (timestamp text, client_ip text, mac_address text, dhcp_name text)''')    

	sniff(filter="udp and (port 67 or 68)", iface=intf,prn=lambda pkt: handle_dhcp_packet(pkt, c, conn))


if __name__ == '__main__':

	parser = optparse.OptionParser()
	parser.add_option('-i', '--interface',
	    action="store", dest="interface",
	    help="query string", default="Ethernet 5")
	options, args = parser.parse_args()

	intf=options.interface

	startscreen()


	th = Thread(target=dnsSniffer)
	th.start()
	
	th2 = Thread(target=dhcpListener)
	th2.start()