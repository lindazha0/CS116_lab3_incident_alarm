#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

incident_number = 0
username = {}
def packetcallback(packet):
  try:
    # from Piazza: we generally don't care for non-TCP packets.
    if not packet.haslayer(TCP):
      return
    global incident_number
    global username
    alarm = False

    # print(f"ID {packet.id} is a TCP packet with flag {packet[TCP].flags}")
    # nalyze for the following incidents:
    # NULL scan - no flags set
    if packet[TCP].flags == 0x0:
      incident_number += 1
      incident = "NULL scan"
      src_ip = packet[IP].src
      protocol_or_port = 'TCP'
      payload = ''
      alarm = True

    # FIN scan - only FIN flag set
    elif packet[TCP].flags == 'F':
      incident_number += 1
      incident = "FIN scan"
      src_ip = packet[IP].src
      protocol_or_port = 'TCP'
      payload = ''
      alarm = True

    # Xmas scan - FIN, PSH, and URG flags set
    elif packet[TCP].flags == 'FPU':
      incident_number += 1
      incident = "Xmas scan"
      src_ip = packet[IP].src
      protocol_or_port = 'TCP'
      payload = ''
      alarm = True

    # Usernames and passwords sent in-the-clear via HTTP Basic Authentication, FTP, and IMAP
    #   - port 80/ 21/ 143, base64 encoded
    elif packet[TCP].dport == 8000 or packet[TCP].dport == 80 or packet[TCP].dport == 21 or packet[TCP].dport == 143:
      if packet[TCP].payload:
        payload = packet[TCP].load.decode("ascii").strip()

        # 1: base64 decode
        if payload.startswith('GET') or payload.startswith('POST'):
          b64_index = payload.find('Authorization: Basic')+21
          if b64_index != -1:
            b64_end = payload.find('\r\n', b64_index)
            pair = base64.b64decode(payload[b64_index:b64_end]).decode('ascii')
            username, passwd = pair.split(':')

            incident_number += 1
            incident = "Username and passwords sent in-the-clear"
            src_ip = packet[IP].src
            protocol_or_port = 'IMAP' if packet[TCP].dport == 143 else 'FTP' if packet[TCP].dport == 21 else 'HTTP'
            payload = f'(username: {username}, password: {passwd})'
            alarm = True

        # 2: no base64 encoding
        # keep track of username
        elif payload.startswith('USER'):
          username = payload[5:-2]
        # match username and password
        elif payload.startswith('PASS'):
          incident_number += 1
          incident = "Username and passwords sent in-the-clear"
          src_ip = packet[IP].src
          protocol_or_port = 'IMAP' if packet[TCP].dport == 143 else 'FTP' if packet[TCP].dport == 21 else 'HTTP'
          payload = f'(username: {username}, password: {payload[5:-2]})'
          alarm = True

    # Nikto scan - no idea what this is

    # Someone scanning for Server Message Block (SMB) protocol - port 445
    elif packet[TCP].dport == 445:
      incident_number += 1
      incident = "Someone scanning for SMB"
      src_ip = packet[IP].src
      protocol_or_port = 'TCP'
      payload = ''
      alarm = True

    # Someone scanning for Remote Desktop Protocol (RDP) - port 3389
    elif packet[TCP].dport == 3389:
      incident_number += 1
      incident = "Someone scanning for or RDP"
      src_ip = packet[IP].src
      protocol_or_port = 'TCP'
      payload = ''
      alarm = True

    # Someone scanning for Virtual Network Computing (VNC) instance(s) - port 5900
    elif packet[TCP].dport == 5900:
      incident_number += 1
      incident = "Someone scanning for VNC"
      src_ip = packet[IP].src
      protocol_or_port = 'TCP'
      payload = ''
      alarm = True

    if alarm:
      # sample alert
      print(f'ALERT #{incident_number}: {incident} is detected from {src_ip}',
            f'({protocol_or_port}){payload}!')

  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    # print("ERROR: ", e)
    pass

# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
