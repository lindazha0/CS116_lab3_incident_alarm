#!/usr/bin/python3

from scapy.all import *
import argparse


incident_number = 0
def packetcallback(packet):
  try:
    global incident_number
    alarm = False

    # Your tool shall be able to analyze for the following incidents:
    # NULL scan - no flags set
    if packet[TCP].flags == 0:
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
    #   - base64 encoded
    elif packet[TCP].dport == 80 or packet[TCP].dport == 21 or packet[TCP].dport == 143:
      if packet[TCP].payload:
        payload = packet[TCP].payload.load
        if payload:
          if payload.decode('utf-8').startswith('USER') or payload.decode('utf-8').startswith('PASS'):
            incident_number += 1
            incident = "Username and password sent in-the-clear"
            src_ip = packet[IP].src
            protocol_or_port = 'TCP'
            payload = ' (' + payload.decode('utf-8')[:-2] + ')' # remove \r\n
            alarm = True

    # Nikto scan - User-Agent contains "nikto"
    # Someone scanning for Server Message Block (SMB) protocol - port 445
    # Someone scanning for Remote Desktop Protocol (RDP) - port 3389
    # Someone scanning for Virtual Network Computing (VNC) instance(s) - port 5900
    # The following is an example of Scapy detecting HTTP traffic - port 80
    # Please remove this case in your actual lab implementation so it doesn't pollute the alerts

    if alarm:
      # sample alert
      print(f'ALERT #{incident_number}: {incident} is detected from {src_ip}',
            f'({protocol_or_port}){payload}!')
  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    print("ERROR: ", e)
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
