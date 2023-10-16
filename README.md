# CS116_lab3_incident_alarm
Assignments for CS116: Introduction to Security at Tufts in 2023 Fall. In this lab, Scapy is used to detect several types of scans and potential crisis.

#### Requirements
- [x] Identify what aspects of the work have been correctly implemented and what have not.
  - As indicated from Piazza, I filtered out all packets that are not TCP-based, and determine the protocol from the port number.
  - NULL/ FIN/ Xmas scan could be correctely detected from the TCP flags and alerted for `null.pcap`, `fin.pcap`, `xmas.pcap`.
  - user-passwd in-the-clear through HTTP Basic/ FTP/ IMAP detection for `set1.pcap`, and decoded from base64, for `set0.pcap`. The user-passwd is extracted from the packet payload.
  - Not finding enough info for Nikto scan, still on it...
  - Detected scanning from different ports for SMB/ RDP/ VNC for `smb.pcap`, `rdp.pcap`, `vnc.pcap`.
- [x] Identify anyone with whom you have collaborated or discussed the assignment.
    - None. I referred to piazza discussions and some links below.
    - scapy tutorials: https://scapy.readthedocs.io/en/latest/usage.html#simple-one-liners
    - For scan flags: https://nmap.org/book/scan-methods-null-fin-xmas-scan.html
- [x] Say approximately how many hours you have spent completing the assignment.
  - Around 8h in total.
  - 3h for reviewing the course materials and understanding the lab (and `scapy`), 3h for clarifying the concepts and designing the program, 2h for coding and debugging.
- [x] List any additional dependencies used.
  - `base64` for decoding the base64 encoded user-passwd.
- [x] For this lab, you must also address the following questions:
  - [x] Are the heuristics used in this assignment to determine incidents "even that good"?
    - Yes for now, at least the provided pcap files.
  - [x] If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
    - I hope the tool could be better structured to detect for each credential separately and produce a thourough report. (Even if there is no incident detected in some part, which could be achieved by keeping track of the some global variables and print only in the very end) I have not figure out each incidents now so the code is very poorly structured.
    - I am still working on the Nikto scan detection, which is not included in the code now.

<!--
### instructions
Your tool shall be able to analyze for the following incidents:
NULL scan
FIN scan
Xmas scan
Usernames and passwords sent in-the-clear via HTTP Basic Authentication, FTP, and IMAP
Nikto scan
Someone scanning for Server Message Block (SMB) protocol
Someone scanning for Remote Desktop Protocol (RDP)
Someone scanning for Virtual Network Computing (VNC) instance(s)
-->
