IP_flags = {'0': 1, '': 2, 'DF': 3, 'MF': 4}
TCP_flags = {'0': 1, 'S': 2, 'SA': 3, 'A': 4, 'PA': 5, 'FPA': 6, 'FA': 7, 'R': 8, 'RA': 9, 'SEC': 10, 'F': 11, 'PAC': 12, 'AC': 13,'SAE':14,'FAU':15}
BOOTP_flags = {'0': 1, '': 2, 'B': 3, 0: 1}
Protocol = {'EAPOL': 1, 'DHCP': 2, 'DNS': 3, 'TCP': 4, 'HTTP': 5, 'ICMP': 6, 'MDNS': 7, 'IGMPv3': 8, 'SSDP': 9, 'NTP': 10, 'HTTP/XML': 11, 'UDP': 12, 'SSLv2': 13, 'TLSv1': 14, 'ADwin Config': 15, 'TLSv1.2': 16, 'ICMPv6': 17, 'HTTP/JSON': 18, 'XID': 19, 'TFTP': 20, 'NXP 802.15.4 SNIFFER': 21, 'IGMPv2': 22, 'A21': 23, 'STUN': 24, 'Gearman': 25, '? KNXnet/IP': 26, 'UDPENCAP': 27, 'ESP': 28, 'SSL': 29, 'NBNS': 30, 'SIP': 31, 'BROWSER': 32, 'SABP': 33, 'ISAKMP': 34, 'CLASSIC-STUN': 35, 'Omni-Path': 36, 'XMPP/XML': 37, 'ULP': 38, 'TFP over TCP': 39, 'AX4000': 40, 'MIH': 41, 'DHCPv6': 42, 'TDLS': 43, 'RTMP': 44, 'TCPCL': 45, 'IPA': 46, 'GQUIC': 47, '0x86dd': 48, 'DB-LSP-DISC': 49, 'SSLv3': 50, 'LLMNR': 51, 'FB_ZERO': 52, 'OCSP': 53, 'IPv4': 54, 'STP': 55, 'SSH': 56, 'TLSv1.1': 57, 'KINK': 58, 'MANOLITO': 59, 'PKTC': 60, 'TELNET': 61, 'RTSP': 62, 'HCrt': 63, 'MPTCP': 64, 'S101': 65, 'IRC': 66, 'AJP13': 67, 'PMPROXY': 68, 'PNIO': 69, 'AMS': 70, 'ECATF': 71, 'LLC': 72, 'TZSP': 73,'RSIP':74,'SSHv2':75
,'DIAMETER':76
,'BFD Control':77
,'ASAP':78
,'DISTCC':79 
,'DISTCC ':79       
,'LISP':80
,'WOW':81
,'DTLSv1.0':82
,'SNMP':83
,'SMB2':84
,'SMB':85
,'NBSS':86
,'UDT':87,'HiQnet':88
,'POWERLINK/UDP':89
,'RTP':90
,'WebSocket':91
,'NAT-PMP':92
,'RTCP':93,'Syslog':94
,'Portmap':95
,'OpenVPN':96
,'BJNP':97
,'RIPv1':98
,'MAC-Telnet':99
,'ECHO':100
,'ASF':101
,'DAYTIME':102
,'SRVLOC':103
,'KRB4':104
,'CAPWAP-Control':105
,'XDMCP':106
,'Chargen':107
,'RADIUS':108
,'L2TP':109
,'DCERPC':110
,'KPASSWD':111
,'H264':112
,'FTP':113
,'FTP-DATA':114
,'ENIP':115
,'RIPv2':116
,'ICP':117,
"BACnet-APDU":118,
"IAX2":119,
"RX":120,
"HTTP2":121,
"SIP/SDP":122,
"TIME":123,
"Elasticsearch":124,
"RSL":125,
"TPCP":126,
 "IPv6":  127 }

FEATURE_DICT = {'pck_size': int, 'Ether_type': int, 'LLC_ctrl': int, 'EAPOL_version': int, 'EAPOL_type': int, 'IP_ihl': int, 'IP_tos': int, 'IP_len': int, 'IP_flags': int,
                    'IP_DF': int, 'IP_ttl': int, 'IP_options': int, 'ICMP_code': int, 'TCP_dataofs': int, 'TCP_FIN': int, 'TCP_ACK': int,
                    'TCP_window': int, 'UDP_len': int, 'DHCP_options': int, 'BOOTP_hlen': int, 'BOOTP_flags': int, 'BOOTP_sname': int,
                    'BOOTP_file': int, 'BOOTP_options': int, 'DNS_qr': int, 'DNS_rd': int, 'DNS_qdcount': int, 'dport_class': int,
                    'payload_bytes': int, 'entropy': float, "MAC": object, 'Label': object}