import csv
import math
import os
import pandas as pd

from scapy.all import *
from src.constants import *
from src.util import list_files

def shannon(data):
    LOG_BASE = 2
   # We determine the frequency of each byte
   # in the dataset and if this frequency is not null we use it for the
   # entropy calculation
    dataSize = len(data)
    ent = 0.0
    freq={} 
    for c in data:
        if c in freq:
            freq[c] += 1
        else:
            freq[c] = 1
   # to determine if each possible value of a byte is in the list
    for key in freq.keys():
        f = float(freq[key])/dataSize
        if f > 0: # to avoid an error for log(0)
            ent = ent + f * math.log(f, LOG_BASE)
    return -ent


def pre_entropy(payload):
    
    characters=[]
    for i in payload:
            characters.append(i)
    return shannon(characters)


def port_class(port):
    port_list=[0,53,67,68,80,123,443,1900,5353,49153]
    if port in port_list:
        return port_list.index(port)+1
    elif 0 <= port <= 1023:
        return 11
    elif  1024 <= port <= 49151 :
        return 12
    elif 49152 <=port <= 65535 :
        return 13
    else:
        return 0
    
    
def port_1023(port):
    if 0 <= port <= 1023:
        return port
    elif  1024 <= port <= 49151 :
        return 2
    elif 49152 <=port <= 65535 :
        return 3
    else:
        return 0
    


def extract_features(pcap_list, device_mac_map):
    header = ['pck_size', 'Ether_type', 'LLC_dsap', 'LLC_ssap', 'LLC_ctrl', 'EAPOL_version', 'EAPOL_type', 'EAPOL_len', 'IP_version', 'IP_ihl', 'IP_tos',
    'IP_len', 'IP_flags', 'IP_Z', 'IP_MF', 'IP_id', 'IP_chksum', 'IP_DF', 'IP_frag', 'IP_ttl', 'IP_proto', 'IP_options', 'IP_add_count',
    'ICMP_type', 'ICMP_code', 'ICMP_chksum', 'ICMP_id', 'ICMP_seq', 'ICMP_ts_ori', 'ICMP_ts_rx', 'ICMP_ts_tx', 'ICMP_ptr', 'ICMP_reserved',
    'ICMP_length', 'ICMP_nexthopmtu', 'ICMP_unused', 'TCP_seq', 'TCP_ack', 'TCP_dataofs', 'TCP_reserved', 'TCP_flags', 'TCP_FIN', 'TCP_SYN',
    'TCP_RST', 'TCP_PSH', 'TCP_ACK', 'TCP_URG', 'TCP_ECE', 'TCP_CWR', 'TCP_window', 'TCP_chksum', 'TCP_urgptr', 'TCP_options', 'UDP_len', 'UDP_chksum', 'DHCP_options',
    'BOOTP_op', 'BOOTP_htype', 'BOOTP_hlen', 'BOOTP_hops', 'BOOTP_xid', 'BOOTP_secs', 'BOOTP_flags', 'BOOTP_sname', 'BOOTP_file', 'BOOTP_options', 'DNS_length', 'DNS_id',
    'DNS_qr', 'DNS_opcode', 'DNS_aa', 'DNS_tc', 'DNS_rd', 'DNS_ra', 'DNS_z', 'DNS_ad', 'DNS_cd', 'DNS_rcode', 'DNS_qdcount', 'DNS_ancount', 'DNS_nscount',
    'DNS_arcount', 'sport_class', 'dport_class', 'sport23', 'dport23', 'sport_bare', 'dport_bare', 'TCP_sport', 'TCP_dport', 'UDP_sport',
    'UDP_dport', 'payload_bytes', 'entropy', 'MAC', 'Label']

    #flags
    #TCP
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80
    #IP
    Z = 0x00
    MF= 0x01
    DF= 0x02

    dst_ip_list={}
    Ether_adresses=[]
    IP_adresses=[]


    for iter, pcap_file in enumerate(pcap_list):
            
        filename = pcap_file[:-5] + ".csv"
        if os.path.exists(filename):
            continue
        
        csvfile = open(filename, "w")
        writer = csv.DictWriter(csvfile, fieldnames=header)
        writer.writeheader()

        print("Filename:", filename)

        data = []
        
        #break
        pkt = rdpcap(pcap_file)

        sayaç=len(pkt)//20
        for jj, j in enumerate(pkt):
            
            try:        
                if jj%sayaç==0:

                        sys.stdout.write("\r[" + "=" * int(jj//sayaç) +  " " * int((sayaç*20 - jj)// sayaç) + "]" +  str(5*jj//sayaç) + "%")
                        sys.stdout.flush()
            except:
                pass

            if j.haslayer(ARP):
                continue
            else:
                
                ts = j.time
                try:
                    pck_size = int(j.len)
                except:
                    pck_size=0

                if j.haslayer(Ether):

                    if j[Ether].dst not in Ether_adresses:
                        Ether_adresses.append(j[Ether].dst)
                    if j[Ether].src not in Ether_adresses:
                        Ether_adresses.append(j[Ether].src)

                    Ether_dst = j[Ether].dst #Ether_adresses.index(j[Ether].dst)+1
                    Ether_src = j[Ether].src #Ether_adj[Ether].dstresses.index(j[Ether].src)+1
                    Ether_type = j[Ether].type

                else:
                    Ether_dst=0
                    Ether_src=0
                    Ether_type=0     


                if j.haslayer(LLC):
                    LLC_dsap = j[LLC].dsap
                    LLC_ssap = j[LLC].ssap
                    LLC_ctrl = j[LLC].ctrl
                else:
                    LLC_dsap=0
                    LLC_ssap=0
                    LLC_ctrl=0            



                if j.haslayer(EAPOL):
                    EAPOL_version=j[EAPOL].version
                    EAPOL_type=j[EAPOL].type
                    EAPOL_len=j[EAPOL].len

                else:
                    EAPOL_version=0
                    EAPOL_type=0
                    EAPOL_len=0            


                if j.haslayer(IP):

                    IP_Z = 0
                    IP_MF= 0
                    IP_DF= 0

                    IP_version=j[IP].version
                    IP_ihl=j[IP].ihl
                    IP_tos=j[IP].tos
                    IP_len=j[IP].len
                    IP_id=j[IP].id
                    IP_flags=j[IP].flags

                    IP_frag=j[IP].frag
                    IP_ttl=j[IP].ttl
                    IP_proto=j[IP].proto
                    IP_chksum=j[IP].chksum


                    #if j[IP].options!=0:
                    IP_options=j[IP].options
                    if "IPOption_Router_Alert"   in str(IP_options):
                        IP_options=1
                    else:IP_options=0
                    
                    
                    if j[Ether].src not in dst_ip_list:
                        dst_ip_list[j[Ether].src]=[]
                        dst_ip_list[j[Ether].src].append(j[IP].dst)
                    elif j[IP].dst not in dst_ip_list[j[Ether].src]:
                        dst_ip_list[j[Ether].src].append(j[IP].dst)
                    IP_add_count=len(dst_ip_list[j.src])

                    #if IP_flags not in ipf: ipf.append(IP_flags)

                    if IP_flags & Z:IP_Z = 1
                    if IP_flags & MF:IP_MF = 1
                    if IP_flags & DF:IP_DF = 1
                    #if "Flag" in str(IP_flags):
                        #IP_flags=str(IP_flags)
                        #temp=IP_flags.find("(")
                        #IP_flags=int(IP_flags[6:temp-1])


                    if j[IP].src not in IP_adresses:
                        IP_adresses.append(j[IP].src)
                    if j[IP].dst  not in IP_adresses:
                        IP_adresses.append(j[IP].dst)           

                    IP_src=j[IP].src#IP_adresses.index(j[IP].src)+1
                    IP_dst=j[IP].dst#IP_adresses.index(j[IP].dst)+1                


                else:
                    IP_Z = 0
                    IP_MF= 0
                    IP_DF= 0

                    IP_version=0
                    IP_ihl=0
                    IP_tos=0
                    IP_len=0
                    IP_id=0
                    IP_flags=0
                    IP_frag=0
                    IP_ttl=0
                    IP_proto=0
                    IP_chksum=0
                    IP_src=0
                    IP_dst=0
                    IP_options=0
                    IP_add_count=0            

                if j.haslayer(ICMP):
                    ICMP_type=j[ICMP].type
                    ICMP_code=j[ICMP].code
                    ICMP_chksum=j[ICMP].chksum
                    ICMP_id=j[ICMP].id
                    ICMP_seq=j[ICMP].seq
                    ICMP_ts_ori=j[ICMP].ts_ori
                    ICMP_ts_rx=j[ICMP].ts_rx
                    ICMP_ts_tx=j[ICMP].ts_tx
                    ICMP_gw=j[ICMP].gw
                    ICMP_ptr=j[ICMP].ptr
                    ICMP_reserved=j[ICMP].reserved
                    ICMP_length=j[ICMP].length
                    ICMP_addr_mask=j[ICMP].addr_mask
                    ICMP_nexthopmtu=j[ICMP].nexthopmtu
                    ICMP_unused=j[ICMP].unused
                else:
                    ICMP_type=0
                    ICMP_code=0
                    ICMP_chksum=0
                    ICMP_id=0
                    ICMP_seq=0
                    ICMP_ts_ori=0
                    ICMP_ts_rx=0
                    ICMP_ts_tx=0
                    ICMP_gw=0
                    ICMP_ptr=0
                    ICMP_reserved=0
                    ICMP_length=0
                    ICMP_addr_mask=0
                    ICMP_nexthopmtu=0
                    ICMP_unused=0


                if j.haslayer(TCP):
                    TCP_FIN = 0
                    TCP_SYN = 0
                    TCP_RST = 0
                    TCP_PSH = 0
                    TCP_ACK = 0
                    TCP_URG = 0
                    TCP_ECE = 0
                    TCP_CWR = 0
                    TCP_sport=j[TCP].sport
                    TCP_dport=j[TCP].dport
                    TCP_seq=j[TCP].seq
                    TCP_ack=j[TCP].ack
                    TCP_dataofs=j[TCP].dataofs
                    TCP_reserved=j[TCP].reserved
                    TCP_flags=j[TCP].flags

                    TCP_window=j[TCP].window
                    TCP_chksum=j[TCP].chksum
                    TCP_urgptr=j[TCP].urgptr
                    TCP_options=j[TCP].options
                    TCP_options= str(TCP_options).replace(",","-")
                    if TCP_options!="0":
                        TCP_options=1
                    else:
                        TCP_options=0
                    
                    
                    #if TCP_flags not in tcpf:
                        #tcpf.append(TCP_flags)
                    #print(TCP_options)
                    if TCP_flags & FIN:TCP_FIN = 1
                    if TCP_flags & SYN:TCP_SYN = 1
                    if TCP_flags & RST:TCP_RST = 1
                    if TCP_flags & PSH:TCP_PSH = 1
                    if TCP_flags & ACK:TCP_ACK = 1
                    if TCP_flags & URG:TCP_URG = 1
                    if TCP_flags & ECE:TCP_ECE = 1
                    if TCP_flags & CWR:TCP_CWR = 1   
                    #print(TCP_flags)
                    #if "Flag" in str(TCP_flags):
                        #TCP_flags=str(TCP_flags)
                        #temp=TCP_flags.find("(")
                        #TCP_flags=int(TCP_flags[6:temp-1])
                        

                else:
                    TCP_sport=0
                    TCP_dport=0
                    TCP_seq=0
                    TCP_ack=0
                    TCP_dataofs=0
                    TCP_reserved=0
                    TCP_flags=0
                    TCP_window=0
                    TCP_chksum=0
                    TCP_urgptr=0
                    TCP_options=0
                    TCP_options=0
                    TCP_FIN = 0
                    TCP_SYN = 0
                    TCP_RST = 0
                    TCP_PSH = 0
                    TCP_ACK = 0
                    TCP_URG = 0
                    TCP_ECE = 0
                    TCP_CWR = 0


                if j.haslayer(UDP):
                    UDP_sport=j[UDP].sport
                    UDP_dport=j[UDP].dport
                    UDP_len=j[UDP].len
                    UDP_chksum=j[UDP].chksum
                else:
                    UDP_sport=0
                    UDP_dport=0
                    UDP_len=0
                    UDP_chksum=0


                if j.haslayer(DHCP):
                    DHCP_options=str(j[DHCP].options)
                    DHCP_options=DHCP_options.replace(",","-")
                    if "message" in DHCP_options:
                        x = DHCP_options.find(")")
                        DHCP_options=int(DHCP_options[x-1])
                        
                else:
                    DHCP_options=0            


                if j.haslayer(BOOTP):
                    BOOTP_op=j[BOOTP].op
                    BOOTP_htype=j[BOOTP].htype
                    BOOTP_hlen=j[BOOTP].hlen
                    BOOTP_hops=j[BOOTP].hops
                    BOOTP_xid=j[BOOTP].xid
                    BOOTP_secs=j[BOOTP].secs
                    BOOTP_flags=j[BOOTP].flags
                    #if "Flag" in str(BOOTP_flags):BOOTP_flags=str(BOOTP_flags)temp=BOOTP_flags.find("(") BOOTP_flags=int(BOOTP_flags[6:temp-1])
                    BOOTP_ciaddr=j[BOOTP].ciaddr
                    BOOTP_yiaddr=j[BOOTP].yiaddr
                    BOOTP_siaddr=j[BOOTP].siaddr
                    BOOTP_giaddr=j[BOOTP].giaddr
                    BOOTP_chaddr=j[BOOTP].chaddr
                    BOOTP_sname=str(j[BOOTP].sname)
                    if BOOTP_sname!="0":
                        BOOTP_sname=1
                    else:
                        BOOTP_sname=0
                    BOOTP_file=str(j[BOOTP].file)
                    if BOOTP_file!="0":
                        BOOTP_file=1
                    else:
                        BOOTP_file=0
                    
                    BOOTP_options=str(j[BOOTP].options)
                    BOOTP_options=BOOTP_options.replace(",","-")
                    if BOOTP_options!="0":
                        BOOTP_options=1
                    else:
                        BOOTP_options=0
                else:
                    BOOTP_op=0
                    BOOTP_htype=0
                    BOOTP_hlen=0
                    BOOTP_hops=0
                    BOOTP_xid=0
                    BOOTP_secs=0
                    BOOTP_flags=0
                    BOOTP_ciaddr=0
                    BOOTP_yiaddr=0
                    BOOTP_siaddr=0
                    BOOTP_giaddr=0
                    BOOTP_chaddr=0
                    BOOTP_sname=0
                    BOOTP_file=0
                    BOOTP_options=0


                if j.haslayer(DNS):
                    DNS_length=j[DNS].length
                    DNS_id=j[DNS].id
                    DNS_qr=j[DNS].qr
                    DNS_opcode=j[DNS].opcode
                    DNS_aa=j[DNS].aa
                    DNS_tc=j[DNS].tc
                    DNS_rd=j[DNS].rd
                    DNS_ra=j[DNS].ra
                    DNS_z=j[DNS].z
                    DNS_ad=j[DNS].ad
                    DNS_cd=j[DNS].cd
                    DNS_rcode=j[DNS].rcode
                    DNS_qdcount=j[DNS].qdcount
                    DNS_ancount=j[DNS].ancount
                    DNS_nscount=j[DNS].nscount
                    DNS_arcount=j[DNS].arcount
                    DNS_qd=str(j[DNS].qd).replace(",","-")
                    if DNS_qd!="0":
                        DNS_qd=1
                    else:
                        DNS_qd=0
                    DNS_an=str(j[DNS].an).replace(",","-")
                    if DNS_an!="0":
                        DNS_an=1
                    else:
                        DNS_an=0
                    DNS_ns=str(j[DNS].ns).replace(",","-")
                    if DNS_ns!="0":
                        DNS_ns=1
                    else:
                        DNS_ns=0
                    DNS_ar=str(j[DNS].ar).replace(",","-")
                    if DNS_ar!="0":
                        DNS_ar=1
                    else:
                        DNS_ar=0
                else:
                    DNS_length=0
                    DNS_id=0
                    DNS_qr=0
                    DNS_opcode=0
                    DNS_aa=0
                    DNS_tc=0
                    DNS_rd=0
                    DNS_ra=0
                    DNS_z=0
                    DNS_ad=0
                    DNS_cd=0
                    DNS_rcode=0
                    DNS_qdcount=0
                    DNS_ancount=0
                    DNS_nscount=0
                    DNS_arcount=0
                    DNS_qd=0
                    DNS_an=0
                    DNS_ns=0
                    DNS_ar=0


                pdata=[]
                if "TCP" in j:            
                    pdata = (j[TCP].payload)
                if "Raw" in j:
                    pdata = (j[Raw].load)
                elif "UDP" in j:            
                    pdata = (j[UDP].payload)
                elif "ICMP" in j:            
                    pdata = (j[ICMP].payload)
                pdata=list(memoryview(bytes(pdata)))            
        
                if pdata!=[]:
                    entropy=shannon(pdata)        
                else:
                    entropy=0
                payload_bytes=len(pdata)

                sport_class = port_class(TCP_sport + UDP_sport)
                dport_class = port_class(TCP_dport + UDP_dport)
                sport23 = port_1023(TCP_sport + UDP_sport)
                dport23 = port_1023(TCP_dport + UDP_dport)
                sport_bare = TCP_sport + UDP_sport
                dport_bare = TCP_dport + UDP_dport#port_class(TCP_dport+UDP_dport)
                
                try:
                    label=device_mac_map[j.src]
                except:
                    label=""
                Mac=j.src             
                
                             
                line = {
                    "pck_size": pck_size,
                    "Ether_type": Ether_type,
                    "LLC_dsap": LLC_dsap,
                    "LLC_ssap": LLC_ssap,
                    "LLC_ctrl": LLC_ctrl,
                    "EAPOL_version": EAPOL_version,
                    "EAPOL_type": EAPOL_type,
                    "EAPOL_len": EAPOL_len,
                    "IP_version": IP_version,
                    "IP_ihl": IP_ihl,
                    "IP_tos": IP_tos,
                    "IP_len": IP_len,
                    "IP_flags": IP_flags,
                    "IP_Z": IP_Z,
                    "IP_MF": IP_MF,
                    "IP_id": IP_id,
                    "IP_chksum": IP_chksum,
                    "IP_DF": IP_DF,
                    "IP_frag": IP_frag,
                    "IP_ttl": IP_ttl,
                    "IP_proto": IP_proto,
                    "IP_options": IP_options,
                    "IP_add_count": IP_add_count,
                    "ICMP_type": ICMP_type,
                    "ICMP_code": ICMP_code,
                    "ICMP_chksum": ICMP_chksum,
                    "ICMP_id": ICMP_id,
                    "ICMP_seq": ICMP_seq,
                    "ICMP_ts_ori": ICMP_ts_ori,
                    "ICMP_ts_rx": ICMP_ts_rx,
                    "ICMP_ts_tx": ICMP_ts_tx,
                    "ICMP_ptr": ICMP_ptr,
                    "ICMP_reserved": ICMP_reserved,
                    "ICMP_length": ICMP_length,
                    #ICMP_addr_mask,
                    "ICMP_nexthopmtu": ICMP_nexthopmtu,
                    "ICMP_unused": ICMP_unused,
                    "TCP_seq": TCP_seq,
                    "TCP_ack": TCP_ack,
                    "TCP_dataofs": TCP_dataofs,
                    "TCP_reserved": TCP_reserved,
                    "TCP_flags": TCP_flags,
                    "TCP_FIN": TCP_FIN,
                    "TCP_SYN": TCP_SYN,
                    "TCP_RST": TCP_RST,
                    "TCP_PSH": TCP_PSH,
                    "TCP_ACK": TCP_ACK,
                    "TCP_URG": TCP_URG,
                    "TCP_ECE": TCP_ECE,
                    "TCP_CWR": TCP_CWR,
                    "TCP_window": TCP_window,
                    "TCP_chksum": TCP_chksum,
                    "TCP_urgptr": TCP_urgptr,
                    "TCP_options": TCP_options,
                    "UDP_len": UDP_len,
                    "UDP_chksum": UDP_chksum,
                    "DHCP_options": DHCP_options,
                    "BOOTP_op": BOOTP_op,
                    "BOOTP_htype": BOOTP_htype,
                    "BOOTP_hlen": BOOTP_hlen,
                    "BOOTP_hops": BOOTP_hops,
                    "BOOTP_xid": BOOTP_xid,
                    "BOOTP_secs": BOOTP_secs,
                    "BOOTP_flags": BOOTP_flags,
                    "BOOTP_sname": BOOTP_sname,
                    "BOOTP_file": BOOTP_file,
                    "BOOTP_options": BOOTP_options,
                    "DNS_length": DNS_length,
                    "DNS_id": DNS_id,
                    "DNS_qr": DNS_qr,
                    "DNS_opcode": DNS_opcode,
                    "DNS_aa": DNS_aa,
                    "DNS_tc": DNS_tc,
                    "DNS_rd": DNS_rd,
                    "DNS_ra": DNS_ra,
                    "DNS_z": DNS_z,
                    "DNS_ad": DNS_ad,
                    "DNS_cd": DNS_cd,
                    "DNS_rcode": DNS_rcode,
                    "DNS_qdcount": DNS_qdcount,
                    "DNS_ancount": DNS_ancount,
                    "DNS_nscount": DNS_nscount,
                    "DNS_arcount": DNS_arcount,
                    "sport_class": sport_class,
                    "dport_class": dport_class,
                    "sport23": sport23,
                    "dport23": dport23,
                    "sport_bare": sport_bare,
                    "dport_bare": dport_bare,
                    "TCP_sport": TCP_sport,
                    "TCP_dport": TCP_dport,
                    "UDP_sport": UDP_sport,
                    "UDP_dport": UDP_dport, 
                    "payload_bytes": payload_bytes,
                    "entropy": entropy,
                    "MAC": Mac,
                    "Label": label
                }

                if label!="":
                    data.append(line)

        
        writer.writerows(data)
        print("  - ",iter+1,"/",len(pcap_list))    
        csvfile.close()

    for iter, file_path in enumerate(pcap_list):
        filename=file_path[:-5]+".csv"
        ths = open("Protocol.csv", "w")
        ths.write("Protocol\n")
        
        command="tshark -r "+pcap_file+" -T fields -e _ws.col.Protocol -E header=n -E separator=, -E quote=d -E occurrence=f > temp.csv"
        os.system(command)

        with open("temp.csv", "r") as file:
            while True:
                line=file.readline()
                print(line)
                if line=="":break
                if  "ARP" not in line:# this line eliminates the headers of CSV files and incomplete streams .
                    ths.write(str(line))
                else:
                    continue                       
        ths.close()  
        print("   {}  /  {}".format(iter+1,len(pcap_list)))    
        os.remove("temp.csv")
        df1=pd.read_csv(filename)
        df2=pd.read_csv("Protocol.csv")
        df1["Protocol"]=df2["Protocol"]        
        label=df1["Label"]
        del df1["Label"]
        df1["Label"]=label
        
        df1 = df1.replace({"IP_flags": IP_FLAGS})
        df1 = df1.replace({"TCP_flags": TCP_FLAGS})
        df1 = df1.replace({"BOOTP_flags": BOOTP_FLAGS})
        df1 = df1.replace({"Protocol": Protocol})
        df1 = df1.fillna(0)

        df1 = df1.astype(FEATURE_DICT)

        df1.to_csv(filename,index=None)

        os.remove("Protocol.csv")


def replace_flags(input_path, ext, output_path):
    
    filelist = list_files(input_path, ext)
    if len(filelist) == 0:
        return

    df = pd.read_csv(filelist[0])
    col_names = list(df.columns)

    empty = pd.DataFrame(columns=col_names)
    empty.to_csv(output_path, mode="a", index=False)#,header=False)

    for file in filelist:
        df = pd.read_csv(file)

        df.to_csv(output_path, mode="a", index=False,header=False)
    
    df=pd.read_csv(output_path)
    df=df.replace({"IP_flags": IP_FLAGS})
    df=df.replace({"TCP_flags": TCP_FLAGS})
    df=df.replace({"BOOTP_flags": BOOTP_FLAGS})
    df=df.replace({"Protocol": Protocol})
    df.to_csv(output_path,index=None)