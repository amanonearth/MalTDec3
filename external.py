from scapy.all import *
import pandas as pd

packetRow = []
# ftp_dest_IP = ''
# ftp_src_IP = ''
# ftp_packet_len = ''

# ssh_dest_IP = ''
# ssh_src_IP = ''
# ssh_packet_len = ''

# tcp_dest_IP = ''
# tcp_src_IP = ''
# tcp_packet_len = ''


def ftp(packet):
    # getting the destination ( IP address from header)
    # global ftp_dest_IP
    # global ftp_src_IP
    # global ftp_packet_len
    ftp_dest_IP = packet.getlayer(IP).dst
    ftp_src_IP = packet.getlayer(IP).src
    ftp_packet_len = packet.getlayer(IP).len
    # getting raw packet load data
    raw = packet.sprintf('%Raw.load%')
    raw = raw + "FTP"
    packetRow.append([ftp_src_IP, ftp_dest_IP, ftp_packet_len, raw])


def ftp_sniffer():
    conf.iface = "lo"
    try:
        # sniffing FTP (port 21) - the ftp function will process the packets
        sniff(filter='tcp port 21', prn=ftp)

    except KeyboardInterrupt as e:
        print("[-] Closing function")
        exit(0)


def ssh(packet):
    global ssh_dest_IP
    # global ssh_src_IP
    # global ssh_packet_len
    # getting the destination ( IP address from header)
    ssh_dest_IP = packet.getlayer(IP).dst
    ssh_src_IP = packet.getlayer(IP).src
    ssh_packet_len = packet.getlayer(IP).len
    # getting raw packet load data
    raw = packet.sprintf('%Raw.load%')
    raw = raw + "SSH"
    packetRow.append([ssh_src_IP, ssh_dest_IP, ssh_packet_len, raw])
    # return ssh_dest_IP, ssh_src_IP, ssh_packet_len, raw

def ssh_sniffer():
    conf.iface = "en0"
    try:
        # sniffing SSH (port 22) - the ssh function will process the packets
        sniff(filter='tcp port 22', prn=ssh)
    except KeyboardInterrupt as e:
        print("[-] Closing function")
        exit(0)


def tcp(packet):
    # global tcp_dest_IP
    # global tcp_src_IP
    # global tcp_packet_len
    # # getting the destination ( IP address from header)
    tcp_dest_IP = packet.getlayer(IP).dst
    src_port = packet.getlayer(TCP).sport
    tcp_src_IP = packet.getlayer(IP).src
    tcp_packet_len = packet.getlayer(IP).len
    # getting raw packet load data
    raw = packet.sprintf('%Raw.load%')
    raw = raw + "TCP"
    if (src_port != 21):
        if (src_port != 22):
            packetRow.append([tcp_src_IP, tcp_dest_IP, tcp_packet_len, raw])

def tcp_sniffer():
    conf.iface = "lo"
    try:
        sniff(filter='tcp', prn=tcp)
    except KeyboardInterrupt as e:
        print("[-] Closing function")
        exit(0)



def packetSniff():
    try:
        ftp_sniffer()
        ssh_sniffer()
        tcp_sniffer()
        df = df.append(pd.DataFrame(packetRow,
                   columns=[ 'src_IP', 'dest_IP', 'packet_len', 'data']),
                   ignore_index = True)
        # display(df)
    except KeyboardInterrupt as e:
        df = df.append(pd.DataFrame(packetRow,
                   columns=[ 'src_IP', 'dest_IP', 'packet_len', 'data']),
                   ignore_index = True)
        
packetSniff()
