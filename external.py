import optparse
from scapy.all import *
import re # regex


ftp_dest_IP = ''
ftp_src_IP = ''
ftp_packet_len = ''

ssh_dest_IP = ''
ssh_src_IP = ''
ssh_packet_len = ''

tcp_dest_IP = ''
tcp_src_IP = ''
tcp_packet_len = ''


def ftp(packet):
    # getting the destination ( IP address from header)
    global ftp_dest_IP
    global ftp_src_IP
    global ftp_packet_len
    ftp_dest_IP = packet.getlayer(IP).dst
    ftp_src_IP = packet.getlayer(IP).src
    ftp_packet_len = packet.getlayer(IP).len
    # getting raw packet load data
    raw = packet.sprintf('%Raw.load%')
    # return ftp_dest_IP, ftp_src_IP, ftp_packet_len, raw

    # print(dest, src, packet_length)
    # getting user/password
    # user = re.findall('(?i)USER (.*)', raw)
    # pswd = re.findall('(?i)PASS (.*)', raw)
    # # validating existance
    # if user:
    #     print("[!] Detected FTP Login %s: " % str(dest))
    #     print("[+] User: %s" % str(user[0]))
    # elif pswd:
    #     print("[+] Password: %s" % str(pswd[0]))

# if __name__ == "__main__":
#     # parsing instance
#     parser = optparse.OptionParser('Usage: -i <interface>')
#     # adding options
#     parser.add_option('-i', dest='interface', type='string', help='specify the NIC interface to listen on')
#     (options, args) = parser.parse_args()
#     # validating options
#     if options.interface  == None:
#         print(parser.usage)
#         exit(0)
#     else:
#         # setting the parsed interface to the conf Scapy iface (interface) prop

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
    global ssh_src_IP
    global ssh_packet_len
    # getting the destination ( IP address from header)
    ssh_dest_IP = packet.getlayer(IP).dst
    ssh_src_IP = packet.getlayer(IP).src
    ssh_packet_len = packet.getlayer(IP).len
    # getting raw packet load data
    raw = packet.sprintf('%Raw.load%')
    # return ssh_dest_IP, ssh_src_IP, ssh_packet_len, raw

def ssh_sniffer():
    conf.iface = "lo"

    try:
        # sniffing SSH (port 22) - the ssh function will process the packets
        sniff(filter='tcp port 22', prn=ssh)

    except KeyboardInterrupt as e:
        print("[-] Closing function")
        exit(0)


def tcp(packet):
    global tcp_dest_IP
    global tcp_src_IP
    global tcp_packet_len
    # getting the destination ( IP address from header)
    tcp_dest_IP = packet.getlayer(IP).dst
    src_port = packet.getlayer(TCP).sport
    tcp_src_IP = packet.getlayer(IP).src
    tcp_packet_len = packet.getlayer(IP).len
    # getting raw packet load data
    raw = packet.sprintf('%Raw.load%')
    if (src_port != 21):
        if (src_port != 22):
            tcp_dest_IP = tcp_dest_IP
            tcp_src_IP = tcp_src_IP
            tcp_packet_len = tcp_packet_len

def tcp_sniffer():
    conf.iface = "lo"
    try:
        sniff(filter='tcp', prn=tcp)
    except KeyboardInterrupt as e:
        print("[-] Closing function")
        exit(0)

# ftp_sniffer()
# ssh_sniffer()
# tcp_sniffer()