'''import scapy.all as scapy
import nmap
import re


values = {}
# Get Source IP Address
values["source_ip"]=source_ip
og_source_ip = source_ip

# Get Source Mac Address
values["source_mac_address"]=source_mac_address
og_source_mac_address = source_mac_address

# Get Target IP Address
target_ip = input("Enter host IP address: ")
values["target_ip"]=target_ip

# Get Target MAC Address
nm = nmap.PortScanner()
nm.scan(target_ip, '22-443')
target_mac_address = str(nm[target_ip]['addresses']['mac'])
values["target_mac_address"]=target_mac_address

# Get Target Ports
tcp_ports = list(nm[target_ip]['tcp'].keys())
values["tcp_ports"]=tcp_ports

# To test comment out everything above (including the import block) and uncomment the block below. Also comment out the two scapy commands in lines 42 and 52
'''
import re
import sys
values = {}
tcp_ports = [80, 22]
values["tcp_ports"]=tcp_ports
target_mac_address = "ff:ff:ff:ff:ff:ff"
values["target_mac_address"]=target_mac_address
og_source_mac_address = "ff:ff:ff:ff:ff:ff"
source_mac_address = "ff:ff:ff:ff:ff:ff"
values["source_mac_address"]=source_mac_address
og_source_ip = "1.1.1.1"
source_ip = "1.1.1.1"
values["source_ip"]=source_ip
target_ip = "1.1.1.1"
values["target_ip"]=target_ip
values["quantity"]=100


# TEMPLATES EXAMPLE

def icmp_ping1():
    valid_var =["timeout", "target_ip"]
    help_statement = "\nsends a ping packet"
    print("\nRunning ICMP 1 attack, please enter the parameters:\n")
    variable_input(valid_var, help_statement)
    all_variables_inputted(valid_var)
    check_var(values, valid_var)
    print("\nICMP 1 working")
    #scapy.send(scapy.IP(dst=values.get("target_ip"))/scapy.ICMP())

def icmp_ping2():
    valid_var =["timeout", "target_ip", "target_mac_address"]
    help_statement = "\nsends a ping packet"
    print("\nRunning ICMP 2 attack, please enter the parameters:\n")
    variable_input(valid_var, help_statement)
    all_variables_inputted(valid_var)
    check_var(values, valid_var)
    print("ICMP 2 working")
    #scapy.send(scapy.IP(dst=values.get("target_ip"))/scapy.ICMP())

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
                variable = list(values.keys())[new_num]
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
            sys.exit()
        elif user_input == "help":
            print(help_statement)
            help_func(required_variable_list)
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
        regex = "[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"
        if(re.search(regex, var_value.lower())):
            values["target_mac_address"]=var_value.lower()
        else:
            print("Invalid mac address\n")
        
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

available_templates = {"Attack Name/Explination":"attack_function_name"}

if 80 in tcp_ports:
    available_templates["ICMP Ping1"]=icmp_ping1

if 22 in tcp_ports:
    available_templates["ICMP Ping2"]=icmp_ping2

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

########## NEED TO DO ##########

'''
Get source ip/mac address
Adding templates/help pages
Add error handling for templates (check if possible in try except loop, confirm with user if variables are correct and add option to change if not)
Add error handling for individual variables (ie ensure that the IP address entered is actually and IP address)
Add functionality for ip ranges
'''
