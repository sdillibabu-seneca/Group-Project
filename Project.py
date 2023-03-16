'''from scapy.all import *
import nmap
import re
import sys
import os
import importlib.util

values = {}

interfaces = get_if_list()
if len(interfaces) > 1:
    while True:
        for i, item in enumerate(list(interfaces)[1:],1):
            print("\n", i, '. ' + item, sep='',end='')
        try:
            data = int(input("\n\nWhich Interface? (Enter a Number): "))
            if 1 <= data <= (len(interfaces)+1):
                interface_name = interfaces[data]
                break
            else:
                print("\nInvalid input\n", data)
        except:
            print("\nInvalid input\n", data)
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
correct = "no"
while correct != "yes":
    while True:
        target_ip = input("\n\nEnter target IP address: ")
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        if(re.search(regex, target_ip.lower())):
            values["target_ip"]=target_ip
            break
        else:
            print("\nInvalid IP address\n")

    # Get Target MAC Address
    nm = nmap.PortScanner()
    print("\n\nGetting target's information. Please wait...")
    nm.scan(arguments='F', hosts=target_ip)
    target_mac_address = str(nm[target_ip]['addresses']['mac']).lower()
    values["target_mac_address"]=target_mac_address

    # Get Target Ports
    try:
        ports = list(nm[target_ip]['tcp'].keys())
        values["ports"]=ports
        print(ports)
    except:
        ports = []
        values["ports"]=ports
        print("\nNo ports available on this target\n")

    while True:
        correct = input("\n\nAttack this host? (yes/no): ")
        if correct == "yes":
            break
        elif correct == "no":
            break
        else:
            print("\nDid not understand, please try again\n")

    if correct == "yes":
        break
        

# To test comment out everything above (including the import block) and uncomment the block below

from scapy.all import *'''
import re
import sys
import os
import importlib.util


values = {}
ports = [80, 22, 53, "any"]
values["ports"]=ports
target_mac_address = "00:0c:29:ac:a4:4a"
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
            
# Ensures there's not a mix match for DNS query type and value
def check_compat(values, required_var_list):
    correct = "no"
    while correct != "yes":
        regex1="([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+"
        regex2="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        if values.get("query_type") == "A" and (re.search(regex2, values.get("query_name").lower())) or values.get("query_type") == "PTR" and (re.search(regex1, values.get("query_name").lower())):
            print("Mismatch of query type and query name")
            print("")
            for i, (k, v) in enumerate({key: values[key] for key in required_var_list if key in values}.items()):
                print(i, '. ', k, ' is ', v)
            print("")
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
            correct == "yes"
            break

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
            
    if variable == "query_type":
        if var_value == "A" or var_value == "PTR":
            values["query_type"]=var_value
        else:
            print("Invalid query type\n")

    if variable == "query_name":
        regex1="([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+"
        regex2="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        if values.get("query_type") == "A" and (re.search(regex1, var_value.lower())):
            values["query_name"]=var_value
        elif values.get("query_type") == "PTR" and (re.search(regex2, var_value.lower())):
            values["query_name"]=var_value
        else:
            print("Invalid query name\n")
            
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
    if "query_type" in required_var_list:
        print("valid entries for query_type are A and PTR, you currently have the query_type value set as", values.get("query_type")) 
    if "query_name" in required_var_list:
        print("value is dependent on query type selected, you currently have the query_type value set as", values.get("query_name")) 

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
attacks_path = os.path.join(os.getcwd(), "attacks")

available_templates = {"Attack Name/Explaination":"attack_function_name"}

for filename in os.listdir(attacks_path):
    if filename.endswith(".py"):
        filepath = os.path.join(attacks_path, filename)
        spec = importlib.util.spec_from_file_location(filename[:-3], filepath)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if module.req_port in ports:
            available_templates[module.name] = module.function_name
            globals()[module.function_name] = getattr(module, module.function_name)


while True:
    for i, item in enumerate(list(available_templates.keys())[1:],1):
        print("\n", i, '. ' + item, sep='',end='')
    try:
        data = int(input("\n\nWhich Attack? (Enter a Number): "))
        if 1 <= data <= (len(list(available_templates.keys())) -1):
            eval(available_templates.get(list(available_templates.keys())[data]) + "()")
            reset()
            #break
        else:
            print("\nInvalid input", data)
    except KeyboardInterrupt:
        print("\nExiting program")
        sys.exit()
