from scapy.all import *
import nmap
import re
import sys
import os
import importlib.util
from tkinter import *
from tkinter import messagebox
from tkinter import scrolledtext
import subprocess

root = Tk()
def gui():
    root.title("Scapy Lite")
    root.geometry('800x600')
    frame=Frame(root,bg='lightblue')
    lable=Label(root, text='Welcome to the home page of scapy tool please use the tabs to navigate, and choose the scan tab to get started')
    frame.place(relx=0,rely=0,relheight=1,relwidth=1)
    lable.place(relx=0,rely=0.2)
    bt=Button(root,text='Run a Nmap scan',command=select_interface)
    bt.grid(column=0,row=0)

def select_interface():
    select_interface_frame = Frame(root, padx=20, pady=20, bg='grey')
    select_interface_frame.place(relx=0, rely=0.1, relheight=0.4, relwidth=0.98)

    interface_list_label = Label(select_interface_frame, text='Please fill the below fields, choose an interface ')
    interface_list_label.place(relx=0.1, rely=0.1)

    interface_list = Listbox(height=5, width=10, bg="lightblue", activestyle='dotbox', font="Helvetica", fg="black")

    global values
    global ports
    interfaces = list(get_if_list())
    for i, item in enumerate(interfaces):
        interface_list.insert(i, item)
    interface_list.place(relx=0.54, rely=0.15)

    interface_selection_button = Button(select_interface_frame, text='Submit', command=lambda:validate_selection(interface_list,interfaces))
    interface_selection_button.place(relx=0.6, rely=0.6)

def validate_selection(interface_list, interfaces):
    selection = interface_list.curselection()[0]
    if not selection:
        messagebox.showwarning("Error", "Please select an interface from the list.")
        return
    interface_name = interfaces[selection]
    values["iface"] = interface_name

    # Get Source IP Address
    source_ip = get_if_addr(interface_name)
    values["source_ip"] = source_ip
    og_source_ip = source_ip

    # Get Source Mac Address
    source_mac_address = get_if_hwaddr(interface_name)
    values["source_mac_address"] = source_mac_address
    og_source_mac_address = source_mac_address

    enter_victim_ip()


def enter_victim_ip():
    # Get Target IP Address
    input_ip_frame = Frame(root, padx=20, pady=20,bg='grey')
    input_ip_frame.place(relx=0,rely=0.1,relheight=0.4,relwidth=0.98)
    label2=Label(input_ip_frame,text='Enter target IP address')
    label2.place(relx=0.1,rely=0.3)
    target_ip = Entry(root, width=10)
    target_ip.place(relx=0.33,rely=0.24)
        
    submit_targetip_button=Button(input_ip_frame,text='Submit', command= lambda:check_regex(target_ip))
    submit_targetip_button.place(relx=0.5,rely=0.5)
    
def check_regex(target_ip):

    # IP address regex pattern
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    
    # Validate the IP address using regex
    if not re.match(pattern, target_ip.get()):
        messagebox.showwarning("Error", "Invalid IP Address")
        return
    values["target_ip"]= target_ip.get()
    nmap_scan()

def nmap_scan():
    nmap_frame = Frame(root, padx=20, pady=20,bg='grey')
    nmap_frame.place(relx=0,rely=0.1,relheight=0.4,relwidth=0.98)
    label3=Label(nmap_frame,text='PORT SCAN')
    label3.place(relx=0.1,rely=0.3)
    
    nmap_box = scrolledtext.ScrolledText(nmap_frame, bg='white', relief=GROOVE, height=8, width=30, font='TkFixedFont', state=DISABLED)
    nmap_box.pack(side=TOP)

    nmap_box.configure(state=NORMAL)
    nmap_box.insert(END,"Getting target's information. Please wait...")
    nmap_box.configure(state=DISABLED)

    nm = nmap.PortScanner()
    nm.scan(arguments='--open -sT -sU -p T:1-1023,[1024-],U:53,67,68', hosts=values.get("target_ip"))
    target_mac_address = str(nm[values.get("target_ip")]['addresses']['mac']).lower()
    values["target_mac_address"]= target_mac_address

    global ports

    # Get Target Ports
    try:
        ports = list(nm[values.get("target_ip")]['tcp'].keys())
        try:
            ports = ports + list(nm[values.get("target_ip")]['udp'].keys())
        except:
            pass
        values["ports"]=ports
        nmap_box.configure(state=NORMAL)
        nmap_box.insert(END,str(ports))
        nmap_box.configure(state=DISABLED)
    except:
        ports = []
        values["ports"]=ports
        nmap_box.configure(state=NORMAL)
        nmap_box.insert(END,"No ports available on this target")
        nmap_box.configure(state=DISABLED)
    ports.append("any")

    submit_nmap_scan_yes_button=Button(nmap_frame,text='Yes', command= lambda:load_modules())
    submit_nmap_scan_yes_button.place(relx=0.72,rely=0.51)
    submit_nmap_scan_no_button=Button(nmap_frame,text='No', command= lambda:enter_victim_ip())
    submit_nmap_scan_no_button.place(relx=0.2,rely=0.5)
    
   
def load_modules():
    attacks_path = os.path.join(os.getcwd(), "attacks")
    for filename in os.listdir(attacks_path):
        if filename.endswith(".py"):
            filepath = os.path.join(attacks_path, filename)
            spec = importlib.util.spec_from_file_location(filename[:-3], filepath)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if module.req_port in ports:
                available_templates[module.name] = module.function_name
                globals()[module.function_name] = getattr(module, module.function_name)
    list_of_available_attacks()

def list_of_available_attacks(): 
    available_attacks_frame = Frame(root, padx=20, pady=20, bg='grey')
    available_attacks_frame.place(relx=0, rely=0.1, relheight=0.4, relwidth=0.98)

    available_attacks_label = Label(available_attacks_frame, text='These are the available attacks, please select one')
    available_attacks_label.place(relx=0.1, rely=0.1)

    available_attacks = Listbox(height=5, width=10, bg="lightblue", activestyle='dotbox', font="Helvetica", fg="black")

    for i, item in enumerate(list(available_templates.keys())):
        available_attacks.insert(i, item)
    available_attacks.place(relx=0.54, rely=0.15)

    interface_selection_button = Button(available_attacks_frame, text='Submit', command=lambda:select_attack(available_attacks,available_templates))
    interface_selection_button.place(relx=0.6, rely=0.6)

def select_attack(attack_list, available_templates):
    data = attack_list.curselection()[0]
    return subprocess.run(available_templates.get(list(available_templates.keys())[data]) + "(values)", shell=True, capture_output=True).stdout

def variable_input(required_var_list, help_statements, values):
    while all(variables in values for variables in required_var_list) is False:
        for variable in list(required_var_list - values.keys()):

            attack_frame = Frame(root, padx=20, pady=20, bg='grey')
            attack_frame.place(relx=0, rely=0.1, relheight=0.4, relwidth=0.98)

            available_attacks_label = Label(attack_frame, text=f'Enter the value {variable}')
            available_attacks_label.place(relx=0.1, rely=0.1)

            var_value = Entry(attack_frame, width=10)
            var_value.place(relx=0.33, rely=0.24)

            submit_button = Button(attack_frame, text="Submit", command=lambda:submit_variable(variable, var_value, values, attack_frame))
            submit_button.place(relx=0.5, rely=0.5)

            help_button = Button(attack_frame, text="Help", command=lambda:help_func(values, list(variable)))
            help_button.place(relx=0.10, rely=0.5)

            attack_label = Label(attack_frame, text=help_statements)
            attack_label.place(relx=0.1, rely=0.8)

            attack_frame.wait_window(attack_frame)

    return values

def submit_variable(variable, var_value, values, attack_frame):
    variable_error_handling(variable, var_value.get(), values)
    attack_frame.destroy()
    return

def variable_error_handling(variable, var_value, values):
    if variable == "target_ip":
        messagebox.showwarning("You are not permitted to change the target IP address")
        return
        
    if variable == "source_ip":
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        if(re.search(regex, var_value.lower())):
            values["source_ip"]=var_value
            return
        else:
            messagebox.showwarning("Invalid IP address\n")
            return
    
    if variable == "target_mac_address":
        messagebox.showwarning("You are not permitted to change the target MAC address")
        return
        
    if variable == "source_mac_address":
        regex = "[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"
        if(re.search(regex, var_value.lower())):
            values["source_mac_address"]=var_value.lower()
            return
        else:
            messagebox.showwarning("Invalid mac address\n")
            return

    if variable == "timeout":
        if var_value.isnumeric():
            values["timeout"]=var_value
            return
        else:
            messagebox.showwarning("Invalid timeout value\n")
            return

    if variable == "quantity":
        if var_value.isnumeric():
            values["quantity"]=var_value
            return 
        else:
            messagebox.showwarning("Invalid quantity value\n")
            return
    
    if variable == "query_name":
        regex1="([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+"
        regex2="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        
        if re.search(regex1, var_value.lower()):
            try:
                if values.get("query_type") == "A":
                    values["query_name"]=var_value
                    return
                elif values.get("query_type") == "PTR":
                    messagebox.showwarning("Mismatch of query type and query name.\nFor a query type of A, the query name must be similar to example.com.\nNo value will be saved.")
                    return
            except:
                values["query_name"]=var_value
                return
        elif re.search(regex2, var_value.lower()):
            try:
                if values.get("query_type") == "PTR":
                    values["query_name"]=var_value
                    return
                elif values.get("query_type") == "A":
                    messagebox.showwarning("Mismatch of query type and query name.\nFor a query type of PTR, the query name must be similar to 100.2.1.192.in-addr.arpa.\nNo value will be saved.")
                    return
            except:
                values["query_name"]=var_value
                return
        else:
            messagebox.showwarning("Invalid query name\n")
            return
            
    if variable == "query_type":
        regex1="([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+"
        regex2="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

        if var_value == "A":
            try:
                if re.search(regex1, values.get("query_name").lower()):
                    values["query_type"]=var_value
                    return
                elif re.search(regex2, values.get("query_name").lower()):
                    messagebox.showwarning("Mismatch of query type and query name.\nFor a query type of A, the query name must be similar to example.com.\nNo value will be saved.")
                    return
            except:
                values["query_type"]=var_value
                return
        elif var_value == "PTR":
            try:
                if re.search(regex2, values.get("query_name").lower()):
                    values["query_type"]=var_value
                    return
                elif re.search(regex1, values.get("query_name").lower()):
                    messagebox.showwarning("Mismatch of query type and query name.\nFor a query type of PTR, the query name must be similar to 100.2.1.192.in-addr.arpa.\nNo value will be saved.")
                    return
            except:
                values["query_type"]=var_value
                return
        else:
            messagebox.showwarning("Invalid query type\n")
            return
    
    if variable == "subnet":
        if var_value.isnumeric() and int(var_value) <= 30 and int(var_value) >= 8:
            values["subnet"]=var_value
            return
        else:
            messagebox.showwarning("Invalid subnet value\n")
            return

def all_variables_inputted(values, required_var_list):
    while all(variables in values for variables in required_var_list) is False:
        for variable in list(required_var_list - values.keys()):

            attack_frame = Frame(root, padx=20, pady=20, bg='grey')
            attack_frame.place(relx=0, rely=0.1, relheight=0.4, relwidth=0.98)

            available_attacks_label = Label(attack_frame, text=f'Enter the value {variable}')
            available_attacks_label.place(relx=0.1, rely=0.1)

            var_value = Entry(attack_frame, width=10)
            var_value.place(relx=0.33, rely=0.24)

            submit_button = Button(attack_frame, text="Submit", command=lambda:submit_variable(variable, var_value, values, attack_frame))
            submit_button.place(relx=0.5, rely=0.5)

            help_button = Button(attack_frame, text="Help", command=lambda:help_func(values, required_var_list))
            help_button.place(relx=0.10, rely=0.5)

            attack_frame.wait_window(attack_frame)

    return values

def check_var(values, required_var_list):
    # create a Toplevel window to show the dialog
    check_var_dialog = Toplevel(root)

    check_var_frame = Frame(check_var_dialog, padx=20, pady=20, bg='grey')
    check_var_frame.pack(fill=BOTH)

    label5 = Label(check_var_dialog, text='Are all of these variables correct?')
    label5.pack()

    check_var_box = scrolledtext.ScrolledText(check_var_dialog, bg='white', relief=GROOVE, height=12, width=10, font='TkFixedFont', state=DISABLED)
    check_var_box.pack(side=BOTTOM)

    check_var_box.configure(state=NORMAL)
    for i, (k, v) in enumerate({key: values[key] for key in required_var_list if key in values}.items()):
        check_var_box.insert(END,f"\n{i}. {k} is {v}\n")
    check_var_box.configure(state=DISABLED)

    def on_yes():
        attack_output()
        check_var_dialog.destroy()

    def on_no():
        change_var(required_var_list)
        check_var_dialog.destroy()

    submit_check_var_yes_button = Button(check_var_dialog, text='Yes', command=on_yes)
    submit_check_var_yes_button.pack(side=LEFT, padx=10, pady=10)

    submit_check_var_no_button = Button(check_var_dialog, text='No', command=on_no)
    submit_check_var_no_button.pack(side=RIGHT, padx=10, pady=10)

    # wait for the user to close the dialog before continuing
    check_var_dialog.wait_window()
            
def change_var(required_var_list):
    change_var_dialog = Toplevel(root)

    change_var_frame = Frame(change_var_dialog, padx=20, pady=20, bg='grey')
    change_var_frame.place(relx=0, rely=0.1, relheight=0.4, relwidth=0.98)

    change_var_label = Label(change_var_dialog, text='Please fill the below fields, choose a parameter ')
    change_var_label.place(relx=0.1, rely=0.1)

    variable_list = Listbox(height=5, width=10, bg="lightblue", activestyle='dotbox', font="Helvetica", fg="black")
    for i, variable in enumerate(required_var_list):
        variable_list.insert(i, variable)
    variable_list.place(relx=0.54, rely=0.15)

    variable_selection_button = Button(change_var_dialog, text='Submit', command=lambda:validate_variable_selection(variable_list,required_var_list))
    variable_selection_button.place(relx=0.6, rely=0.6)

def validate_variable_selection(variable_list,required_var_list):
    selection = variable_list.curselection()[0]
    if not selection:
        messagebox.showwarning("Error", "Please select a parameter from the list.")
        return
    variable = required_var_list[selection]

    attack_dialog = Toplevel(root)

    attack_frame2 = Frame(attack_dialog, padx=20, pady=20, bg='grey')
    attack_frame2.place(relx=0, rely=0.1, relheight=0.4, relwidth=0.98)

    available_attacks_label = Label(attack_dialog, text=f'Enter the value {variable}')
    available_attacks_label.place(relx=0.1, rely=0.1)

    var_value = Entry(attack_dialog, width=10)
    var_value.place(relx=0.33, rely=0.24)

    submit_button = Button(attack_dialog, text="Submit", command=lambda:submit_variable(variable, var_value, values, attack_frame2))
    submit_button.place(relx=0.5, rely=0.5)

    help_button = Button(attack_dialog, text="Help", command=lambda:help_func(values, list(variable)))
    help_button.place(relx=0.10, rely=0.5)

    attack_frame2.wait_window(attack_dialog)
    check_var(values, required_var_list)

def attack_output():

    def redirector(inputStr):
        attack_output_box.configure(state=NORMAL)
        attack_output_box.insert(END,inputStr)
        attack_output_box.configure(state=DISABLED)

    attack_output_frame = Frame(root, padx=20, pady=20,bg='grey')
    attack_output_frame.place(relx=0,rely=0.1,relheight=0.4,relwidth=0.98)
    label6=Label(attack_output_frame,text='Attack Running')
    label6.place(relx=0.1,rely=0.3)
    
    attack_output_box = scrolledtext.ScrolledText(attack_output_frame, bg='white', relief=GROOVE, height=12, width=10, font='TkFixedFont', state=DISABLED)
    attack_output_box.pack(side=BOTTOM)

    sys.stdout.write = redirector(sys.stdout.write)


def help_func(values, help_var):
    if "source_ip" in help_var:
        messagebox.showwarning("Help","to enter ip type source_ip = 1.1.1.1, you currently have the target_ip set as", values.get("source_ip"))
        return
    if "target_ip" in help_var:
        messagebox.showwarning("Help","the target ip cannot be changed, you currently have the target_ip set as", values.get("target_ip"))
        return
    if "source_mac_address" in help_var:
        messagebox.showwarning("Help","to enter mac type target_mac_address = ff:ff:ff:ff:ff:ff, you currently have target_mac_address set as", values.get("source_mac_address"))
        return
    if "target_mac_address" in help_var:
        messagebox.showwarning("Help","the target mac cannot be changed, you currently have target_mac_address set as", values.get("target_mac_address"))
        return
    if "timeout" in help_var:
        messagebox.showwarning("Help","to enter the timeout value type any number, you currently have the timeout value set as", values.get("timeout"))
        return
    if "quantity" in help_var:
        messagebox.showwarning("Help","to enter the quantity value type any number, you currently have the quantity value set as", values.get("quantity"))
        return
    if "query_type" in help_var:
        messagebox.showwarning("Help","valid entries for query_type are A and PTR, you currently have the query_type value set as", values.get("query_type")) 
        return
    if "query_name" in help_var:
        messagebox.showwarning("Help","value is dependent on query type selected, you currently have the query_name value set as", values.get("query_name")) 
        return
    if "subnet" in help_var:
        messagebox.showwarning("Help","to enter subnet value type a number between 8 and 30 inclusive, you currently have the subnet value set as", values.get("subnet"))
        return

########## MAIN MENU EXAMPLE ##########

if __name__ == '__main__':

    available_templates = {}#"Attack Name/Explaination":"attack_function_name"
    values = {}
    
    gui()
    root.mainloop()
    select_interface()
    messagebox.showwarning("Notice","Attack has finished running, you can now close the program")