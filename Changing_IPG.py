from netmiko import ConnectHandler
import xml.etree.ElementTree as ET
from pprint import pprint
import re
import requests
import urllib3
import json

"""Modifies profiles if NodeID is Valid"""
def Change_Profile(host):
    """APIC login & API requests"""
    global NodeID
    apic = host
    url = 'https://' + apic + '/api/aaaLogin.json'
    username = "admin"
    password = "Onnatop!2"
    payload = {"aaaUser":{"attributes":{"name": username, "pwd": password}}}
    headers = {'content-type': 'application/json'}
    response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    r_json = response.json()
    token = r_json["imdata"][0]["aaaLogin"]["attributes"]["token"]
    cookie = {'APIC-cookie': token}

    """API Query for current interfaces configured & associated profiles"""
    url = 'https://' + apic + '/api/node/mo/uni/infra/accportprof-Leaf' + NodeID + '_IntProf.xml?query-target=subtree&target-subtree-class=infraRsAccBaseGrp'
    r = requests.get(url, cookies=cookie, verify=False)
    tree = ET.ElementTree(ET.fromstring(r.text))
    root = tree.getroot()
    interfaces = {}
    for node in root.findall('infraRsAccBaseGrp'):
        ports_temp = str(re.findall(r"E1_.", node.get('dn')))
        ports = ports_temp.lstrip("['",).rstrip("']")
        profile_temp = str(re.findall(r"-(\w*)", node.get('tDn')))
        profile = profile_temp.lstrip("['").rstrip("']")
        interfaces[ports] = profile
    user_interface = input('Please enter interface number of choice(between 1 to {}): '.format(len(interfaces)))

    """API Query for available profiles"""
    url = 'https://' + apic + '/api/node/mo/uni/infra/funcprof.xml?query-target=subtree&target-subtree-class=infraAccPortGrp'
    r = requests.get(url, cookies=cookie, verify=False)
    tree = ET.ElementTree(ET.fromstring(r.text))
    root = tree.getroot()
    access_profile = {}
    x = 0
    for node in root.findall('infraAccPortGrp'):
        access_profile[x] = str(node.get('name'))
        x += 1
    pprint(access_profile)
    profile_index_num = input('Enter Index # profiles of choice: ')
    new_profile = access_profile[int(profile_index_num)]
    print(new_profile)

    """API Query for Hostname & Address"""
    url = 'https://' + apic + '/api/node/mo/topology/pod-1/node-' + NodeID + '/sys.xml?query-target=subtree&target-subtree-class=topSystem'
    r = requests.get(url, cookies=cookie, verify=False)
    tree = ET.ElementTree(ET.fromstring(r.text))
    root = tree.getroot()
    for node in root.findall('topSystem'):
        Hostname = node.get('name')
        IPAddress = node.get('inbMgmtAddr')
    print('Summary of the change:\nHOSTNAME(IP_ADDRESS): {}({})\nINTERFACE: E1_{}\nCURRENT-PROFILE: {}\nNEW-PROFILE: {}'.format(Hostname,IPAddress,user_interface, interfaces['E1_{}'.format(user_interface)], new_profile))
    print('Please verify change to be made is correct. \x1B[3mWarning!! changes once made can be distuptive.\x1B[23m')
    confirmation = input('Do you wish to proceed with change(Y or N): ')
    if confirmation == 'Y':
        url = 'https://' + apic + '/api/node/mo/uni/infra/accportprof-Leaf' + NodeID + '_IntProf/hports-E1_' + user_interface + '-typ-range/rsaccBaseGrp.json'
        payload = {"infraRsAccBaseGrp":{"attributes":{"tDn":"uni/infra/funcprof/accportgrp-" + new_profile + ""}}}
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        new_post = requests.post(url, data=json.dumps(payload), headers=headers, cookies=cookie, verify=False)
        if new_post.status_code == 200:
            print('Success!!!!')
        else:
            print(new_post.status_code)
    else:
        exit()

"""Next step if NodeID is invalid"""
def Invalid():
    global NodeID
    NodeID = input('Enter node ID: ')
    Validate(NodeID)

"""Verifies if NodeID is Valid"""
def Validate(NodeID):
    for host in hosts:
        # Place what you want each thread to do here, for example connect to SSH, run a command, get output
        print('\nPlease wait validating node.....')
        Brocade_ICX = {'device_type' : 'cisco_nxos', 'ip' : host, 'username' : 'admin', 'password' : 'Onnatop!2','verbose' : False}
        ssh_session = ConnectHandler(**Brocade_ICX)
        for cmd in cisco_command :
            mac_table_temp = ssh_session.send_command(cmd)
            #print(mac_table_temp)
            mac_table_temp = [x.strip() for x in mac_table_temp.splitlines()]
            del mac_table_temp[len(mac_table_temp)-2:len(mac_table_temp)+1]
            #print(mac_table_temp)
            ID = re.sub(r"['ID*\s:$']", '', str(mac_table_temp)).lstrip('[').rstrip(']')
            ID_list = ID.split(",")
            #print(ID_list)
            if NodeID in ID_list:
                print("Valid Node")
                Change_Profile(host)
            else:
                print('Enter valid Node')
                Invalid()
        ssh_session.disconnect()

"""Loads APIC from file"""
with open('APIC.txt', 'r') as f:
    hosts = f.read().splitlines()
cisco_command = ['show switch detail | grep ID']
table= []

"""Request input Node from user"""
NodeID = input('Enter node ID: ')
Validate(NodeID)
