from gvm.connections import UnixSocketConnection, DebugConnection
from gvm.protocols.gmp import Gmp 
from gvm.protocols.gmpv224 import Gmp
import gvm
import xml
import xml.etree.ElementTree as ET
import nmap 

### NMAP HOST DISCOVERY ###
nm = nmap.PortScanner();

print('input ip range and omit host id ( ex: 192.168.1 ):');
ip_range = input();

nm.scan('%s.0/24' % ip_range, '22-443');
host_list = list(nm.all_hosts()) 

for host in nm.all_hosts():
    f = open('hosts.txt', 'a')
    f.write('%s\n' % host)
    f.close()

f = open('hosts.txt', 'r')
print('hosts:\n')
print(f.read())

### GVM PATH and CREDENTIALS ###
gmp_path = '/run/gvmd/gvmd.sock'                            # specify path for the Unix domain socket
socket_connection = UnixSocketConnection(path=gmp_path)     # create the connection to the socket through the path
connection = DebugConnection(socket_connection)             # debug the connection so we can see wtf is happening

username = 'admin'
password = '*password*'

### USING GMP (GREENBONE MANAGEMENT PROTOCOL) ###
with Gmp(connection=connection) as gmp:                     # make the connection 
    gmp.authenticate(username, password)                    # authenticate with a username and password
    
    #CREATE NEW TARGET
    print('name for new target:')
    target_name = input()
    
    parsed_port_lists = ET.fromstring(gmp.get_port_lists())  # parse the xml from the gmp.get_port_lists()
    for child in parsed_port_lists.findall('port_list'):     # find all port_lists
        name = child.findtext('name')                        # find the text in the <name></name>
        id_ = child.get('id')                                # find the id of the port_list in <task id='blablablanumbers'></task>
        print(name, id_)
        print('\n')
    print('port_list ID to use:')
    port_list = input()
    
    gmp.create_target(name=target_name, hosts=host_list, port_list_id=port_list)
    
    #CREATE NEW TASK
    print('\nname for new task:')
    task_name = input()
    print('\n')
   
    parsed_configs = ET.fromstring(gmp.get_scan_configs())  # parse the xml from the gmp.get_scan_configs()
    for child in parsed_configs.findall('config'):          # find all tasks
        name = child.findtext('name')                       # find the text in the <name></name> of task
        id_ = child.get('id')                               # find the id of the task in <task id='blablablanumbers'></task>
        print(name, id_)
        print('\n')
    print('scan_config ID to use:')
    scan_config = input()
    
    parsed_targets = ET.fromstring(gmp.get_targets())       # parse the xml from the gmp.get_targets()
    for child in parsed_targets.findall('target'):          # find all targets
        name = child.findtext('name')                       # find the text in the <name></name>
        id_ = child.get('id')                               # find the id of the target in <task id='blablablanumbers'></task>
        print(name, id_)
        print('\n')
    print('target ID to scan:')
    target = input()
    
    parsed_scanners = ET.fromstring(gmp.get_scanners())     # parse the xml from the gmp.get_scanners()
    for child in parsed_scanners.findall('scanner'):        # find all tasks
        name = child.findtext('name')                       # find the text in the <name></name>
        id_ = child.get('id')                               # find the id of the scanner in <task id='blablablanumbers'></task>
        print(name, id_)
        print('\n')
    print('scanner ID to use:')
    scanner = input()
    
    gmp.create_task(name=task_name, config_id=scan_config, target_id=target, scanner_id=scanner)
    
    
    parsed_tasks = ET.fromstring(gmp.get_tasks())       # parse the xml from the gmp.get_tasks()
    for child in parsed_tasks.findall('task'):          # find all tasks
        name = child.findtext('name')                   # find the text in the <name></name> of task
        id_ = child.get('id')                           # find the id of the task in <task id='blablablanumbers'></task>
        print(name, id_)
        print('\n')
    
    print('what task do you wanna start?')              
    task_ID = input()  
    gmp.start_task(task_ID)