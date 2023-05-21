from gvm.connections import UnixSocketConnection, DebugConnection
from gvm.protocols.gmp import Gmp 
from gvm.protocols.gmpv224 import Gmp
import gvm
import xml
import xml.etree.ElementTree as ET

gmp_path = '/run/gvmd/gvmd.sock'                                    # specify path for the Unix domain socket
socket_connection = UnixSocketConnection(path=gmp_path)             # create the connection to the socket through the path
connection = DebugConnection(socket_connection)                     # debug the connection so we can see whats is happening

username = 'admin'
password = '*password*'


### USING GMP (GREENBONE MANAGEMENT PROTOCOL) ###
with Gmp(connection=connection) as gmp:                             # make the connection 
    gmp.authenticate(username, password)                            # authenticate with a username and password

    parsed_results = ET.fromstring(gmp.get_results())               # parse the xml from the gmp.get_results()
    gvm.xml.pretty_print(gmp.get_results())
    
    for child in parsed_results.findall('result'):                  # find all results
        name = child.findtext('name')                               # find the text in the <name></name> of result
        id_ = child.get('id')                                       # find the id of the result in <result id='blablablanumbers'></result>
        host = child.findtext('host')
        severity = child.findtext('severity')
        
        nvt = child.findall('nvt')
        oid = child.get('oid')
        description = child.findtext('description')
        indent = "  "
        
        print(indent, "Name: ", name)
        print(indent, "ID: ", id_)
        print(indent, "host: ", host)
        print(indent, "nvt_oid: ", oid)
        print(indent, "severity:", severity)
        print ("")
        print(indent, "description:")
        print(indent, description) 