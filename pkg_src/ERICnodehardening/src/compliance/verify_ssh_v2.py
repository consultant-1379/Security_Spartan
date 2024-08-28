#!/usr/bin/python
"""This script verifies if ssh protocol version 2 has been enabled or not"""

def ssh_protocol_check():
    """This function verifies if ssh protocol version 2 has been enabled or not"""
    with open('/etc/ssh/ssh_config', 'r') as fin:
        data1 = fin.readlines()
    a = ["Protocol 2\n"]
    if a[0] in data1:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'enable_ssh_proto_v2.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    ssh_protocol_check()
