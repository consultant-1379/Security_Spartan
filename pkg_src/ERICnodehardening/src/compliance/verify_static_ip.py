#!/usr/bin/python
"""This script verifies if static ip addresss has been assigned to all \
interfaces persent in the server or not"""

import subprocess
import os


def dhcp_staticip_check():
    """This function verifies if static ip addresss has been assigned to all \
interfaces persent in the server or not"""
    os.system("ls /sys/class/net/ | grep -v lo | grep -v bond-masters > \
/ericsson/security/compliance/log.txt")
    with open('/ericsson/security/compliance/log.txt', 'r') as fin:
        data1 = fin.readlines()
    data = "/etc/sysconfig/network-scripts/ifcfg-"
    os.system("rm -rf /ericsson/security/compliance/log.txt")

    for i in data1:
        k = data+i
        cmd = "cat %s"%(k)
        result = subprocess.check_output(cmd, shell=True)
        if "dhcp" in result:
            return "NON-COMPLIANT:  EXECUTE 'verify_static_ip_config.py' TO MAKE IT COMPLIANT"
        else:
            return "COMPLIANT"
if __name__ == '__main__':
    dhcp_staticip_check()
