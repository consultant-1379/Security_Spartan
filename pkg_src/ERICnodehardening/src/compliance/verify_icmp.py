#!/usr/bin/python
"""This script verifies if the specified icmp-types are blocked or not"""

import commands

def check_icmp():
    """This script verifies if the specified icmp-types are blocked or not"""
    flag = 0
    icmp_types = ["redirect", "timestamp-reply", "router-solicitation", "router-advertisement"]

    for i in icmp_types:
        icmp_status = commands.getoutput("firewall-cmd --query-icmp-block=%s" % i)
        if icmp_status == 'yes':
            flag += 1
    if flag == 4 and 'net.ipv4.icmp_echo_ignore_all = 0' in open('/etc/sysctl.conf').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'configure_icmp.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_icmp()
