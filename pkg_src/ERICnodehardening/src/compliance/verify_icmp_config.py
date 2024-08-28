#!/usr/bin/python
"""This script verifies if icmp broadcast has been disabled or not"""

def icmp_check():
    """This script verifies if icmp broadcast has been disabled or not"""

    if 'net.ipv4.icmp_echo_ignore_broadcasts=1' in open('/etc/sysctl.conf').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'disable_icmp_broadcast.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    icmp_check()
