#!/usr/bin/python

"""This script verifies if the Ipv6Autoconf is set to no or not"""

def check_ipv6_autoconf_status():
    """This function verifies if Ipv6Autoconf is disabled or not"""

    if 'net.ipv6.conf.default.autoconf=0' in open('/etc/sysctl.conf').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'disable_Ipv6_autoconf.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_ipv6_autoconf_status()
