#!/usr/bin/python
"""This script verifies if reverse path forwarding has been enabled or not"""
import subprocess

def check_reverse_fwd():
    """This script verifies if reverse path forwarding has been enabled or not"""

    status = subprocess.check_output("cat /proc/sys/net/ipv4/conf/default/rp_filter", shell=True)

    if status == '1\n':
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'reverse_fwd.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_reverse_fwd()
