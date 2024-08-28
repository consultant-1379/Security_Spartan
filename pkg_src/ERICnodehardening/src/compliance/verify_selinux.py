#!/usr/bin/python
"""This script verifies if selinux is in enforcing mode or not"""

import subprocess
import re

def check_sestatus():
    """This function verifies if selinux is in enforcing mode or not"""
    status = subprocess.check_output("getenforce", shell=True)
    config_file = open("/etc/sysconfig/selinux", "r")
    for line in config_file:
        if re.match("SELINUX=enforcing", line):
            status2 = 'SELINUX=enforcing'
    if status == 'Enforcing\n' and status2 == 'SELINUX=enforcing':
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'enforce_selinux.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_sestatus()
