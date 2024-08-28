#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : verify_audit.py
# Purpose   : This script verifies the system audit configurations
#             enforced on the system.
# ********************************************************************
"""
import subprocess

def check_audit_config():
    """This function verifies the system audit configuration"""
    active_status = subprocess.check_output("systemctl status auditd | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = subprocess.check_output("systemctl status auditd | sed -n '/Loaded:/p' | \
cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)
    if active_status != "active\n" or enabled_status != "enabled\n":
        return "NON-COMPLIANT:  EXECUTE 'audit_config.py' TO MAKE IT COMPLIANT"
    read_path = "/etc/audit/rules.d/audit.rules"
    verify_path = "/ericsson/security/audit/config.txt"
    with open(read_path, 'r') as wrt:
        file_read = wrt.readlines()
    with open(verify_path, 'r') as wrt1:
        file_compare = wrt1.readlines()
    for i in file_compare:
        if i not in file_read and i != '\n':
            return "NON-COMPLIANT:  EXECUTE 'audit_config.py' TO MAKE IT COMPLIANT"
    return "COMPLIANT"

if __name__ == '__main__':
    check_audit_config()
