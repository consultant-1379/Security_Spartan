#!/usr/bin/python
"""This script verifies if the shortcut: mask_alt_ctrl_del has been masked or not"""

import os

def ctrl_alt_del():
    """This function verifies if the shortcut: mask_alt_ctrl_del has been masked or not"""
    os.system("systemctl status ctrl-alt-del.target > /ericsson/security/compliance/status.txt")
    with open('/ericsson/security/compliance/status.txt', 'r') as fin:
        data1 = fin.read()
    os.system("rm -rf /ericsson/security/compliance/status.txt")
    if "man:systemd.special" in data1:
        return "NON-COMPLIANT:  EXECUTE 'mask_alt_ctrl_del.py' TO MAKE IT COMPLIANT"
    else:
        return "COMPLIANT"

if __name__ == '__main__':
    ctrl_alt_del()
