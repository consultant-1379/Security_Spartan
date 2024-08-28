#!/usr/bin/python
"""
# ********************************************************************
# Name       : NTC_Verify_NH_Config.py
# Purpose    : Test Case to verify only valid ports and services should be enabled.
# ********************************************************************
"""

import os
from TC_Verify_NH_Config import NH_conf

def check_NH_conf():
    check_mount_point = os.path.ismount("/JUMP")
    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")

    if mws_insttype_path is True:
     "enabling port on the MWS"
     os.system("firewall-cmd --zone=public --add-port=69/tcp --permanent > /dev/null 2>&1")
     os.system("firewall-cmd --reload > /dev/null 2>&1")
     r=NH_conf()
     os.system("firewall-cmd --zone=public --remove-port=69/tcp --permanent > /dev/null 2>&1")
     os.system("firewall-cmd --reload > /dev/null 2>&1")
    elif eniq_insttype_path is True:
     "enabling port on the MWS"
     os.system("firewall-cmd --zone=public --remove-port=6389/tcp --permanent > /dev/null 2>&1")
     os.system("firewall-cmd --reload > /dev/null 2>&1")
     r=NH_conf()
     os.system("firewall-cmd --zone=public --add-port=6389/tcp --permanent > /dev/null 2>&1")
     os.system("firewall-cmd --reload > /dev/null 2>&1")
    if r == "FAIL":
     return "SUCCESS"
    else:
     return "FAIL"

if __name__ == '__main__':

    print check_NH_conf()
