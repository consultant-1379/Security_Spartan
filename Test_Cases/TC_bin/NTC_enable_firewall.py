#!/usr/bin/python
"""
# ********************************************************************
# Name      : NTC_enable_firewall.py
# Purpose   : Test script to check that firewall is enabled.
#
# ********************************************************************
"""
import os
import subprocess as s
from TC_enable_firewall import firewall

def change_firewall():
    check1 = s.check_output("systemctl status firewalld | grep -i Active | cut -d':' -f 2 | cut -d ' ' -f 2", shell= True)
    check2 = s.check_output("systemctl status firewalld | grep Loaded | cut -d ';' -f 2 | cut -d ' ' -f 2", shell = True)
    if check1 == "active\n" or check2 == "enabled\n":
      os.system("systemctl stop firewalld")
      os.system("systemctl disable firewalld > /dev/null 2>&1")
      os.system("firewall-cmd --reload > /dev/null 2>&1")
    firewall()
    os.system("systemctl start firewalld")
    os.system("systemctl enable firewalld > /dev/null 2>&1")
    os.system("firewall-cmd --reload > /dev/null 2>&1")
    return "SUCCESS"

if __name__ == '__main__':
    print change_firewall()
