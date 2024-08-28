#!/usr/bin/python


import os
import commands
import logging
import subprocess as s

def check_server():
    """This function is to find the type of server """
    check_mount_point = os.path.ismount("/JUMP")
    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")
    if mws_insttype_path:
        mws_insttype = s.check_output("cat /ericsson/config/inst_type", shell=True)
        server_config_name = s.check_output("cat /ericsson/config/ericsson_use_config | cut -d'=' -f 2", shell=True)
        server_config_name = server_config_name.replace('\n', '')
        if check_mount_point and 'rhelonly' in mws_insttype and 'mws' in server_config_name:
            return 'MWS'
    elif eniq_insttype_path:
        return 'ENIQ server'

def check_firewall():
    """This function is to check the firewall status"""
    active_status = s.check_output("systemctl status firewalld | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = s.check_output("systemctl status firewalld | sed -n '/Loaded:/p' \
| cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)
    if active_status != "active\n" or enabled_status != "enabled\n":
       return False
    return True

def check_port():
    is_port=commands.getoutput("firewall-cmd --list-port | grep 5093")
    return is_port

def check_rules():
    is_rule=commands.getoutput("firewall-cmd --list-rich | grep 5093")
    return is_rule

def sentinal_check():
    if check_server() == "MWS":
        return "Not Applicable"
    if check_firewall() == False:
        return "FAIL"
    if check_port():
        return "FAIL"
    if check_rules():
        return "FAIL"
    return "SUCCESS"
