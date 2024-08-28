#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2020 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
#
# ********************************************************************
# Name      : sentinel_hardening.py
# Author    : Megha H R
# Date      : 11-08-2020
# Revision  : A
# Purpose   : This script is to perform sentinel hardening,
#             by blocking sentinel port and provide restriction
#             by allowing NetAN IP
# Reason    : EQEV-76384
#---------------------------------------------------------------------
# History
"""

import os
import re
import logging
import time
import signal
import subprocess as sub

from user_verification import user_verification

REG_255 = '(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'
COLORS = {'RED' : '\33[31m', 'END' : '\033[0m', 'GREEN' : '\33[32m', 'YELLOW' : '\33[33m'}
BACKUP_FILE = '/ericsson/security/BACKUP_CONFIG_FILES/netan_whitelisted_IP.txt'
file_name = "sentinel_hardening.py"
null_cmd = " 1>/dev/null 2>&1"

def log_func(script_name, state, log_path):
    """This function is to create log file header and footer"""
    if state == 0:
        open(log_path, 'a').writelines('*'*95+'\n')
        host = sub.check_output('hostname', shell=True).replace('\n', '')
        start_time = time.strftime("%Y-%m-%d_%H-%M-%S")
        open(log_path, 'a').writelines(host+' '*(95-len(host)-len(start_time))+start_time+'\n')
        open(log_path, 'a').writelines(script_name+'\n')
        open(log_path, 'a').writelines('*'*95+'\n')
    elif state == 1:
        open(log_path, 'a').writelines('*'*95+'\nLog file location:\n')
        open(log_path, 'a').writelines(log_path+'\n'+'*'*95+'\n')
        print "Script logs are saved at : \033[93m %s \033[00m" % log_path

def firewall_check():
    """This function is to check the firewalld status"""
    print "[INFO]:  Checking firewalld status"
    logging.info("Checking firewalld status")
    active_status = sub.check_output("systemctl status firewalld | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = sub.check_output("systemctl status firewalld | sed -n '/Loaded:/p' | \
cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)
    backup_folder = '/ericsson/security/BACKUP_CONFIG_FILES/'
    backup_exist = os.path.exists(backup_folder)
    if active_status == "active\n" and enabled_status == "enabled\n" and backup_exist:
        print "[INFO]:  Firewalld status is active and enabled"
        logging.info("Firewalld status is active and enabled")
        return True
    logging.info("Firewalld is not enabled")
    print COLORS['RED']+"[ERROR]: firewalld is not enabled" +COLORS['END']
    return False

def sentinel_port_verfication():
    """This function is to verify Sentinel Port"""
    print "[INFO]:  Checking Sentinel port is open on the server"
    logging.info("Checking Sentinel port is open on the server")
    try:
        port_udp = sub.check_output("firewall-cmd --list-ports | grep -o 5093/udp", shell=True)
        if port_udp == "5093/udp\n":
            print "[INFO]:  Disabling Sentinel port for all external host"
            logging.info("Disabling Sentinel port for all external host")
            os.system("firewall-cmd --zone=public --remove-port=5093/udp --permanent > \
/dev/null 2>&1")
            restart_firewalld()
        else:
            print "[INFO]:  Sentinel port is not open in the server"
            logging.info("Sentinel port is not open in the server")
    except sub.CalledProcessError as error:
        if error.returncode != 1:
            print "[INFO]:  Sentinel port is not open in the server"
            logging.info("Sentinel port is not open in the server")
            logging.error("\33[31m RuntimeError \033[0m: command '%s return \
with error (code %s): %s", error.cmd, error.returncode, error.output)

def restart_firewalld():
    """This Function is to restart firewalld service"""
    logging.info('Reloading firewalld service')
    os.system("firewall-cmd --reload > /dev/null 2>&1")

def validate_ip_format(ip):
    """Validate the IP format (both IPv4 and IPv6)"""
    ipv4_pattern = r'^' + REG_255 + r'\.' + REG_255 + r'\.' + REG_255 + r'\.' + REG_255 + r'$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6})?::([0-9a-fA-F]{1,4}(:\
[0-9a-fA-F]{1,4}){0,6})?$'

    if re.match(ipv4_pattern, ip):
        return "ipv4"
    elif re.match(ipv6_pattern, ip):
        return "ipv6"
    else:
        return "invalid"

def get_netan_ip():
    """This Function will get NetAN IP and validate the IP format"""
    file_exist_status = os.path.exists("/eniq/installation/config/windows_server_conf_files/")
    if file_exist_status:
        try:
            netan_ip = sub.check_output("ls /eniq/installation/config/windows_server_\
conf_files/ | grep -i NETAN", shell=True, stderr=sub.STDOUT)
            whitelist_ip = netan_ip.replace(netan_ip[:6], '').strip()
            if validate_ip_format(whitelist_ip) == "ipv4" or validate_ip_format(whitelist_ip) \
== "ipv6":
                print whitelist_ip
                return whitelist_ip
            else:
                logging.error("Invalid IP format check NetAN configuration file under \
/eniq/installation/config/windows_server_conf_files/")
                print COLORS['RED']+"[ERROR]: Invalid IP format check NetAN configuration file \
under /eniq/installation/config/windows_server_conf_files/" + COLORS['END']
                return False
        except sub.CalledProcessError as error:
            if error.returncode != 1:
                print "[INFO]:  NetAN configuration details are not present on this ENIQ server"
                logging.info("NetAN configuration details are not present on this ENIQ server")
                logging.error("\33[31m RuntimeError \033[0m: command '%s return with error \
(code %s): %s", error.cmd, error.returncode, error.output)
                return False
    print "[INFO]:  NetAn configuration file is not found"
    logging.info("NetAn configuration file is not found")
    return False

def get_user_input():
    """This Function is to get NetAn IP from user Input and validate the IP format"""
    proceed = raw_input("Is NetAN server configured in ENIQ-S deployment (y/n):?")
    if proceed.lower() == "y":
        for _ in range(3):
            print "Enter NetAn Server IP :"
            whitelist_ip = raw_input().strip()
            if validate_ip_format(whitelist_ip) == "ipv4" or validate_ip_format(whitelist_ip) \
== "ipv6":
                return whitelist_ip
            else:
                print "Invalid IP"
                logging.info('Invalid IP')
                print "To Quit press Q/q and C/c to continue:"
                status = raw_input().strip()
                if status.lower() in ('q', 'quit'):
                    log_func(file_name, 1, LOG_PATH)
                    exit(0)
                elif status.lower() in ('c', 'continue'):
                    print "Enter a valid input"
                    logging.info('User entered invalid input')
        print "[ERROR]: Retry exceeded 3 times"
        logging.error("Retry exceeded 3 times")
        exit(1)
    elif proceed.lower() in ('n', 'no'):
        print"\n"
        exit(0)
    else:
        print "[INFO]:  You have entered an invalid option...!!\n"
        log_func(file_name, 1, LOG_PATH)
        exit(1)

def netan_whitelisting(whitelist_ip):
    """This Function will allow the NetAn IP"""
    backup_exist = os.path.exists(BACKUP_FILE)
    if backup_exist:
        for netan_ip in open(BACKUP_FILE, "r").read().splitlines():
            if netan_ip == whitelist_ip:
                print "[INFO]:  NetAn IP is already allowed"
                logging.info("NetAn IP is already allowed")
            else:
                print "[INFO]:  Removing Old NetAn IP from the allowed IP list"
                logging.info('Removing Old NetanIP from the allowed IP list')
                if validate_ip_format(whitelist_ip) == "ipv4":
                    command_remove = ("firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 \
source address=" + str(whitelist_ip) + " port port=5093 protocol=udp accept' ")
                    print command_remove
                elif validate_ip_format(whitelist_ip) == "ipv6":
                    command_remove = ("firewall-cmd --permanent --remove-rich-rule='rule family=ipv6 \
source address=" + str(whitelist_ip) +  " port port=5093 protocol=udp accept' ")
                    print command_remove
                os.system(command_remove + " 1>/dev/null 2>&1")
                print "[INFO]:  Allowing a New NetAn IP"
                if validate_ip_format(whitelist_ip) == "ipv4":
                    command_add = ("firewall-cmd --permanent --add-rich-rule='rule family=ipv4 \
source address=" + str(whitelist_ip) + " port port=5093 protocol=udp accept' ")
                    print command_add
                elif validate_ip_format(whitelist_ip) == "ipv6":
                    command_add = ("firewall-cmd --permanent --add-rich-rule='rule family=ipv6 \
source address=" + str(whitelist_ip) + " port port=5093 protocol=udp accept' ")
                    print command_add
                os.system(command_add + null_cmd)
                restart_firewalld()
                backup = open(BACKUP_FILE, 'w')
                backup.write(whitelist_ip)
    else:
        print "[INFO]:  Allowing the NetAn IP to access Sentinel Port"
        logging.info("Allowing the NetAn IP to access Sentinel Port")
        if validate_ip_format(whitelist_ip) == "ipv4":
            command_add = ("firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source \
address=" + str(whitelist_ip) + " port port=5093 protocol=udp accept' ")
            print command_add
        elif validate_ip_format(whitelist_ip) == "ipv6":
            command_add = ("firewall-cmd --permanent --add-rich-rule='rule family=ipv6 source \
address=" + str(whitelist_ip) + " port port=5093 protocol=udp accept' ")
            print command_add

        os.system(command_add + null_cmd)
        restart_firewalld()
        backup = open(BACKUP_FILE, 'w')
        backup.write(whitelist_ip)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_sentinel_hardening.log'
    os.system("mkdir -p /ericsson/security/log/")
    FORMAT_STR = '%(asctime)s\t%(levelname)s\t%(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/%s" % FNAME,
                        format=FORMAT_STR)
    LOG_PATH = "/ericsson/security/log/"+FNAME
    log_func(file_name, 0, LOG_PATH)
    ENIQ_INSTALLATION_PATH = os.path.exists("/eniq/installation/config/")
    if ENIQ_INSTALLATION_PATH is True:
        FIREWALL_STATUS = firewall_check()
    else:
        print COLORS['RED']+"[ERROR] This is not ENIQ server and sentinel hardening feature \
is not supported"+COLORS['END']
        logging.error("This is not ENIQ server and sentinel hardening feature is not supported")
        log_func(file_name, 1, LOG_PATH)
        exit(1)
    if FIREWALL_STATUS:
        sentinel_port_verfication()
        WHITELIST_IP = get_netan_ip()
        if not WHITELIST_IP:
            WHITELIST_IP = get_user_input()
        netan_whitelisting(WHITELIST_IP)
    else:
        logging.error("Apply Node hardening on the server.")
        print COLORS['RED']+"[ERROR]: Apply Node hardening "+ \
                        "on the server.\nRefer ENIQ-S Node Hardening Guide"+ \
                        "(4/1543-CNA 403 2613) for Nodehardening Procedure" +COLORS['END']
        log_func(file_name, 1, LOG_PATH)
        exit(1)
    log_func(file_name, 1, LOG_PATH)
    exit(0)
