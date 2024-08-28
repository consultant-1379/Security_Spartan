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
#
# ********************************************************************
# Name      : vlan_ssh_restriction_permanent.py
# Author    : XMEGHHR
# Date      : 30-01-2020
# Revision  : A
# Purpose   : This script is to enable permanent
#             VLAN SSH restriction and allowing IP's
# Reason    : EQEV-68439
#---------------------------------------------------------------------
# History
"""

import os
import logging
import time
import pickle
import signal
import subprocess
import re

from vlan_ssh_restriction import firewall_check
from user_verification import user_verification

WHITELIST_RULES = "/ericsson/security/config/Permanent_white_list_rules.cfg"
VLAN_RULES = "/ericsson/security/config/Permanent_Vlan_rules.cfg"
REG_255 = '(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'
REG_IPV6 = r'[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]+'

def log_func(script_name, state):
    """This function is to create log file header and footer"""
    if state == 0:
        open(LOG_PATH, 'a').writelines('*'*95+'\n')
        host = subprocess.check_output('hostname', shell=True).replace('\n', '')
        start_time = time.strftime("%Y-%m-%d_%H-%M-%S")
        open(LOG_PATH, 'a').writelines(host+' '*(95-len(host)-len(start_time))+start_time+'\n')
        open(LOG_PATH, 'a').writelines(script_name+'\n'+'*'*95+'\n')
    elif state == 1:
        open(LOG_PATH, 'a').writelines('*'*95+'\nLog file location:\n')
        open(LOG_PATH, 'a').writelines(LOG_PATH+'\n'+'*'*95+'\n')
        print "Script logs are saved at : \033[93m %s \033[00m" % LOG_PATH
        os.system("rm -rf /ericsson/security/bin/*.pyc")

def apply_whitelist_perm():
    """This function is to allow provided IPs on the server"""
    try:
        if not os.path.exists(WHITELIST_RULES):
            logging.error(COLORS['RED'] + "%s file not found. Make sure you" % WHITELIST_RULES + \
" have applied and tested the temporary rules" + COLORS['END'])
            print COLORS['RED'] + "[ERROR]: %s file not found. Make sure you " % WHITELIST_RULES + \
"have applied and tested the temporary rules" + COLORS['END']
            log_func('vlan_ssh_restriction_permanent.py', 1)
            exit(1)
        print "[INFO]:  Performing permanent IP allowing on the server"

        ipv4_pattern = REG_255 + r'\.' + REG_255 + r'\.' + REG_255 + r'\.' + REG_255
        ipv6_pattern = REG_IPV6
        find_ip = r'(' + ipv4_pattern + r')|(' + ipv6_pattern + r')'

        for command in open(WHITELIST_RULES, 'r').read().splitlines():
            if command:
                whitelist_ip = re.search(find_ip, command).group(0)
                status = os.system("{} >/dev/null 2>&1".format(command)) if os.name == "posix" \
else os.system("{} >NUL 2>&1".format(command))
                if status != 0:
                    print COLORS['RED'] + "[ERROR]: Failed to apply the firewalld rules, " + \
"check %s for further details" % LOG_PATH + COLORS['END']
                    logging.error(COLORS['RED'] + "Failed to apply the firewalld rules, check" + \
"%s for further details", LOG_PATH + COLORS['END'])
                    logging.error(COLORS['RED'] + "Error in performing command for ip:" + \
"%s", whitelist_ip + COLORS['END'])
                    print "[INFO]:  Restarting firewalld service"
                    logging.info("Restarting firewalld service")
                    os.system('systemctl restart firewalld 1>/dev/null 2>&1')
                    log_func('vlan_ssh_restriction_permanent.py', 1)
                    exit(1)
                logging.info("Allowed IP's %s", whitelist_ip)
                WHITELISTED_IPS[whitelist_ip] = WHITELISTED_IPS.get(whitelist_ip, True)
        print "[INFO]:  Allowing IP's on the server is successful applied for the provided IPs"
        logging.info("Allowing IP's on the server is successful applied for the provided IPs")
    except (subprocess.CalledProcessError, IOError, AttributeError, OSError, \
ValueError) as e:
        logging.warning("Error while allowing Permanent IP: %s", e)

def apply_vlan_perm():
    """This function is to perform SSH VLAN restriction for the provided subnet IPs"""
    try:
        if not os.path.exists(VLAN_RULES):
            logging.error(COLORS['RED']+"%s file not found. Make sure you have" % VLAN_RULES + \
" applied and tested the temporary rules" +COLORS['END'])
            print COLORS['RED']+"[ERROR]: %s file not found. Make sure you have " % VLAN_RULES + \
"applied and tested the temporary rules" +COLORS['END']
            log_func('vlan_ssh_restriction_permanent.py', 1)
            exit(1)
        print "[INFO]:  Performing permanent VLAN restriction on the server"

        ipv4_pattern = REG_255 + r'\.' + REG_255 + r'\.' + REG_255 + r'\.' + REG_255
        ipv4_subnet_pattern = ipv4_pattern + r'[/](3[0-2]|[0-2]?[0-9])'
        ipv6_subnet_pattern = r'[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]+/[0-9]+'
        find_subnet = r'(' + ipv4_subnet_pattern + r')|(' + ipv6_subnet_pattern + r')'

        for command in open(VLAN_RULES, 'r').read().splitlines():
            if command:
                vlan_subnet = re.search(find_subnet, command).group(0)
                status = os.system("{} >/dev/null 2>&1".format(command)) if os.name == "posix" \
else os.system("{} >NUL 2>&1".format(command))
                if status != 0:
                    print COLORS['RED']+"[ERROR]: Failed to apply the firewalld rules, "+ \
"check %s for further details" % LOG_PATH + COLORS['END']
                    logging.error(COLORS['RED']+"Failed to apply the firewalld rules, check"+ \
" %s for further details", LOG_PATH +COLORS['END'])
                    logging.error(COLORS['RED']+"Error in performing firewall rule for %s", \
vlan_subnet +COLORS['END'])
                    log_func('vlan_ssh_restriction_permanent.py', 1)
                    exit(1)
                logging.info("SSH VLAN Restricted for %s", vlan_subnet)
                PERMITTED_VLANS[vlan_subnet] = PERMITTED_VLANS.get(vlan_subnet, True)
        print "[INFO]:  Removing SSH service from public zone"
        logging.info("Removing SSH service from public zone")
        os.system("firewall-cmd --permanent --remove-service=ssh 1>/dev/null 2>&1")
        print "[INFO]:  Restarting firewalld service"
        logging.info("Restarting firewalld service")
        os.system("systemctl restart firewalld 1>/dev/null 2>&1")
        os.system("rm -rf "+ VLAN_RULES)
        print "[INFO]:  Applied permanent SSH VLAN restriction for the provided subnets"
        logging.info("Applied permanent SSH VLAN restriction for the provided subnets")
    except (subprocess.CalledProcessError, IOError, AttributeError, OSError, \
ValueError) as e:
        logging.warning("Error while allowing Permanent VLAN restriction: %s", e)

if __name__ == '__main__':
    user_verification()
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    USER = subprocess.check_output("whoami", shell=True).replace('\n', '')
    if USER != 'root':
        print "\33[31mYou are not root user.\nScript exiting.\033[0m"
        exit(1)
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_VLAN_SSH_Restriction_permanent.log'
    os.system('mkdir -p /ericsson/security/log/VLAN_Logs')
    FORMAT_STR = '%(asctime)s\t%(levelname)s\t%(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/VLAN_Logs/%s" % FNAME,
                        format=FORMAT_STR)
    MESSAGE = '#'*105+'\n#'+' '*6+ \
              'Make sure you have applied temporary VLAN and allowing the listed IP rules and'+ \
              ' test SSH connection'+' '*6+'#\n'+'#'*105
    LOG_PATH = '/ericsson/security/log/VLAN_Logs/'+FNAME
    log_func('vlan_ssh_restriction_permanent.py', 0)
    COLORS = {'RED' : '\33[31m', 'END' : '\033[0m', 'GREEN' : '\33[32m', 'YELLOW' : '\33[33m'}
    print MESSAGE
    if not firewall_check():
        log_func('vlan_ssh_restriction_permanent.py', 1)
        exit(1)
    backup_config_added_ips = '/ericsson/security/BACKUP_CONFIG_FILES/added_ips.pkl'
    if not os.path.exists('/ericsson/security/config/temp_flag.pkl'):
        if os.path.exists(backup_config_added_ips):
            print COLORS['RED']+'[ERROR]: SSH restriction is already configured on '+ \
                                'the server.'+COLORS['END']
            logging.error(COLORS['RED']+'SSH restriction is already configured on '+ \
                                        'the server.'+COLORS['END'])
            log_func('vlan_ssh_restriction_permanent.py', 1)
            exit(1)
        else:
            logging.error(COLORS['RED']+'Temporary VLAN restriction rules are not '+ \
                                        'applied'+COLORS['END'])
            print COLORS['RED']+"[ERROR]: Temporary VLAN restriction rules are not applied" + \
                                ", script exiting"+COLORS['END']
            log_func('vlan_ssh_restriction_permanent.py', 1)
            exit(1)
    TMP_VAR, WHITELIST_VAR = pickle.load(open('/ericsson/security/config/temp_flag.pkl', 'r'))
    if os.path.exists(backup_config_added_ips):
        WHITELISTED_IPS, PERMITTED_VLANS = pickle.load(open\
(backup_config_added_ips, 'r'))
    else:
        WHITELISTED_IPS, PERMITTED_VLANS = dict(), dict()
    if TMP_VAR:
        if WHITELIST_VAR:
            print "[INFO]:  Restarting firewalld service"
            logging.info("Restarting firewalld service")
            os.system("systemctl restart firewalld 1>/dev/null 2>&1")
            os.system('systemctl restart firewalld 1>/dev/null 2>&1')
            apply_whitelist_perm()
            apply_vlan_perm()
            print "[INFO]:  Cleaning up"
            logging.info("Cleaning up")
            os.system("rm -rf "+ WHITELIST_RULES +' '+ VLAN_RULES)
        else:
            print "[INFO]:  Restarting firewalld service"
            logging.info("Restarting firewalld service")
            os.system('systemctl restart firewalld1>/dev/null 2>&1')
            apply_vlan_perm()
            print "[INFO]:  Claening up"
            logging.info("Cleaning up")
            os.system("rm -rf "+ VLAN_RULES)
    else:
        print COLORS['RED']+"[ERROR]: Temporary rules are not applied"+COLORS['END']
        print COLORS['RED']+"[ERROR]: Apply and test temporary SSH VLAN Restriction adn "+ \
                            "Allowing listed Ip's before running permanent rules"+COLORS['END']
        logging.error(COLORS['RED']+"Temporary rules are not applied"+COLORS['END'])
        log_func('vlan_ssh_restriction_permanent.py', 1)
        exit(1)

    pickle.dump([WHITELISTED_IPS, PERMITTED_VLANS], \
open(backup_config_added_ips, 'w'))
    os.system("rm -rf /ericsson/security/config/temp_flag.pkl")
    log_func('vlan_ssh_restriction_permanent.py', 1)

