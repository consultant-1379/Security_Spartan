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
# Name      : vlan_ssh_restriction_rollback.py
# Author    : XMEGHHR
# Date      : 30-01-2020
# Revision  : A
# Purpose   : This script is to restore/rollback VLAN SSH restriction and
#             allowing IP's on the server.
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
from vlan_ssh_restriction import firewall_check
from user_verification import user_verification
file_name = "vlan_ssh_restriction_rollback.py"
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

def whitelist_rollback():
    """This function is to perform rollback of allowing IPs"""
    try:
        print "[INFO]:  Performing rollback of allowing IP on the server"
        for ip_s in WHITELISTED_IPS.keys():
            command_ipv4 = "firewall-cmd --zone=public --remove-rich-rule 'rule family=ipv4 "+ \
"source address=\"%s\" service name=\"ssh\" accept' --permanent 1>/dev/null 2>&1" % ip_s
            command_ipv6 = "firewall-cmd --zone=public --remove-rich-rule 'rule family=ipv6 "+ \
"source address=\"%s\" service name=\"ssh\" accept' --permanent 1>/dev/null 2>&1" % ip_s

            status_ipv4 = os.system("{} >/dev/null 2>&1".format(command_ipv4)) if os.name == \
"posix" else os.system("{} >NUL 2>&1".format(command_ipv4))
            status_ipv6 = os.system("{} >/dev/null 2>&1".format(command_ipv6)) if os.name == \
"posix" else os.system("{} >NUL 2>&1".format(command_ipv6))

            if status_ipv4 != 0 and status_ipv6 != 0:
                print COLORS['RED']+"[ERROR]: Failed to remove %s from allowing IPs. \
Check %s for further details" % (ip_s, LOG_PATH) + COLORS['END']
                logging.error(COLORS['RED']+"Failed to remove %s from allowing IPs. \
Check %s for further details", ip_s, LOG_PATH +COLORS['END'])
                log_func(file_name, 1)
                exit(1)
            logging.info("Removed %s from allowed IPs", ip_s)
        print "[INFO]:  Rollback of allowing IPs is successful"
        logging.info("Rollback of allowing IPs is successful")
    except (subprocess.CalledProcessError, IOError, AttributeError, OSError, \
ValueError) as e:
        logging.warning("Error while rolling back Whitelisted IP: %s", e)

def vlan_rollback():
    """This function is to perform rollback of SSH VLAN restriction"""
    try:
        print "[INFO]:  Performing rollback for VLAN restriction on the server"
        for vlan_subnet in PERMITTED_VLANS.keys():
            command_ipv4 = "firewall-cmd --zone=public --remove-rich-rule 'rule family=ipv4 "+ \
"source address=\"%s\" service name=\"ssh\" accept' --permanent 1>/dev/null" % vlan_subnet
            command_ipv6 = "firewall-cmd --zone=public --remove-rich-rule 'rule family=ipv6 "+ \
"source address=\"%s\" service name=\"ssh\" accept' --permanent 1>/dev/null" % vlan_subnet

            status_ipv4 = os.system("{} >/dev/null 2>&1".format(command_ipv4)) if os.name == \
"posix" else os.system("{} >NUL 2>&1".format(command_ipv4))
            status_ipv6 = os.system("{} >/dev/null 2>&1".format(command_ipv6)) if os.name == \
"posix" else os.system("{} >NUL 2>&1".format(command_ipv6))

            if status_ipv4 != 0 and status_ipv6 != 0:
                print COLORS['RED']+"[ERROR]: Failed to remove SSH VLAN restriction for %s. \
Check %s for further details" % (vlan_subnet, LOG_PATH) + COLORS['END']
                logging.error(COLORS['RED']+"Failed to remove SSH VLAN restriction for %s. \
Check %s for further details", vlan_subnet, LOG_PATH +COLORS['END'])
                log_func(file_name, 1)
                exit(1)
            logging.info("SSH VLAN restriction is removed for %s", vlan_subnet)

        print "[INFO]:  Restarting firewalld service"
        logging.info("Restarting firewalld service")
        os.system("systemctl restart firewalld 1>/dev/null 2>&1")
        print "[INFO]:  Rollback of SSH VLAN restriction is successful"
        logging.info("Rollback of SSH VLAN restriction is successful")
    except (subprocess.CalledProcessError, IOError, AttributeError, OSError, \
ValueError) as e:
        logging.warning("Error while Rolling back VLAN SSH access: %s", e)


if __name__ == '__main__':
    user_verification()
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    USER = subprocess.check_output("whoami", shell=True).replace('\n', '')
    if USER != 'root':
        print "\33[31mYou are not root user.\n Script exiting.\033[0m"
        exit(1)
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_VLAN_SSH_Restriction_rollback.log'
    os.system('mkdir -p /ericsson/security/log/VLAN_Logs')
    FORMAT_STR = '%(asctime)s\t%(levelname)s\t%(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/VLAN_Logs/%s" % FNAME,
                        format=FORMAT_STR)
    LOG_PATH = '/ericsson/security/log/VLAN_Logs/'+FNAME
    log_func(file_name, 0)
    COLORS = {'RED' : '\33[31m', 'END' : '\033[0m', 'GREEN' : '\33[32m', 'YELLOW' : '\33[33m'}
    if not firewall_check():
        log_func(file_name, 1)
        exit(1)
    if not os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES/added_ips.pkl"):
        logging.error(COLORS['RED']+"SSH VLAN restriction is not configured on the server\033[0m")
        print COLORS['RED']+"[ERROR]: SSH VLAN restriction is not configured on the server\033[0m"
        log_func(file_name, 1)
        exit(1)
    WHITELISTED_IPS, PERMITTED_VLANS = pickle.load(open\
("/ericsson/security/BACKUP_CONFIG_FILES/added_ips.pkl", 'r'))
    if PERMITTED_VLANS:
        if WHITELISTED_IPS:
            print "[INFO]:  Adding SSH service to public zone"
            logging.info("Adding SSH service to public zone")
            os.system("firewall-cmd --permanent --add-service=ssh 1>/dev/null 2>&1")
            whitelist_rollback()
            vlan_rollback()
        else:
            print "[INFO]:  Adding SSH service to public zone"
            logging.info("Adding SSH service to public zone")
            os.system("firewall-cmd --permanent --add-service=ssh 1>/dev/null 2>&1")
            vlan_rollback()
    else:
        print COLORS['RED']+"[ERROR]: Apply SSH VLAN Restriction and Allowing listed IP's " \
                            "before running Rollback"+COLORS['END']
        logging.error("\33[31mSSH VLAN Restriction and IP Whitelisting not configured\033[0m")
        log_func(file_name, 1)
        exit(1)
    print "[INFO]:  Cleaning up"
    logging.info("Cleaning up")
    os.system("rm -rf /ericsson/security/BACKUP_CONFIG_FILES/added_ips.pkl")
    log_func(file_name, 1)
