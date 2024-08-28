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
# Name      : sentinel_hardening_rollback.py
# Author    : Megha H R
# Date      : 19-08-2020
# Revision  : A
# Purpose   : This script is to perform sentinel hardening rollback
#             by removing the allowed NetAN IP's.
# Reason    : EQEV-76384
#---------------------------------------------------------------------
# History
"""
import os
import logging
import time
import re
import signal
import subprocess as sub
from sentinel_hardening import log_func
from sentinel_hardening import restart_firewalld
from sentinel_hardening import validate_ip_format
from user_verification import user_verification
BACKUP_FILE = '/ericsson/security/BACKUP_CONFIG_FILES/netan_whitelisted_IP.txt'
REG_255 = '(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'
file_name = "sentinel_hardening_rollback.py"

def netan_whitelist_rollback():
    """This Function is to remove NetAn IP from the allowed IP list"""
    backup_exist = os.path.exists(BACKUP_FILE)
    if backup_exist:
        netan_ip = open(BACKUP_FILE, "r").read().replace('\n', '')
        if validate_ip_format(netan_ip) == "ipv4":
            command_remove = ("firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 \
source address=" + str(netan_ip) + " port port=5093 protocol=udp accept' ")
            print command_remove
        elif validate_ip_format(netan_ip) == "ipv6":
            command_remove = ("firewall-cmd --permanent --remove-rich-rule='rule family=ipv6 \
source address=" + str(netan_ip) +  " port port=5093 protocol=udp accept' ")
            print command_remove
        else:
            print "[ERROR]: Invalid IP found in backup"
            logging.error('Invalid IP found in backup')
            log_func(file_name, 1, LOG_PATH)
            cleanup()
            exit(1)

        print "[INFO]:  Removing NetAn IP from allowed IP list"
        logging.info('Removing NetanIP from allowed IP list')
        os.system(command_remove + " 1>/dev/null 2>&1")

        restart_firewalld()
        os.system("rm -rf /ericsson/security/BACKUP_CONFIG_FILES/netan_whitelisted_IP.txt")
        log_func(file_name, 1, LOG_PATH)
        cleanup()
        exit(0)
    print "[ERROR]: No Netan IP is allowed on the server"
    logging.error('No Netan IP is allowed on the server')
    log_func(file_name, 1, LOG_PATH)
    cleanup()
    exit(1)


def cleanup():
    """This Function is to do cleanup"""
    os.system("rm -rf /ericsson/security/bin/*.pyc")
if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_sentinel_hardening_rollback.log'
    os.system("mkdir -p /ericsson/security/log/")
    FORMAT_STR = '%(asctime)s\t%(levelname)s\t%(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/%s" % FNAME,
                        format=FORMAT_STR)
    LOG_PATH = "/ericsson/security/log/"+FNAME
    log_func(file_name, 0, LOG_PATH)
    netan_whitelist_rollback()

