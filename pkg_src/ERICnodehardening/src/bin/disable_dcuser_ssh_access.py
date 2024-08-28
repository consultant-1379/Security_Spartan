#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2022 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name     : disable_dcuser_ssh_access.py
# Purpose  : This script removes SSH access for specified IP addresses
# Author   : ZDODPRA
# Revision : A
# Reason   : EQEV-106689
# ********************************************************************
"""
import os
import sys
import time
import logging
import subprocess
import re
import socket
from Verify_NH_Config import configure_nh
from dcuser_ssh_login import is_valid_hostname

err_dc_user = "Error while disabling SSH access for dcuser, Invalid input"
err_dc_user_print1 = "\nRun the script by passing hostnames as Command Line Input as shown in the below example :- "
err_dc_user_print2 = "\n/ericsson/security/bin/disable_dcuser_ssh_access.py <hostname1>,<hostname2>"

def disable_internal_dcuser_ssh_access():
    """This function verifies hostnames"""
    try:
        address = sys.argv[1]
        hostnames = address.split(',')
        for hostname in hostnames:
            if is_valid_hostname(hostname):
                user = 'dcuser@' + hostname
                disable_dcuser_ssh_access(user)
            else:
                print "**********Invalid Input format**********"
                logging.warning('%s', err_dc_user)
                print err_dc_user_print1
                print err_dc_user_print2
                return 0

        os.system("systemctl restart sshd")
        print "...Restarting SSHD..."
        return 1
    except (IOError, RuntimeError, AttributeError, TypeError, IndexError):
        print "Error while removing SSH access for dcuser"
        logging.warning('%s', err_dc_user)
        print err_dc_user_print1
        print err_dc_user_print2
        return 0

def disable_dcuser_ssh_access(user):
    """This function detects and removes passed hostname-based dcuser"""
    try:
        flag = 0
        with open("/etc/ssh/sshd_config", 'r') as fin:
            data = fin.readlines()
            data1 = []
            existing_users = ""
        for line in data:
            if line != '\n':
                data1 = line.split()
                if data1[0] == "AllowUsers":
                    flag = 1
                    a = data.index(line)
                    existing_users = data[a]
                    existing_users = existing_users.split()
        if flag == 1:
            if user not in existing_users:
                print "**********dcuser SSH access is not enabled for passed hostname*********"
            else:
                existing_users.remove(user)
            existing_users = ' '.join(existing_users)
            data[a] = existing_users + '\n'
            with open('/etc/ssh/sshd_config', 'w') as fout:
                fout.writelines(''.join(data))
    except (IOError, RuntimeError, AttributeError, TypeError, IndexError):
        print "\nError while removing SSH access for dcuser"
        logging.warning('%s', err_dc_user)
        print err_dc_user_print1
        print err_dc_user_print2
        exit(1)

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_dcuser_ssh_login.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)
    disable_internal_dcuser_ssh_access()
