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
# Name     : inter_blade_access.py
# Purpose  : This script enables SSH access inter blade root users
#
# Author   : ZDODPRA
# Revision : A
# ********************************************************************
"""

import os
import re
import socket
from sentinel_hardening import log_func
from dcuser_ssh_login import is_valid_hostname

def enable_internal_root_ssh_access(host_list):
    """This function verifies hostnames"""
    try:
        for host in host_list:
            if is_valid_hostname(host):
                user = 'root@' + host
                enable_ssh_access(user)
            else:
                print "Invalid hostname:", host
                return 0
        return 1
    except (IOError, RuntimeError, AttributeError, TypeError, ValueError):
        return 0

def enable_ssh_access(user):
    """This function enables SSH access for mentioned hostname"""
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
                existing_users.append(user)
            existing_users = ' '.join(existing_users)
            data[a] = existing_users + '\n'
            with open('/etc/ssh/sshd_config', 'w') as fout:
                fout.writelines(''.join(data))
    except (IOError, RuntimeError, AttributeError, TypeError):
        return 0
