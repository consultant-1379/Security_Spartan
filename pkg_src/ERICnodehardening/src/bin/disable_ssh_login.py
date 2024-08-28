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
# Name     : disable_ssh_login.py
# Purpose  : This script removes restricts SSH access for root and
#            dcuser.
# Author   : ZDODPRA
# Revision : A
# Reason   : EQEV-106689
# ********************************************************************
"""

import os
import subprocess
from IPy import IP
import socket
from dcuser_ssh_login import duplicate

def disable_ssh_access():
    """This module disables ssh access for root and dcuser"""
    try:
        hostname = socket.gethostname()

        verify = verify_group()

        with open("/etc/ssh/sshd_config", 'r') as fin:
            data = fin.readlines()
            data1 = []
            existing_users = ""
        for line in data:
            if line != '\n':
                data1 = line.split()
                if data1[0] == "AllowUsers":
                    a = data.index(line)
                    existing_users = data[a]
                    existing_users = existing_users.split()
        if verify != 0:
            existing_users = check_existing_users(hostname, existing_users)
            existing_users = ' '.join(existing_users)
            data[a] = existing_users + '\n'
        if existing_users != 1:
            with open('/etc/ssh/sshd_config', 'w') as fout:
                fout.writelines(''.join(data))
        duplicate()
        return 1
    except (IOError, RuntimeError, AttributeError, TypeError):
        return 0

def verify_group():
    """This module verifies the presence of Privileged user group"""
    group = subprocess.check_output("cat /etc/group",shell=True)
    group = group.split("\n")
    flag = 0
    for name in group:
        if "ENIQ_ADMIN_ROLE" in name:
            flag = 1
    return flag

def check_existing_users(hostname, existing_users):
    """This function checks and updates the existing users according to the server type"""
    try:
        for index, value in enumerate(existing_users):
            if value == "root" or value == "dcuser":
                existing_users[index] = value+"@"+ hostname
        return existing_users
    except (IOError, RuntimeError, AttributeError, TypeError):
        return 0

 #       logging.error("Failed to fetch existing users")

#disable_ssh_access()

