#!/usr/bin/python
"""
# *********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# *********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2021 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name       : remove_privileged_ssh_access.py
# Purpose    : This script removes ssh access to specific privileged
#              users.
# Author     : Pradeep Kumar Doddagoudar (zdodpra)
# Reason     : EQEV-111410
# ********************************************************************
"""
import os

def remove_user_ssh(remove_user):
    try:
        with open("/etc/ssh/sshd_config", 'r') as fin:
            data = fin.readlines()
        data1 = []
        a = 0
        existing_users = ""
        for line in data:
            if line != '\n':
                data1 = line.split()
                if data1[0] == "AllowUsers":
                    a = data.index(line)
                    existing_users = data[a]
                    existing_users = existing_users.split()
                    for i in remove_user:
                        if i in existing_users:
                            cmd = "sed -i -e '/AllowUsers/s/"+i+"//' /etc/ssh/sshd_config"
                            os.system(cmd)
        return 1
    except (IOError, RuntimeError, AttributeError, TypeError, ValueError):
        return 0
