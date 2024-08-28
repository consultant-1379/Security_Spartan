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
# Name     : reenable_ssh_login.py
# Purpose  : This script removes deployed ip address for root and
#            provides ssh access for root.
# Author   : ZBARPHU
# Revision : A
# Reason   : EQEV-106689
# ********************************************************************
"""

import os
import subprocess

with open("/etc/ssh/sshd_config", 'r') as fin:
    data = fin.read()
data = data.split()

def group_existence_check():
    """This function verifies whether the ENIQ_ADMIN_ROLE group is present or not"""
    group_existence = subprocess.check_output("cat /etc/group | grep ENIQ_ADMIN_ROLE | \
cut -d':' -f 1", shell=True).strip()
    if group_existence != "ENIQ_ADMIN_ROLE":
        print "\n Privileged user group is not present on the server! \n \n \
Exiting the Script execution! \n"
        return 0
def reenable_ssh_login():
    """This function verifies and provides root SSH access """
    try:
        if group_existence_check() == 0:
            return 0
        if "AllowUsers" not in data:
            print "\n SSH access parameter is not configured in config file \n Exiting the script execution \n"
            return 0
            exit(1)

        else:
            os.system("sed -i 's/\S*\(root@\)\S*//g' /etc/ssh/sshd_config")
            with open('/etc/ssh/sshd_config', 'r+') as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    if line.startswith('AllowUsers'):
                        lines[i] = lines[i].strip() + ' root\n'
                f.seek(0)
                for line in lines:
                    f.write(line)
            f.close()
            return 1

    except IOError:
        print "Script exited abnormally!"
        return 0

if __name__ == '__main__':
    reenable_ssh_login()
