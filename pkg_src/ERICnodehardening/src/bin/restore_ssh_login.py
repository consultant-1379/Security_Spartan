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
# Name     : restore_ssh_login.py
# Purpose  : This script removes deployed ip address for root and
#            provides ssh access for root.
# Author   : ZDODPRA
# Revision : A
# ********************************************************************
"""

import os
import subprocess
import sys

def group_existence_check(group_file):
    """This function verifies whether the ENIQ_ADMIN_ROLE group is present or not"""
    group_existence = subprocess.check_output("cat %s | grep ENIQ_ADMIN_ROLE | \
cut -d':' -f 1"%group_file, shell=True).strip()
    if group_existence != "ENIQ_ADMIN_ROLE":
        print "\n Privileged user group is not detected in the passed file path! \n \n \
Exiting the Script execution! \n"
        return 0

def restore_ssh_login():
    """This function verifies and provides root SSH access """
    try:
        fpath = (sys.argv[1])
        fpath = fpath.split(',')
        length = len(fpath)
        if length != 2:
            print"\n ************File paths are not as expected************\n"
            print"\n Usage :-"
            print"\n /ericsson/security/bin/restore_ssh_login.py <group_file_absolute_path>,\
\<sshd_config_file_absolute_path>"
            return 0
        for file in fpath:
            if os.path.exists("%s"%file) is False:
                print"***********Invalid file path***************"
                print"\n Usage :-"
                print"\n /ericsson/security/bin/restore_ssh_login.py <group_file_absolute_path>,\
<sshd_config_file_absolute_path>"
                return 0
        group_file = fpath[0]
        config_file = fpath[1]
        if group_existence_check(group_file) == 0:
            return 0
        with open(config_file, 'r') as fin:
            data = fin.read()
            data = data.split()
        if "AllowUsers" not in data:
            print "\n SSH access parameter is not passed in config file \n Exiting the script execution \n"
            return 0
        else:
            os.system("sed -i 's/\S*\(root@\)\S*//g' %s"%config_file)
            with open(config_file, 'r+') as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    if line.startswith('AllowUsers') and 'root' not in line:
                        lines[i] = lines[i].strip() + ' root\n'
                f.seek(0)
                for line in lines:
                    f.write(line)
            os.system("systemctl restart sshd")
            return 1
    except (IndexError,IOError,TypeError,ValueError,RuntimeError, AttributeError, IndexError):
        print"*********Script exited abnormally*********"
        print"\n Usage :- "
        print"\n /ericsson/security/bin/restore_ssh_login.py <group_file_absolute_path>,\
<sshd_config_file_absolute_path>"
        exit(1)


if __name__ == '__main__':
    restore_ssh_login()

