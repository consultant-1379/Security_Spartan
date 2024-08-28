#!/usr/bin/python
"""
# *********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# *********************************************************************
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
# Name     : dcuser_ssh_login.py
# Purpose  : This script enables SSH access for dcuser
#
# Author   : ZDODPRA
# Revision : A
# ********************************************************************
"""

import os
import sys
import logging
import socket
import time
import subprocess

from Verify_NH_Config import configure_nh

err_dcuser_ssh = "\nError while enabling SSH access for dcuser"
logging_dcuser_ssh = "Error while enabling SSH access for dcuser, Invalid input"
err_dcuser_ssh_ex = "\nRun the script by passing hostnames as Command Line \
Input as shown in the below example :- "
err_dcuser_ssh_ex_1 = "\nericsson/security/bin/dcuser_ssh_login.py <hostname1>,<hostname2>"
sshd_file = "/etc/ssh/sshd_config"

def enable_internal_dcuser_ssh_access():
    """This function validates and passes the dcuser hostnames directly"""
    try:
        address = sys.argv[1]
        hostnames = address.split(',')
        for hostname in hostnames:
            if is_valid_hostname(hostname):
                user = 'dcuser@' + hostname
                enable_ssh_access(user)
            else:
                print err_dcuser_ssh
                logging.warning('%s', logging_dcuser_ssh)
                print err_dcuser_ssh_ex
                print err_dcuser_ssh_ex_1
                return 0
        return 1
    except (IOError, RuntimeError, AttributeError, TypeError, IndexError):
        print err_dcuser_ssh
        logging.warning('%s', logging_dcuser_ssh)
        print err_dcuser_ssh_ex
        print err_dcuser_ssh_ex_1
        return 0

def enable_ssh_access(user):
    """This function adds the passed dcuser names to AllowUsers list"""
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
            with open(sshd_file, 'w') as fout:
                fout.writelines(''.join(data))
        duplicate()
    except (IOError, RuntimeError, AttributeError, TypeError,IndexError):
        print err_dcuser_ssh
        logging.warning('%s', logging_dcuser_ssh)
        print err_dcuser_ssh_ex
        print err_dcuser_ssh_ex_1
        return 0

def duplicate():
    if os.system("cat /etc/ssh/sshd_config | grep -w AllowUsers >> /dev/null") != 0:
        print "SSH access parameter is not present in the config file"
    else:
        line = subprocess.check_output("cat /etc/ssh/sshd_config | grep -w AllowUsers", shell=True)
        line_1 = line.split()
        res = [line_1[i] for i in range(len(line_1)) if i == line_1.index(line_1[i])]
        join = ' '.join(res)
        join = join+"\n"
        with open(sshd_file, 'r') as file:
            content = file.read()
        content = content.replace(line, join)
        with open(sshd_file, 'w+') as file:
            file.write(content)

def is_valid_hostname(hostname):
    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return False
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return False
        except socket.error:
            return True

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_dcuser_ssh_login.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)
    enable_internal_dcuser_ssh_access()



