#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
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
# Name       : verify_ssh_login.py
# Purpose    : This script verifies if ssh login has been restricted to
#              all users based upon server types
# Author     : Pradeep Kumar Doddagoudar (zdodpra)
# Reason     : EQEV-89425
# ********************************************************************
"""

import subprocess
import sys
import random
import string
import logging
import os
from IPy import IP
import socket

sys.path.insert(0, '/ericsson/security/bin')
from enable_ssh_login import server_type
from enable_ssh_login import ssh_user

class NullWriter(object):
    """This class is a null writer class that would hide the stdout"""
    def write(self, arg):
        """This method points to the stdout"""
        pass

def check_ssh_login():
    """This function  verifies if ssh login has been restricted to all users \
except the users in the username file or not"""

    check_flag = 0
    users = check_users()
    if not users:
        check_flag = 1
    sshd_config_file = '/etc/ssh/sshd_config'
    username_file = '/ericsson/security/bin/username'
    if 'AllowUsers' in open(sshd_config_file).read():
        os.system("yum install -y expect > /dev/null 2>&1")

        print "\nVerifying of SSH access for test user\n"
        logging.info('Creating a test user for testing ssh login')
        check_flag = verify_login(username_file, sshd_config_file)
    else:
        check_flag = 1

    if check_flag == 1:
        return "NON-COMPLIANT:  EXECUTE 'enable_ssh_login.py' TO MAKE IT COMPLIANT"
    else:
        return "COMPLIANT"

def verify_login(username_file, sshd_config_file):
    """This function is to test the ssh login by adding a test user"""
    flag = 0
    logging.info('Creating a test user for testing ssh login')
    status = subprocess.call("useradd sshtest > /dev/null 2>&1", shell=True)
    if status != 0:
        logging.error("\nFailed to create the test user:sshtest")

    rand_string = string.ascii_letters
    stringlength = 8
    rand_string = ''.join(random.choice(rand_string) for _ in range(stringlength))
    rand_no = string.digits
    digitlength = 6
    rand_digit = ''.join(random.choice(rand_no) for _ in range(digitlength))
    rand_password = rand_string + '#' + rand_digit
    rand_password = str(rand_password)

    os.system("echo '%s' | passwd --stdin sshtest 2>&1 | \
tee /ericsson/security/compliance/errorlog.txt > /dev/null 2>&1" % rand_password)

    if 'passwd: all authentication tokens updated successfully.' in \
open('/ericsson/security/compliance/errorlog.txt').read():
        logging.info('Password is also set for the user!')
    else:
        logging.error("\nFailed to set password for the test user: sshtest")
        flag = 1

    logging.info('Verifying ssh login for test user...')
    if 'sshtest' in open(username_file).read():
        logging.info('sshtest is already present in username file')
    else:
        os.system("echo \"sshtest\" >> /ericsson/security/bin/username ")

    if 'sshtest' in open(sshd_config_file).read():
        logging.info('sshtest is already present in sshd_config file')
    else:
        nullwrite = NullWriter()
        oldstdout = sys.stdout
        sys.stdout = nullwrite
        ssh_user(0)
        sys.stdout = oldstdout

    os.system("systemctl restart sshd > /dev/null 2>&1")
    subprocess.call(['/ericsson/security/compliance/login.sh %s >\
 /ericsson/security/compliance/samp.txt' % rand_password], shell=True)
    user = subprocess.check_output("sed -n '/password/{n;p}' \
/ericsson/security/compliance/samp.txt", shell=True)
    name = user.replace('\n', '').replace('\r', '')
    if name != "sshtest":
        logging.error("\nUnable to login to server")
    print "\nVerification of SSH access completed for test user"
    print "\nRemoving the test user"
    remove_user(username_file, sshd_config_file)

    if user == 'sshtest' or name == 'sshtest':
        logging.info("Completed testing by logging as sshtest user")
    else:
        flag = 1

    return flag

def remove_user(username_file, sshd_config_file):
    """"This is to remove the added test user"""
    os.system("userdel -r sshtest > /dev/null 2>&1")
    os.system("rm -rf /home/sshtest > /dev/null 2>&1")
    os.system("rm -rf /ericsson/security/compliance/samp.txt > /dev/null 2>&1")
    os.system("rm -rf /ericsson/security/compliance/errorlog.txt > /dev/null 2>&1")
    os.system("ssh-keygen -R localhost > /dev/null 2>&1")
    with open(username_file) as fin:
        data = fin.read()
    data = data.split('\n')
    if 'sshtest' in data:
        data.remove('sshtest')
    with open(username_file, 'w') as fout:
        fout.writelines('\n'.join(data))
    with open(sshd_config_file) as fin:
        newtext = fin.read().replace('sshtest', '')
    with open(sshd_config_file, "w") as fout:
        fout.write(newtext)
    os.system("systemctl restart sshd > /dev/null 2>&1")

def check_users():
    """This verifies only the required users based on server type are allowed access and\
storadm are blocked from external login in ENIQ-S server"""
    try:
        hostname = socket.gethostname()
        storadmlocal_host = "storadm@"+hostname

        server = server_type()

        with open("/etc/ssh/sshd_config", 'r') as fin:
            data = fin.readlines()
        data1 = []

        user_list = ""
        for line in data:
            if line != '\n':
                data1 = line.split()
                if data1[0] == "AllowUsers":
                    a = data.index(line)
                    user_list = data[a]
        extra_users = ['storadm', 'dcuser']
        eniq_users = [storadmlocal_host]
        flag = 0
        user_list = user_list.split(' ')
        if server == "MWS":
            if extra_users not in user_list and eniq_users not in user_list and 'root' in user_list:
                flag = 1
        elif server == "ENIQ-S" and eniq_users not in user_list:
            flag = 1
        return flag
    except (IOError, RuntimeError, TypeError, ValueError):
        logging.error("Invalid hostname address found...")

if __name__ == '__main__':
    check_ssh_login()
