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
# ********************************************************************
# Name      : set_password_policy.py
# Purpose   : This script sets the password policy by enforcing as
#               mentioned in Desktop Security.
# ********************************************************************
"""

import logging
import os
import time
import subprocess
import commands

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from stor_pass_change import Pchange
from user_verification import user_verification
from enable_ssh_login import server_type
file_name_pswdauth = "/etc/pam.d/password-auth"
file_name_sysauth = "/etc/pam.d/system-auth"
logging_exp = "Expiring root user password"
logging_successful_exp = "Successfully expired root user password"

def change_hashing_algo():
    """Take backup of existing configuration files and apply recommended hashing algorithm"""
    backup_files(file_name_pswdauth, [])
    backup_files('/etc/pam.d/system-auth', [])
    backup_files('/etc/login.defs', [])

    status = subprocess.check_output("authconfig --test | grep hash | cut -d' ' -f 6", shell=True)
    if status == 'sha512\n':
        print "checking password policies"
        logging.info("Checking password policies")
        account()
        sys()
    else:
        os.system("authconfig --passalgo=sha512 --update > /dev/null")
        logging.info("password hashing algrithm is set to recommended algorithm")
        account()
        sys()
        reset_storage()

def reset_storage():
    """This function is to reset password of storage users"""

    os.system("rm -rf /ericsson/security/bin/result.txt")
    os.system("dmidecode -t chassis > /ericsson/security/bin/result.txt")
    with open("/ericsson/security/bin/result.txt", 'r') as fin:
        data = fin.read()
    if "Type: Blade" in data:
        reset = Pchange()
        reset.storage()
        logging.info("Default password is restored for storage users")
    os.system("rm -rf /ericsson/security/bin/result.txt")

def account():
    """This function checks if Account lockout has already been set or not."""
    file_name = file_name_pswdauth
    with open(file_name, 'r') as fin:
        data = fin.readlines()
        line = 'auth [success=1 default=ignore] pam_succeed_if.so user in root:dcuser\n'
        for i in data:
            if line in i:
                flag = True
                break
            else:
                flag = False
        if flag:
            print "\n*********Account Lockout is already enforced!**********\n"
            logging.info('Account Lockout is already enforced!')
        else:
            account_locking()
            print "\n*********Account Lockout has been successfully enforced!**********\n"
            logging.info('Account Lockout has been successfully enforced')

def account_locking():
    """This function sets the account lockout."""
    try:
        file_name = file_name_pswdauth
        with open(file_name, 'r') as fin:
            data = fin.readlines()
            index_number = 0
            line1 = 'auth        required      pam_faillock.so preauth silent audit deny=5 \
even_deny_root unlock_time=1800\n'
            line2 = 'auth        [default=die] pam_faillock.so authfail audit deny=5 \
even_deny_root  unlock_time=1800\n'
            for i in data:
                if line1 in i:
                    index_number = data.index(line1)
                    data.pop(index_number)
                if line2 in i:
                    index_number = data.index(line2)
                    data.pop(index_number)

        data2 = []
        for i in data:
            if i != "\n":
                data2 = i.split()
                if data2[0] == "auth" and data2[1] == "required" and data2[2] == "pam_env.so":
                    a = data.index(i)
        if data[a+1] != "auth [success=1 default=ignore] pam_succeed_if.so user in root:dcuser\n":
            data.insert(a+1, "auth [success=1 default=ignore] pam_succeed_if.so user in \
root:dcuser\n")

        with open(file_name, 'w') as fout:
            fout.writelines(''.join(data))

        with open(file_name, 'r') as fin:
            data = fin.readlines()

        data3 = []
        for i in data:
            if i != "\n":
                data3 = i.split()
                if data3[0] == "auth" and data3[1] == "required" and data3[2] == "pam_env.so":
                    a = data.index(i)
        if data[a+2] != "auth        required      pam_faillock.so preauth silent audit deny=5 \
unlock_time=1800\n":
            data.insert(a+2, "auth        required      pam_faillock.so preauth silent audit \
deny=5 unlock_time=1800\n")

        with open(file_name, 'w') as fout:
            fout.writelines(''.join(data))

        with open(file_name, 'r') as fin:
            data = fin.readlines()

        data4 = []
        for i in data:
            if i != "\n":
                data4 = i.split()
                if data4[0] == "auth" and data4[1] == "sufficient" and data4[2] == "pam_unix.so":
                    a = data.index(i)
        if data[a+1] != "auth        [default=die] pam_faillock.so authfail audit deny=5  \
unlock_time=1800\n":
            data.insert(a+1, "auth        [default=die] pam_faillock.so authfail audit deny=5  \
unlock_time=1800\n")

        with open(file_name, 'w') as fout:
            fout.writelines(''.join(data))

        with open(file_name, 'r') as fin:
            data = fin.readlines()

        data5 = []
        for i in data:
            if i != "\n":
                data5 = i.split()
                if data5[0] == "account" and data5[1] == "required" and \
data5[2] == "pam_permit.so":
                    a = data.index(i)
        if data[a+1] != "account     required      pam_faillock.so\n":
            data.insert(a+1, "account     required      pam_faillock.so\n")

        with open(file_name, 'w') as fout:
            fout.writelines(''.join(data))
    except IOError:
        logging.error('File not accessible')

def sys():
    """This function checks for the system auth file"""
    with open(file_name_sysauth, 'r') as fin:
        data = fin.readlines()
        line = "password [success=4 default=ignore] pam_succeed_if.so user ingroup storage\n"
        sec_context()
        for i in data:
            if line in i:
                flag = True
                break
            else:
                flag = False
        if flag:
            print "\n*********Password Complexity is already enforced!**********\n"
            logging.info('Password Complexity is already enforced!')

        else:
            complexity_set()
            expire()
            sec_context()
            print "\n*********Password Complexity has been successfully enforced!**********\n"
            logging.info('Password Complexity has been successfully enforced')


def sec_context():
    """This function is to verify Seinux Context of password history file and correct if otherwise"""
    output1 = commands.getoutput("ls -lZ /etc/security/opasswd | cut -d ':' -f'3'")
    output2 = commands.getoutput("ls -lZ /etc/security/opasswd.old | cut -d ':' -f'3'")
    if output1 != "shadow_t" or output2 != "shadow_t":
        os.system("restorecon -R -v /etc/security/opasswd* > /dev/null")

def expire():
    """This function is to determine the type of server and expire root user's password \
accordingly..."""
    root_expire = "passwd -e root > /dev/null"
    verify_server = server_type()
    if verify_server == "MWS":
        logging.info('%s', logging_exp)
        os.system(root_expire)
        logging.info('%s', logging_successful_exp)
    elif verify_server == "ENIQ-S":
        with open("/eniq/sw/conf/server_types", 'r') as fin:
            data = fin.readlines()
        if len(data)==1:
            logging.info('%s', logging_exp)
            os.system(root_expire)
            logging.info('%s', logging_successful_exp)
    else:
        logging.info("Error in verifying the type of server")

def complexity_set():
    """This function sets the password policies"""
    with open(file_name_pswdauth) as fin:
        data = fin.read().replace('password    requisite     pam_pwquality.so try_first_pass \
local_users_only retry=3 authtok_type=', 'password    requisite     pam_pwquality.so minlen=9 \
maxrepeat=2 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 ... enforce_for_root retry=3')
    with open(file_name_pswdauth, 'w') as fout:
        fout.write(data)

    with open(file_name_sysauth, 'r') as fin:
        data1 = fin.readlines()
        for i in data1:
            if i == "account     required      pam_permit.so\n":
                line1 = data1.index(i)
                # Excluding storage group from password policies
                data1.insert(line1+2, 'password [success=4 default=ignore] \
pam_succeed_if.so user ingroup storage\n')
    with open(file_name_sysauth, 'w') as fout:
        fout.writelines(''.join(data1))

    with open(file_name_sysauth, 'r') as fin:
        data2 = fin.readlines()
        for i in data2:
            if i == "password [success=4 default=ignore] pam_succeed_if.so user ingroup storage\n":
                line2 = data2.index(i)
                # Setting Password Complexity rules
                data2.insert(line2+1, 'password    requisite     pam_pwquality.so minlen=9 \
maxrepeat=2 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 ... enforce_for_root retry=3\n')
    with open(file_name_sysauth, 'w') as fout:
        fout.writelines(''.join(data2))

    with open(file_name_sysauth, 'r') as fin:
        data3 = fin.readlines()
        for i in data3:
            if i == "password    requisite     pam_pwquality.so minlen=9 maxrepeat=2 \
lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 ... enforce_for_root retry=3\n":
                line3 = data3.index(i)
                # Setting Password History check rules
                data3.insert(line3+1, 'password    required      pam_pwhistory.so debug \
use_authtok remember=5 enforce_for_root retry=3\n')
    with open(file_name_sysauth, 'w') as fout:
        fout.writelines(''.join(data3))

    with open(file_name_sysauth, 'r') as fin:
        data4 = fin.readlines()
        for i in data4:
            if i == "password    required      pam_pwhistory.so debug use_authtok \
remember=5 enforce_for_root retry=3\n":
                line4 = data4.index(i)
                data4.insert(line4+1, 'password    sufficient    pam_unix.so sha512 shadow \
nullok try_first_pass use_authtok\n')
    with open(file_name_sysauth, 'w') as fout:
        fout.writelines(''.join(data4))

    with open(file_name_sysauth, 'r') as fin:
        data5 = fin.readlines()
        for i in data5:
            if i == "password    sufficient    pam_unix.so sha512 shadow nullok \
try_first_pass use_authtok\n":
                line5 = data5.index(i)
                data5.insert(line5+1, 'password    required      pam_deny.so\n')
                break
    with open(file_name_sysauth, 'w') as fout:
        fout.writelines(''.join(data5))


if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_password_policy.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()

    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        change_hashing_algo()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
