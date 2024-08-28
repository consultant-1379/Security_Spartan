#!/usr/bin/python
"""
# ******************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ******************************************************************************
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
# ********************************************************************************
# Name        : Pradeep Kumar (ZDODPRA)
# Purpose     : To restrict the users from su access.
# Date        : 05-07-2021
# Revision    : A
# Script Name : su_restriction.py
# ********************************************************************************
"""
import os
import getpass
import subprocess
import time
import logging
from Verify_NH_Config import configure_nh
from sentinel_hardening import log_func
from NH_Backup import backup_files
from user_verification import user_verification
def restrict_su_command():
    """This restricts su access to certain users only """
    backup_files('/etc/pam.d/su', [])
    server = server_type()
    add_group(server)
    try:
        with open("/etc/pam.d/su", 'r') as fin:
            data = fin.readlines()
        default_line1 = "#auth           required        pam_wheel.so use_uid\n"
        default_line2 = "#auth\t\trequired\tpam_wheel.so use_uid\n"
        configured_line = "auth            required        pam_wheel.so use_uid group=sugroup\n"
        temp = 0
        flag = 0
        for i in data:
            if default_line1 in i or default_line2 in i:
                temp = data.index(i)
                data[temp] = 'auth            required        pam_wheel.so use_uid group=sugroup\n'
                flag = flag+1
            elif configured_line in i:
                print"\n********************su restriction is already applied********************\n"
                logging.info("su restriction is already applied")
        with open("/etc/pam.d/su", 'w') as fout:
            fout.writelines(''.join(data))
        if flag == 1:
            print"\n********************Successfully enforced su restriction********************\n"
            logging.info("Successfully enforced su restriction")
    except (IOError, RuntimeError):
        logging.error("Cannot restrict su accesss")
def server_type():
    """This function returns the server type"""
    check_mount_point = os.path.ismount("/JUMP")
    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")
    if mws_insttype_path is True:
        mws_insttype = subprocess.check_output("cat /ericsson/config/inst_type", shell=True)
        server_config_name = subprocess.check_output("cat /ericsson/config/ericsson_use_config | cut -d'=' -f 2", \
shell=True)
        server_config_name = server_config_name.replace('\n', '')
        if (check_mount_point is True) and ('rhelonly' in mws_insttype) and ('mws' in server_config_name):
            logging.info("Proceeding with MWS server")
            return 'MWS'
    elif eniq_insttype_path is True:
        logging.info("Proceeding with ENIQ-S server")
        return "ENIQ-S"
    else:
        logging.error("Server Not configured properly")
        exit(1)
def add_group(server_type):
    """This function is to add the sugroup and the users to it"""
    try:
        if os.path.exists("/ericsson/security/bin/username") is True:
            with open("/ericsson/security/bin/username", 'r') as fin:
                data = fin.readlines()
        else:
            logging.error("username file doesn't exist....Exiting")
            exit(1)
        check_present = subprocess.check_output("cat /etc/group | grep -iw sugroup | cut -d':' -f 1", shell=True)
        check_present = check_present.strip()
        if check_present != "sugroup":
            os.system("groupadd sugroup > /dev/null 2>&1")
            logging.info("Created the sugroup")
        else:
            logging.info("The sugroup is already present")
        check_users = subprocess.check_output("cat /etc/group | grep -iw sugroup | cut -d':' -f 4", shell=True)
        check_users = check_users.strip().split(',')
        data1 = []
        for i in data:
            if i != "\n":
                data1 = i.split()
                user = data1[0]
                if server_type == "MWS":
                    if data1[0] != "storadm" and data1[0] != "dcuser" in check_users:
                        logging.info("%s is already added into the group" %user)
                    elif data1[0] != "storadm" and data1[0] != "dcuser":
                        add_user(user)
                elif server_type == "ENIQ-S":
                    if data1[0] in check_users:
                        logging.info("%s is already added into the group" %user)
                    else:
                        add_user(user)
        logging.info("sugroup is already present")
    except IndexError:
        logging.error("Unable to set the su user restrictions")
def add_user(user_name):
    """This adds the users to the sugroup"""
    try:
        os.system("usermod -a -G sugroup %s > /dev/null 2>&1" %user_name)
    except OSError:
        logging.error("Cannot set all required users into sugroup ")
if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + 'su_restriction.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,\
filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,\
format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'su_restriction.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        restrict_su_command()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
