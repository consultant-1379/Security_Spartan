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
# Name      : enable_sftp.py
# Purpose   : This script is used to configure SFTP user.
# Author    : ZSABVAR
# Reason    : EQEV-100651
# Revision  : A
# ********************************************************************
"""
import os
import logging
import time
import subprocess
import sys
import getpass
import re
from Verify_NH_Config import configure_nh
from sentinel_hardening import log_func
from user_verification import user_verification

def get_user_input():
    """This function gets the raw input from the user."""
    try:
        if len(sys.argv) == 2:
            validate_user_input(sys.argv[1].strip())
        elif len(sys.argv) == 1:
            validate_user_input(raw_input("Enter the username:\n").strip())
        else:
            logging.error('Please provide atmost one command line argument for this script!!')
            print "\n\033[31mAtmost one command line input is expected." \
                  "\n**********Failed to configure SFTP user!!**********\033[00m\n"
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to accept user input string!!')

def validate_user_input(string):
    """This function validates whether user input string is acceptable or not."""
    try:
        regex = re.compile(r'[\'\-\+\[\]`"=.@!#$%^&*()<>?/\|}{~:;,]')
        if (string.strip() != ""
                and regex.search(string) == None
                and re.search(r'[A-Z]',string) == None
                and string[0].isdigit() == False
                and len(string)<=32):
            logging.info('User input string is accepted!!')
            validate_user(string)
        else:
            logging.error('User input is not accepted!!')
            print "\n\033[31m**********User input is not accepted. " \
                  "Failed to configure SFTP user!!**********\033[00m\n"
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to accept user input string!!')

def validate_user(username):
    """This function validates whether user is present or not."""
    try:
        cmd_user = "id "+username+" > /dev/null 2>&1"
        return_value_user = os.system(cmd_user)
        if return_value_user == 0:
            user_path = "/home/" + username
            check = os.path.exists(user_path)
            logging.info('checKing for user\'s home directory!!')
            if check:
                logging.info('User\'s home directory exists!!')
                enable_sftp(username)
            else:
                logging.error('User\'s home directory not found!!')
                print "\n\033[31m**********User\'s home directory not found. " \
                      "Failed to configure SFTP user!!**********\033[00m\n"
        else:
            logging.error('User not found!!')
            print "\n\033[31m**********User not found. " \
                  "Failed to configure SFTP user!!**********\033[00m\n"
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to validate user!!')

def enable_sftp(username):
    """This function enforce SFTP access by restricting SSH access."""
    try:
        with open('/etc/ssh/sshd_config', 'r') as fin:
            data = fin.readlines()
        existing_users=""
        line_match = ""
        index_allowuser = -1
        for line in data:
            if line != '\n':
                line_split = line.split()
                if line_split[0] == "AllowUsers":
                    index_allowuser = data.index(line)
                    existing_users = data[index_allowuser]
                    existing_users = existing_users.split()
                if line == "Match Group sftpgroup\n":
                    line_match = line
        if username in existing_users:
            logging.info('User already present in AllowUsers parameter!!')
        elif index_allowuser != -1:
            os.system("sed -i -e '/AllowUsers/s/$/ "+username+"/' /etc/ssh/sshd_config")
            logging.info('User is added to the AllowUsers parameter!!')
        if line_match == "":
            fedit = open('/etc/ssh/sshd_config', 'a')
            line1 = "Match Group sftpgroup"
            line2 = "ChrootDirectory /home/"+username
            line3 = "ForceCommand internal-sftp"
            line4 = "Match all"
            fedit.write("\n{}\n{}\n{}\n{}\n".format(line1, line2, line3, line4))
            fedit.close()
            logging.info('Configuration lines has been added to sshd_config file!!')
        else:
            os.system("sed -i -e 's/ChrootDirectory \\/home.*/ChrootDirectory \\/home\\/"+
                      username+"/' /etc/ssh/sshd_config")
            logging.info('Configuration already added!!')

        logging.info('Restarting the sshd service!!')
        os.system("systemctl restart sshd")

        validate_group()
        logging.info('Adding user to the sftpgroup!!')
        os.system("usermod -G sftpgroup "+username)
        logging.info('changing ownership of user\'s /home directory!!')
        os.system("chown root /home/"+username)
        os.system("chmod 755 /home/"+username)
        cron_job(username)

        print "\n\x1b[32m**********Successfully configured SFTP user!!**********\x1b[0m\n"
        logging.info("Successfully configured SFTP user!!")

    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error("Failed to configure SFTP user!!")

def validate_group():
    """This function validates whether sftpgroup is present or not."""
    try:
        return_value_group = os.system("getent group sftpgroup > /dev/null 2>&1")
        if return_value_group != 0:
            os.system("groupadd sftpgroup")
            logging.info('Successfully sftpgroup was created!!')
        else:
            logging.info('Sftpgroup is already created!!')
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error("Failed to validate group!!")

def cron_job(username):
    """This function starts the cron job."""
    try:
        sftp_file_path = "/ericsson/security/bin/sftp_user_list"
        check = os.path.exists(sftp_file_path) and os.path.getsize(sftp_file_path) > 0
        logging.info('checking sftp_user_list file is present or not!!')
        if check:
            with open(sftp_file_path, 'r') as fdata:
                user_list = fdata.read().splitlines()
            if not username in user_list:
                os.system("echo " + username + ">>/ericsson/security/bin/sftp_user_list")
        else:
            os.system("echo " + username + ">>/ericsson/security/bin/sftp_user_list")
        cmd_cron = "cat /var/spool/cron/root | grep '/ericsson/security/bin/cron_sftp.py'"
        process_cron = subprocess.Popen(cmd_cron, shell=True, stdout=subprocess.PIPE)
        output_cron = process_cron.stdout.read()
        if output_cron == "":
            cmd_crontab = '(crontab -l 2>/dev/null; echo "0 23 * * * ' \
                          '/ericsson/security/bin/cron_sftp.py 1 >> /dev/null 2>&1")| crontab -'
            os.system(cmd_crontab)
            logging.info('Cron job cleanup enabled successfully for user\'s /home directory!!')
        else:
            logging.info('cron job already enabled!!')
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error("Failed to start cron job!!")

if __name__ == "__main__":
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR+'_enable_sftp.log'
    os.system("mkdir -p /ericsson/security/log/Optional_NH_Logs/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Optional_NH_Logs/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Optional_NH_Logs/%s" % FNAME
    SCRIPT_NAME = 'enable_sftp.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        get_user_input()
    else:
        print "Failed to verify the security settings. Execute " \
              "/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
