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
# *************************************************************************
# Name      : disable_sftp.py
# Purpose   : This script is used to revoke the configuration of SFTP user.
# Author    : ZSABVAR
# Reason    : EQEV-100651
# Revision  : A
# *************************************************************************
"""
import os
import logging
import time
import subprocess
import getpass
from Verify_NH_Config import configure_nh
from sentinel_hardening import log_func
from user_verification import user_verification

def rollback_sftp():
    """This function rollbacks SSH restriction for SFTP connection."""
    try:
        sftp_file_path = "/ericsson/security/bin/sftp_user_list"
        check = os.path.exists(sftp_file_path) and os.path.getsize(sftp_file_path) > 0
        logging.info('checking sftp_user_list file is present or not!!')
        if check:
            remove_cron_job(sftp_file_path)
            remove_user(sftp_file_path)
            revoke_ownership(sftp_file_path)
            remove_group()
            logging.info('Removing sftp_user_list file!!')
            os.system("rm -rf /ericsson/security/bin/sftp_user_list")

            print "\n\x1b[32m**********Rollback of SFTP user configuration was " \
                  "successful!!**********\x1b[0m\n"
            logging.info("Rollback of SFTP user configuration was successful!!")
        else:
            logging.error('sftp_user_list file was not found!!')
            print "\n\033[31m**********sftp_user_list file was not found. " \
                  "Failed to rollback SFTP user configuration!!**********\033[00m\n"
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to rollback SFTP user configuration!!')

def remove_cron_job(sftp_file_path):
    """This function removes the running cron job for clean up of logs."""
    try:
        cmd_crontab = "sed  -i '/\\/ericsson\\/security\\/bin\\/cron_sftp.py/d' " \
                      "/var/spool/cron/root"
        os.system(cmd_crontab)
        logging.info('cron job has been removed for user\'s home directory!!')
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to remove cron job!!')

def remove_user(sftp_file_path):
    """This function removes user from AllowUser parameter in sshd_config file."""
    try:
        with open(sftp_file_path, 'r') as fdata:
            remove_user = fdata.read().splitlines()

        cmd_allowuser = "cat /etc/ssh/sshd_config | grep AllowUsers"
        process_allowuser = subprocess.Popen(cmd_allowuser, shell=True, stdout=subprocess.PIPE)
        output_allowuser = process_allowuser.stdout.read()
        if output_allowuser != "":
            for username in remove_user:
                cmd_remove_user = "sed -i -e '/AllowUsers/s/ " + username \
                                  + "//' /etc/ssh/sshd_config"
                os.system(cmd_remove_user)
                logging.info('User has been removed from AllowUsers parameter!!')
        remove_config(remove_user)
        logging.info('Restarting the sshd service!!')
        os.system("systemctl restart sshd")
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to remove user from AllowUser parameter in sshd_config file!!')

def remove_config(remove_user):
    """This function revokes SFTP configurations in sshd_config file."""
    try:
        match = ["Match Group sftpgroup", "ForceCommand internal\\-sftp", "Match all"]
        for user in remove_user:
            line1 = "ChrootDirectory \\/home\\/"+user
            match.append(line1)
        for line in match:
            cmd_remove_config = "sed -i -e '/"+line+"/d' /etc/ssh/sshd_config"
            os.system(cmd_remove_config)
        logging.info('Configuration lines has been removed!!')
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to revoke SFTP user configurations in sshd_config file!!')

def revoke_ownership(sftp_file_path):
    """This function revokes the ownership of user home directory."""
    try:
        with open(sftp_file_path, 'r') as ffile:
            user_list = ffile.read().splitlines()
        for username in user_list:
            cmd_user = "id " + username + " > /dev/null 2>&1"
            return_value_user = os.system(cmd_user)
            if return_value_user == 0:
                user_path = "/home/" + username
                check = os.path.exists(user_path)
                logging.info('checKing for user\'s home directory!!')
                if check:
                    logging.info('changing ownership of user\'s home directory!!')
                    os.system("chown " + username + " /home/" + username)
                    os.system("chmod 700 /home/" + username)
                else:
                    logging.info('user\'s home directory not exists!!')
            else:
                logging.error('User not found!!')
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to revoke the ownership of user home directory!!')

def remove_group():
    """This function removes the sftpgroup."""
    try:
        return_value_group = os.system("getent group sftpgroup > /dev/null 2>&1")
        if return_value_group != 0:
            logging.info('sftpgroup was not present!!')
        else:
            os.system("groupdel sftpgroup")
            logging.info('sftpgroup was deleted successfully!!')
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to remove sftpgroup!!')

if __name__ == "__main__":
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR+'_disable_sftp.log'
    os.system("mkdir -p /ericsson/security/log/Optional_NH_Logs/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Optional_NH_Logs/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Optional_NH_Logs/%s" % FNAME
    SCRIPT_NAME = 'disable_sftp.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        rollback_sftp()
    else:
        print "Failed to verify the security settings. " \
              "Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
