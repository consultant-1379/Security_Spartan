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
# Name      : cron_sftp.py
# Purpose   : This script is used to delete the log files present
#             inside SFTP user's home directory.
# Author    : ZSABVAR
# Reason    : EQEV-100651
# Revision  : A
# ********************************************************************
"""

import os
import subprocess
import sys
import re

from user_verification import user_verification

def validate_user_input():
    """This function validates whether user input string is acceptable or not."""
    try:
        if len(sys.argv) == 2:
            string = sys.argv[1].strip()
            regex = re.compile(r'[\'\-\+\[\]`"=_@!#$%^&*()<>?/\|}{~:;,]')
            if (string.strip() != ""
                    and regex.search(string) == None
                    and re.search(r'[A-Z]',string) == None
                    and re.search(r'[a-z]', string) == None
                    and string != '.'
                    and len(string)<=4):
                check_username_backupfile(string)
            else:
                check_username_backupfile("1")
        else:
            check_username_backupfile("1")
    except(IOError, RuntimeError, AttributeError, TypeError):
        pass
def check_username_backupfile(string):
    """This function is to check whether username backup file is present or not """
    try:
        sftp_file_path = "/ericsson/security/bin/sftp_user_list"
        check = os.path.exists(sftp_file_path) and os.path.getsize(sftp_file_path) > 0
        if check:
            cron_job(string,sftp_file_path)
    except(IOError, RuntimeError, AttributeError, TypeError):
        pass

def cron_job(input,sftp_file_path):
    """This function deletes the log files present inside user's home directory."""
    try:
        with open(sftp_file_path, 'r') as fread:
            user_list = fread.read().splitlines()
        for username in user_list:
            check_homedir = os.path.exists("/home/"+username)
            if check_homedir:
                dir_size = subprocess.check_output("du -h /home/"+username,shell=True).split()[0]
                if dir_size[-1] == 'G' and float(dir_size[0:-1])>float(input):
                    os.system("find /home/"+username+"/ENIQ_log_collector_*.zip -mtime +0 "
                                                     "-type f -delete >> /dev/null 2>&1")
                else:
                    os.system("find /home/"+username+"/ENIQ_log_collector_*.zip -mtime +2 "
                                                     "-type f -delete >> /dev/null 2>&1")
    except(IOError, RuntimeError, AttributeError, TypeError):
        pass

if __name__ == "__main__":
    user_verification()
    validate_user_input()
