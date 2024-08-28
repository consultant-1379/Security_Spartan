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
# Name      : set_autologout.py
# Purpose   :This script enables automatic logout and sets the
#                lockout time to 900 secs.
# ********************************************************************
"""
import subprocess
import os
import time
import logging
from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/profile"
#------------------------------------------------------------------------------------
#Automatic Logout
#-------------------------------------------------------------------------------------
def auto_logout():
    """This function enables automatic logout and sets the lockout time to 900 secs."""
    backup_files(file_name, [])
    with open("/etc/profile", "r") as in_file:
        buf = in_file.readlines()
    if 'TMOUT' in open(file_name).read():
        if 'readonly TMOUT' in open(file_name).read():
            print "\n**********Automatic logout is already enabled**********\n"
            logging.info('Automatic timeout is already set for 900 seconds and readonly')
        else:
            with open(file_name, "w") as out_file:
                for line in buf:
                    if line == "TMOUT=900\n":
                        line = line + "readonly TMOUT\n"
                    out_file.write(line)
    else:
        line1 = "TMOUT=900"
        line2 = "readonly TMOUT"
        line3 = "export TMOUT"
        with open(file_name, 'a') as out:
            out.write('{}\n{}\n{}\n'.format(line1, line2, line3))
        print "\n**********Successfully enabled automatic logout**********\n"
        logging.info('Successfully enabled automatic logout and set timeout for 900 seconds')
if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + 'set_autologout.log'
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
        auto_logout()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\n \033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
