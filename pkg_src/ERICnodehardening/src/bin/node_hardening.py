#!/usr/bin/python
"""
#*********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
#**********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2023 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# *********************************************************************
# Name      : node_hardening.py
# Purpose   : This script verifies NH package and upgrdes it.
#             Full NodeHarding is applied post successfull upgrade.
# Revision  : A
# Reason    : EQEV-113841
# *********************************************************************
"""
import commands
import sys
import os
import logging
import subprocess
import time
from sentinel_hardening import log_func
from Verify_NH_Config import configure_nh
from user_verification import user_verification
def check_install_security_rpm():
    """This is to check and update NH package"""
    try:
        OM_LINUX_PATH = sys.argv[1]
        om_path = subprocess.check_output("ls %ssecurity/\
ERICnodehardening* "%OM_LINUX_PATH, shell=True)
        om_path = om_path.strip('\n')
        if os.path.exists(om_path):
            logging.info("Security package is available in %s", om_path)
        else:
            print"Security packages is not available in %s"%OM_LINUX_PATH
            logging.info("Security packages is not available in %s", OM_LINUX_PATH)
            exit(1)
        old_eric_rpm = commands.getoutput("rpm -q ERICnodehardening | cut -d'.' -f 1")
        if old_eric_rpm == "":
            print"\nSecurity RPM is not installed so not upgrading\n"
            logging.info("\nSecurity RPM is not installed so not upgrading\n")
        else:
            upgrade_package(om_path)
    except (IOError, RuntimeError, AttributeError, TypeError, subprocess.CalledProcessError,\
IndexError):
        print "\nUNABLE TO UPGRADE. RE-CHCEK THE PASSED INPUT!!\n"
        logging.info("Error in passed input!!!")
def upgrade_package(om_path):
    """This is to check compliance and upgrade node hardening"""
    try:
        status = commands.getoutput("rpm -Uvh %s"%om_path)
        if "Updating / installing..." in status:
            os.system("rm -rf /ericsson/security/BACKUP_CONFIG_FILES/ > /dev/null 2>&1")
            logging.info("\nRemoved files from back up directory\n")
            print"\n****Successfully Upgraded security rpm %s****\n"%om_path
            logging.info("\n*************Successfully Upgraded security rpm %s****** \
*******\n", om_path)
            logging.info("\n*********Proceeding with compliance status verification**********\n")
            print"\n**************Proceeding with compliance status verifcation**************\n"
            os.system("/ericsson/security/compliance/NH_Compliance.py")
            os.system("sleep 10s")
            logging.info("\n********Proceeding with Node Hardening*********\n")
            print"\n**************Proceeding with Node hardening**************\n"
            action = sys.argv[2] if len(sys.argv) > 2 else ""
            action = action.split()
            if "--ansible" in action:
                logging.info("Proceeding with Node hardening without reboot!\n")
                os.system("echo Y > /ericsson/security/bin/input.txt")
                os.system("/ericsson/security/bin/Apply_Node_Hardening.py --ansible < /ericsson/security/bin/input.txt")
                os.system("rm -rf /ericsson/security/bin/input.txt")
            else:
                logging.info("Proceeding with Node hardening with reboot!\n")
                os.system("echo Y > /ericsson/security/bin/input.txt")
                os.system("/ericsson/security/bin/Apply_Node_Hardening.py < /ericsson/security/bin/input.txt")
                os.system("rm -rf /ericsson/security/bin/input.txt")
        else:
            print"\nNewer package is already installed. Please check the passed input!!!\n"
            logging.info("\nNewer package is already installed. Please check the passed input\n")
    except (IOError, RuntimeError, AttributeError, TypeError, subprocess.CalledProcessError,\
IndexError):
        print "\nUNABLE TO UPGRADE. RE-CHCEK THE PASSED INPUT!!\n"
        logging.info("Error in passed input!!!")
if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_node_hardening.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/%s" % FNAME
    SCRIPT_NAME = 'node_hardening.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        check_install_security_rpm()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
