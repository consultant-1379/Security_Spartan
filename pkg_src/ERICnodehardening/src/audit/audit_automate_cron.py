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
# *******************************************************************
# Name      : audit_automate_cron.py
# Purpose   : This script will automate the cron jon that will run
#             everday at 11:45 pm.
# Reason    : EQEV-100494
# *******************************************************************
"""
import subprocess
import os
import time
import logging

def check_upgrade_case(cron_test,cron_match1):
    '''This function check the upgrade scenario and remove previous zipping time i.e 11:00 PM'''
    try:
        cron_file = "/ericsson/security/audit/cron_job_upgrade.txt"
        cron_test.remove(cron_match1)
        f = open(cron_file, "w")
        for item in range(0, len(cron_test)):
            f.write(cron_test[item]+"\n")
        f.close()
        cmd = 'crontab /ericsson/security/audit/cron_job_upgrade.txt'
        os.system("sed -i \'/^$/d\' /ericsson/security/audit/cron_job_upgrade.txt")
        os.system(cmd)
        os.system('systemctl restart crond')
        os.remove('/ericsson/security/audit/cron_job_upgrade.txt')
        logging.info("Sucessfully removed previous audit zipping cron job!")
    except (IOError, RuntimeError, AttributeError, TypeError, subprocess.CalledProcessError):
            print "Failed to remove previous audit zipping cron job!"
            logging.info("Failed to remove previous audit zipping cron job!")

def get_automated_audit_cron():
    '''Automate cron job'''
    try:
        cron_test = subprocess.check_output("crontab -l", shell=True).split('\n')
        cron_match = "45 23 * * * /usr/bin/python2.7 /ericsson/security/audit/auditlog_rotate.py \
>> /dev/null 2>&1"
        cron_match1 = "0 23 * * * /usr/bin/python2.7 /ericsson/security/audit/auditlog_rotate.py \
>> /dev/null 2>&1"
        if cron_match1 in cron_test:
            check_upgrade_case(cron_test,cron_match1)
        if cron_match in cron_test:
            print "****Audit cron job already configured****"
            logging.info('****Audit cron job already configured****')
        else:
            cmd_crontab = '(crontab -l 2>/dev/null; echo "45 23 * * * ' \
'/usr/bin/python2.7 /ericsson/security/audit/auditlog_rotate.py \
>> /dev/null 2>&1")| crontab -'
            os.system(cmd_crontab)
            os.system('systemctl restart crond')
            logging.info('****Audit cron job configured successfully****')
            print "****Audit cron job configured successfully****"
    except (IOError, RuntimeError, AttributeError, TypeError, subprocess.CalledProcessError):
            print "Failed to setup cron job"
            logging.info("Failed to set up cron job!")

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_audit_automate_cron.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=FORMAT_STRING)
    get_automated_audit_cron()