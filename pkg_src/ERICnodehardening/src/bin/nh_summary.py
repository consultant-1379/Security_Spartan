#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
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
# *******************************************************************
# Name      : nh_summary.py
# Purpose   : This script wil automate the cron jon that will run
#             11 pm everday monday on once aweek
# Reason    : EQEV-103713
# Author    : ZNITGUP
# *******************************************************************
"""
import subprocess
import os
import time
import logging

def generate_report():
    '''Automate cron job'''
    try:
        cron_tab = subprocess.check_output("crontab -l", shell=True).split('\n')
        job = "0 23 * * 1 /usr/bin/python2.7 /ericsson/security/compliance/nh_summary_generate.py \
>> /dev/null 2>&1"
        if job in cron_tab:
            logging.info('****NH Summary cron job already configured****')
        else:
            cmd_crontab = '(crontab -l 2>/dev/null; echo "0 23 * * 1 ' \
'/usr/bin/python2.7 /ericsson/security/compliance/nh_summary_generate.py \
>> /dev/null 2>&1")| crontab -'
            os.system(cmd_crontab)
            os.system('systemctl restart crond')
            logging.info('****NH Summary cron job configured successfully****')
    except (IOError, RuntimeError, AttributeError, TypeError, subprocess.CalledProcessError):
        logging.info("Failed to set up summary job")

if __name__ == '__main__':
    generate_report()
