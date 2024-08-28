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
# Name      : set_passd_change_days.py
# Author    : Archit Anand (ZANAARC)
# Reason    : EQEV-85618 3UK Pen testing finding.
# Purpose   : This script sets the minimum no days between password change
#             for all users except root and storage users.
#********************************************************************
"""
import os
import time
import logging
import getpass
from sentinel_hardening import log_func
from user_verification import user_verification

def pass_days():
    """This function sets the password aging\
 for all the users except root and storobj"""
    days = get_days()
    with open("/etc/passwd", "r") as fin:
        data = fin.readlines()
    for i in data:
        if i != '\n':
            data1 = i.split(":")
            if data1[0] == "dcuser":
                set_days = "chage -m "+ days+" dcuser"
                check_output_dcuser = os.system(set_days+"> /dev/null 2>&1")
                if check_output_dcuser == 0:
                    continue
                else:
                    print "Number of days for dcuser is not set."
                    logging.info('Number of days for dcuser is not set.')
            elif (data1[0] == "root") or (data1[0] == "storadm") or \
(int(data1[2]) < 999):
                #Root, storage users and system users are excluded.
                pass
            else:
                set_days = "chage -m "+ days +" "+ data1[0]
                check_output = os.system(set_days+"> /dev/null 2>&1")
                if check_output == 0:
                    continue
                else:
                    print 'Number of days for'+data1[0]+'are not set.'
                    logging.info('Number of days for'+data1[0]+'are not set.')

    with open('/etc/login.defs') as fin:
        etc_config = fin.read()
    conf = ['PASS_MIN_DAYS\t0\n', 'PASS_MIN_DAYS\t1\n', 'PASS_MIN_DAYS\t5\n', 'PASS_MIN_DAYS\t7\n']
    change_value = 'PASS_MIN_DAYS\t'+days+'\n'
    for i in conf:
        if i in etc_config:
            etc_config = etc_config.replace(i, change_value)
        else:
            continue

    with open('/etc/login.defs', 'w') as fout:
        fout.write(etc_config)
    print '\nNumber of days for password change has been set to '+days+'.'
    logging.info('Number of days for password change has been set to \
 '+days +' for all users except for root,storadm.')
    log_func(SCRIPT_NAME, 1, LOG_PATH)

def get_days():
    """This function to get the days for minimum\
 number of days for password change"""
    try:
        while True:
            print '\n'
            days_input = raw_input("Enter number of days for \
Password Change(Default is 1) [1,5,7]:")
            if days_input == '1' or days_input == '5' or days_input == '7':
                logging.info('Number of days Entered by user is '+days_input)
                return days_input
            elif days_input == '':
                set_days = '1'
                logging.info('Number of days has been set to 1')
                return set_days
            else:
                print "Please Enter valid number of days...!!!"
    except (Exception, KeyboardInterrupt, EOFError):
        print "\nScript exited abnormally...!!!"
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)
        exit(1)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_set_passd_change_days.log'
    os.system("mkdir -p /ericsson/security/log/Optional_NH_Logs/")

    FORMAT_STR = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Optional_NH_Logs/%s" % FNAME,
                        format=FORMAT_STR)
    SCRIPT_NAME = '_set_passd_change_days.py'
    LOG_PATH = "/ericsson/security/log/Optional_NH_Logs/"+FNAME
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    pass_days()
