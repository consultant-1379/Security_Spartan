#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
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
# Name      : pwd_change_days_rollback.py
# Author    : Archit Anand (ZANAARC)
# Reason    : EQEV-85618 3UK Pen testing finding.
# Purpose   : This script removes the minimum no days between password change
#             for all users.
#********************************************************************
"""
import os
import time
import logging
import getpass
from sentinel_hardening import log_func
from user_verification import user_verification

def unset_days():
    """This function set the min no of days for\
password change to 0."""
    with open("/etc/passwd", "r") as fin:
        data = fin.readlines()
    for i in data:
        if i != '\n':
            data1 = i.split(":")
            if data1[0] == "dcuser":
                set_days = "chage -m 0 dcuser"
                os.system(set_days+"> /dev/null 2>&1")
            elif (data1[0] == "root") or (data1[0] == "storadm") or \
(int(data1[2]) < 999):
                #exclude root, storage and system users.
                pass
            else:
                set_days = "chage -m 0 "+data1[0]
                os.system(set_days+"> /dev/null 2>&1")

    with open('/etc/login.defs') as fin:
        etc_config = fin.read()
    conf = ['PASS_MIN_DAYS\t1\n', 'PASS_MIN_DAYS\t5\n', 'PASS_MIN_DAYS\t7\n']
    change_value = 'PASS_MIN_DAYS\t0\n'
    for i in conf:
        if i in etc_config:
            etc_config = etc_config.replace(i, change_value)
        else:
            continue

    with open('/etc/login.defs', 'w') as fout:
        fout.write(etc_config)
    print("\nMinimum number of days for password change are restored.")
    logging.info("Minimum number of days for password change have been set to 0.")
    log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_pwd_change_days_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Optional_NH_Logs/")

    FORMAT_STR = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Optional_NH_Logs/%s" % FNAME,
                        format=FORMAT_STR)
    SCRIPT_NAME = '_pwd_change_days_rollback.log'
    LOG_PATH = "/ericsson/security/log/Optional_NH_Logs/"+FNAME
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    unset_days()
