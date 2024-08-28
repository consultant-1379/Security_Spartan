#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
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
# ********************************************************************
# Name     : nh_verification.py
# Purpose  : This script verifies whether Node Hardening is applied
#            on the server.
# Author   : ZBARPHU
# Revision : A
# Reason   : EQEV-106686
# ********************************************************************
"""

import os
import subprocess
import logging
import time
from sentinel_hardening import log_func

try:
    def logging_function():
        '''Stores the logging function'''
        TIMESTR = time.strftime("%Y%m%d-%H%M%S")
        FNAME = TIMESTR + '_nh_verification.log'
        os.system("mkdir -p /ericsson/security/log/nh_status_log/")
        FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
        logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/nh_status_log/%s" % FNAME,
                        format=FORMAT_STRING)
        LOG_PATH = "/ericsson/security/log/nh_status_log/%s" % FNAME
        SCRIPT_NAME = 'nh_verification.py'
        log_func(SCRIPT_NAME, 0, LOG_PATH)

    def nh_interrupt():
        cmd1 = "find /ericsson/security/log/Apply_NH_Logs | grep Apply_Node | sort -n | tail -1"
        file_check = subprocess.check_output(cmd1, shell=True)
        cmd_concat = "sed -n '1p ; $p' "+ file_check
        line_check = subprocess.check_output(cmd_concat, shell=True).split()
        if "WARNING" not in line_check and "reboot" not in line_check:
            return 0
        else:
            return 1

    def nh_check():
        logging_function()
        granular_excution = "Granular execution of a feature is applied before Node Hardening"
        nh_not_applied = "Node Hardening is not applied on the server, please Apply Node Hardening \
to continue!"
        nh_log = "/ericsson/security/log/Apply_NH_Logs"
        roll_back_log = "/ericsson/NH_Rollback_logs/"
        if os.path.exists(nh_log) == True and os.path.exists(roll_back_log) == False:
            data = subprocess.check_output("ls -l /ericsson/security/log/Apply_NH_Logs/", \
shell=True, stderr=subprocess.PIPE).strip()
            if "drw" in data and "-rw-r" not in data and "-r-xr-x" not in data:
                logging.info('Node Hardening is not applied on the server!')
                logging.warning(granular_excution)
                return 0
            else:
                logging.info('Node Hardening is applied on the server!')
                return 1

        elif os.path.exists(nh_log) == False and os.path.exists(roll_back_log) == False:
            logging.info(nh_not_applied)
            return 0

        elif os.path.exists(nh_log) == True and os.path.exists(roll_back_log) == True:

            nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/log\
/Apply_NH_Logs | grep Apply_Node | sort -n | tail -1 | cut -d '/' -f 6 | cut -d '_' -f 1 \
| cut -d '-' -f 1", shell=True, stderr=subprocess.PIPE)
            nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/log\
/Apply_NH_Logs | grep Apply_Node | sort -n | tail -1 | cut -d '/' -f 6 | cut -d '_' -f 1 \
| cut -d '-' -f 2", shell=True, stderr=subprocess.PIPE)
            rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| sort -n | tail -1 | cut -d '-' -f 1 | cut -d '/' -f 4", shell=True, stderr=subprocess.PIPE)
            rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| sort -n | tail -1 | cut -d '-' -f 2 | cut -c 1-6", shell=True, stderr=subprocess.PIPE)
            data = subprocess.check_output("ls -l /ericsson/security/log/Apply_NH_Logs/", \
shell=True, stderr=subprocess.PIPE).strip()

            if "drw" in data and "-rw-r" not in data and "-r-xr-x" not in data:
                logging.info('Node Hardening is not applied on the server!')
                logging.warning(granular_excution)
                return 0

            elif nh_logs_date_stamp > rollback_logs_date_stamp:
                if nh_interrupt() == 0:
                    logging.warning('Keyboard Interrupt is detected!')
                    logging.info(nh_not_applied)
                    return 0
                else:
                    logging.info('Node Hardening applied on the server')
                    return 1
            elif nh_logs_date_stamp == rollback_logs_date_stamp and nh_logs_time_stamp \
> rollback_logs_time_stamp:
                if nh_interrupt() == 0:
                    logging.warning('Keyboard Interrupt is detected!')
                    logging.info(granular_excution)
                    return 0
                else:
                    logging.info('Node Hardening is applied on the server')
                    return 1
            else:
                logging.info(nh_not_applied)
                return 0
        else:
            logging.info(nh_not_applied)
            return 0

except IOError:
    logging.error('Script exited abnormally!')
    log_func(SCRIPT_NAME, 1, LOG_PATH)
if __name__ == '__main__':
    nh_check()