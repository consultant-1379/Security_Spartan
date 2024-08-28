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
# Name      : verify_date_time_info.py
# Purpose   : This script ensures that the modify date and time information
#             are collected or not.
# Reason    : EQEV-88535
# Authour   : ZATLPOE
# Revision  : A
# ********************************************************************
"""

import subprocess
import os


def check_date_time_info():
    """This function verifies the modify date and time information are collected successfully"""

    if os.path.exists("/etc/audit/rules.d/50-time_change.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_date_time_info.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-time_change.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        cmd = "getconf LONG_BIT"
        result = subprocess.check_output(cmd, shell=True)
        string = ""
        if int(result) == 64:
            if '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' in data and \
'-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' in data and \
'-a always,exit -F arch=b64 -S clock_settime -k time-change' in data and \
'-a always,exit -F arch=b32 -S clock_settime -k time-change' in data and \
'-w /etc/localtime -p wa -k time-change' in data:
                string = "COMPLIANT"
            else:
                string = "NON-COMPLIANT:  EXECUTE 'ensure_date_time_info.py' TO MAKE IT COMPLIANT"
        elif int(result) == 32:
            if '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' \
in data and '-a always,exit -F arch=b32 -S clock_settime -k time-change' in data and \
'-w /etc/localtime -p wa -k time-change' in data:
                string = "COMPLIANT"
            else:
                string = "NON-COMPLIANT: EXECUTE 'ensure_date_time_info.py' TO MAKE IT COMPLIANT"
        return string

if __name__ == '__main__':
    check_date_time_info()
