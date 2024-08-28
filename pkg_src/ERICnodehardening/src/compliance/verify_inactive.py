#!/usr/bin/python
"""This script is to verify if the inactive days is set to 30 or not"""
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
# Name      : verify_inactive.py
# Purpose   : This script is to verify if the inactive days is set to
#             30 or not.
# Author    : Pradeep Kumar Doddagoudar
# Date      : 17-06-2021
# Revision  : A
# Reason    : EQEV-88190
# ********************************************************************
# History
"""
import subprocess
import logging
import os
def check_inactive():
    """This fundction verifies if the inactive password days is set to 30 or not"""
    status_default = verify_default_inactive()
    status_users = verify_set_users()
    if status_default and status_users:
        return"COMPLIANT"
    else:
        return"NON-COMPLIANT: EXECUTE 'set_inactive_days.py' TO MAKE IT COMPLIANT"
def verify_default_inactive():
    """This is to verify if the inactive password lockout is set to 30 days as default or not"""
    inactive_days = subprocess.check_output("useradd -D | grep INACTIVE", shell=True)
    if inactive_days == "INACTIVE=30\n":
        logging.info("Inactive password lock is set to 30 days")
        return True
    else:
        logging.error("Default inactive password lock is not set to 30 days")
        return False
def verify_set_users():
    """This is to verify if the present users are set with inactive password lock or not"""
    check_value = os.system(r"grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7 \
> /ericsson/security/compliance/verify_inacive_days.txt")
    if check_value != 0:
        logging.error("Unable to fetch user accounts and its inactive password lockout period")
    else:
        logging.info("Fetched user accounts and its inactive password lockout period")
    with open("/ericsson/security/compliance/verify_inacive_days.txt", 'r') as fin:
        data = fin.readlines()
    data1 = []
    expected_value = "30\n"
    for i in data:
        if i != "\n":
            data1 = i.split(':')
            if (data1[0] != "root") and (data1[0] != "storadm"):
                user = data1[0]
                fetched_value = data1[1]
                if fetched_value != expected_value:
                    logging.error("Inactive password lock is not set as 30 days for %s", user)
                    os.system("rm -rf /ericsson/security/compliance/verify_inacive_days.txt")
                    return False
                else:
                    logging.info("Inactive password lock is set to 30 day for user %s", user)
    os.system("rm -rf /ericsson/security/compliance/verify_inacive_days.txt")
    return True
if __name__ == '__main__':
    check_inactive()
