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
# Name      : grace_time_audit.py
# Purpose   : This script verifies if login grace time is set or not
# Reason    : EQEV-92525
# Revision  : B
#*********************************************************************
"""
import logging

def grace_cmp():
    """This function verifies if login grace time has been set or not"""
    with open('/etc/ssh/sshd_config', 'r') as fin:
        data = fin.read()
    compliance_status = 1
    if 'LoginGraceTime 1m' in data:
        return "COMPLIANT"
    elif 'LoginGraceTime' in data:
        logging.info('Customized value found!\n')
        compliance_status = 0
    else:
        compliance_status = 0

    if compliance_status == 0:
        return "NON-COMPLIANT:  EXECUTE 'set_grace_time.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    grace_cmp()
