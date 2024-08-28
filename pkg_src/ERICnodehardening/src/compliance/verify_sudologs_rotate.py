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
# *********************************************************************
# Name      : verify_sudologs_rotate.py
# Purpose   : This script verifies sudo logs rotation is configured
#             properly or not.
# Reason    : EQEV-111556
# Authour   : ZBARPHU
# Revision  : A
# *********************************************************************
"""

def verify_sudo_log():

    try:
        with open("/etc/logrotate.d/sudo", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        con = ['/var/log/sudo.log','{','    daily','    compress','    size 20M','    rotate 1',\
'    create','    dateext','    postrotate','        systemctl restart rsyslog',\
'    endscript','}']
        if all(word in data for word in con):
            return "COMPLIANT"
        else:
            return "NON-COMPLIANT:  EXECUTE 'sudologs_rotate.py' TO MAKE IT COMPLIANT"

    except IOError:
        return "NON-COMPLIANT:  EXECUTE 'sudologs_rotate.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    verify_sudo_log()