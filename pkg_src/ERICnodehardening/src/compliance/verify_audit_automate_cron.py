#!/usr/bin/python
"""
#*********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
#*********************************************************************
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
# Name      : verify_automate_cron.py
# Purpose   : This script verifies wheather audit log rotation cron
#             job is confiured or not
# Reason    : EQEV-100494
# ********************************************************************
"""
import subprocess

def verify_audit_automate_cron():
    '''This fuction verify whether corn job is configured or not'''
    try:
        cron_test = subprocess.check_output("crontab -l", shell=True).split('\n')
        cron_match = "45 23 * * * /usr/bin/python2.7 /ericsson/security/audit/auditlog_rotate.py \
>> /dev/null 2>&1"
        if cron_match in cron_test:
            string = "COMPLIANT"
        else:
            string = "NON-COMPLIANT: EXECUTE 'audit_automate_cron.py' \
    TO MAKE IT COMPLIANT"
        return string
    except (IOError, RuntimeError, AttributeError, TypeError, subprocess.CalledProcessError):
        print "Cron job not configured on the server"

if __name__ == '__main__':
    verify_audit_automate_cron()