#!/usr/bin/python
"""This script verifies if logrotate has been configured or not"""
import subprocess

def cron_log_cmp():
    """This function verifies if logrotate has been configured or not"""
    cmd = "[ -f /etc/logrotate.d/cron ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd, shell=True)

    if result == 'File exist\n':
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'set_cron_log.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    cron_log_cmp()
