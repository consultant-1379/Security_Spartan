#!/usr/bin/python
"""This script verifies if the access to 'cron' command has been restricted or not"""
import subprocess

def cron_restrict_cmp():
    """This script verifies if the access to 'at' command has been restricted or not"""
    cmd = "[ -f /etc/cron.allow ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd, shell=True)

    if result == 'File exist\n':
        flag1 = 1
    else:
        flag1 = 0

#    cmd1 = "[ -f /etc/cron.deny ] && echo 'File exist' || echo 'File does not exist' "
#    result = subprocess.check_output(cmd1, shell=True)
#    if result == 'File exist\n':  # cron.deny is removed in set_file_permissons.py
#        flag2 = 1
#    else:
#        flag2 = 0
    result1 = subprocess.check_output('find /etc/ -empty', shell=True)

    if 'cron.allow' in result1:
        flag2 = 0
    else:
        flag2 = 1

    if flag1 == 1 and flag2 == 1:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'restrict_cron.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    cron_restrict_cmp()
