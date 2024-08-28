#!/usr/bin/python
"""This script verifies if the access to 'at' command has been restricted or not"""

import subprocess

def at_restrict_cmp():
    """This script verifies if the access to 'at' command has been restricted or not"""
    cmd = "[ -f /etc/at.allow ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd, shell=True)

    if result == 'File exist\n':
        flag1 = 1
    else:
        flag1 = 0

    cmd1 = "[ -f /etc/at.deny ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd1, shell=True)

    if result == 'File exist\n':
        flag2 = 1
    else:
        flag2 = 0


    if flag1 == 1 and flag2 == 1:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'restrict_at.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    at_restrict_cmp()
