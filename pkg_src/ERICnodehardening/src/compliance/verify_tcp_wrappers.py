#!/usr/bin/python
"""This script verifies if the tcp wrappers has enforced the configuration changes or not"""

import subprocess

def tcp_cmp():
    """This function verifies if vsftpd has been disabled in /etc/hosts.deny or not"""

    cmd = "[ -f /etc/hosts.allow ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd, shell=True)

    if result == 'File exist\n':
        flag1 = 1
    else:
        flag1 = 0

    cmd1 = "[ -f /etc/hosts.deny ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd1, shell=True)

    if result == 'File exist\n':
        flag2 = 1
    else:
        flag2 = 0

    with open('/etc/hosts.deny', 'r') as fin:
        data = fin.read()
    if 'vsftpd: ALL' in data:
        flag3 = 1
    else:
        flag3 = 0

    if flag1 == 1 and flag2 == 1 and flag3 == 1:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'tcp_wrappers.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    tcp_cmp()
