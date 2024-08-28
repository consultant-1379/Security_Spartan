#!/usr/bin/python
""""This script verifies if sticky bit has been set for the system files or not"""

import subprocess


def check_sticky_bit():
    """This function verifies if sticky bit has been set for the system files or not"""
    status = subprocess.check_output("ls -l / | grep -i etc | awk '{print $1'} | \
cut -d'-' -f 3 | cut -d'.' -f 1", shell=True)

    if status == 't\n':
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT: EXECUTE 'enable_sticky_bit.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_sticky_bit()
