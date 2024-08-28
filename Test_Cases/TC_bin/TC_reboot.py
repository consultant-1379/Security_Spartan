#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_reboot.py
# Purpose   : Test script to check server is getting rebooted by reboot.py
# ********************************************************************
"""

import os

def boot():

    status = os.system("/ericsson/security/bin/reboot.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        exit()

    print "SUCCESS"

if __name__ == '__main__':
        boot()
