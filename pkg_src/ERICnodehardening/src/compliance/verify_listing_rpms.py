#!/usr/bin/python
"""This script verifies if /ericsson/security/bin/list_rpms.py script \
lists and logs all the rpms installed in the server or not"""

import os
from os import path
import subprocess
import sys
sys.path.insert(0, '/ericsson/security/bin')
from list_rpms import check_rpms

class NullWriter(object):
    """This class is a null writer class that would hide the stdout"""
    def write(self, arg):
        """This method points to the stdout"""
        pass

def check_listing_rpms():
    """This function verifies if /ericsson/security/bin/list_rpms.py \
script lists and logs all the rpms installed in the server or not"""
    with open('/ericsson/security/compliance/log.txt', 'a'):
        nullwrite = NullWriter()
        oldstdout = sys.stdout
        sys.stdout = nullwrite
        check_rpms()
        sys.stdout = oldstdout
    file_name = subprocess.check_output("tail -2 /ericsson/security/compliance/log.txt | \
cut -d'/' -f 6 | cut -d' ' -f 1", shell=True)
    file_name = file_name.replace('\n', '')
    os.system("rm -rf /ericsson/security/compliance/log.txt")
    if path.exists("/ericsson/security/log/rpm_logs/%s" % file_name):
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'list_rpms.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_listing_rpms()
