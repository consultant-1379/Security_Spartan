#!/usr/bin/python
"""This script verifies if /ericsson/security/bin/capture_performance.py script \
captures and logs the system performance or not"""

import os
from os import path
import subprocess

import sys
sys.path.insert(0, '/ericsson/security/bin')
from capture_performance import performance

class NullWriter(object):
    """This class is a null writer class that would hide the stdout"""
    def write(self, arg):
        """This method points to the stdout"""
        pass

def check_performance_logs():
    """This script verifies if /ericsson/security/bin/capture_performance.py script \
captures and logs the system performance or not"""

    with open('/ericsson/security/compliance/log.txt', 'a'):
        nullwrite = NullWriter()
        oldstdout = sys.stdout
        sys.stdout = nullwrite
        performance()
        sys.stdout = oldstdout

    file_name = subprocess.check_output("cat /ericsson/security/compliance/log.txt | sed '5!d' \
| cut -d'/' -f 6 | cut -d' ' -f 1", shell=True)
    file_name = file_name.replace('\n', '')
    os.system("rm -rf /ericsson/security/compliance/log.txt")

    if path.exists("/ericsson/security/log/performance_logs/%s" % file_name):
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'capture_performance.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_performance_logs()
