#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_audit_config.py
# Purpose   : Test script to test configuration of auditlog rules done by audit_config.py
#
# ********************************************************************
"""

import sys

sys.path.insert(0, '/ericsson/security/audit')
from audit_config import Logaudit

def audit_testing():
    content = open('/ericsson/security/config/audit_input.cfg', 'r').read().replace('100', '-1')
    open('/ericsson/security/config/audit_input.cfg', 'w').write(content)
    status = Logaudit().update_auditd()
    if status != False:
       return "FAIL"
    content = open('/ericsson/security/config/audit_input.cfg', 'r').read().replace('-1', '201')
    open('/ericsson/security/config/audit_input.cfg', 'w').write(content)
    status1 = Logaudit().update_auditd()
    if status1 != False:
       return "FAIL"
    content = open('/ericsson/security/config/audit_input.cfg', 'r').read().replace('201', '100')
    open('/ericsson/security/config/audit_input.cfg', 'w').write(content)
    status2 = Logaudit().update_auditd()
    if status2 != True:
       return "FAIL"

    read_path = "/ericsson/security/audit/config.txt"
    with open(read_path, 'r') as wrt:
       file_read = wrt.readlines()
    with open(Logaudit().write_path, 'r+') as wrt1:
       file_write = wrt1.readlines()
       for i in file_read:
           if i not in file_write:
               return"FAIL"

    return "SUCCESS"
