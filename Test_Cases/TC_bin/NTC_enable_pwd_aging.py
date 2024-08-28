#!/usr/bin/python
"""
# *********************************************************************
# Name      : NTC_enable_pwd_aging.py
# Purpose   : Test script to check that recommended values are set for password aging.
#
# *********************************************************************
"""
import os
from TC_enable_pwd_aging import password_age

def set_passwd_aging():
    check_mount_point = os.path.ismount("/JUMP")
    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")

    if mws_insttype_path is True:
      chage_output_root = os.system("chage -M 26 -W 18 root > /dev/null 2>&1")
      r=password_age()
      os.system("chage -M 99999 -W 7 root > /dev/null 2>&1")

    if eniq_insttype_path is True:
       os.system("chage -M 70 -W 18 root > /dev/null 2>&1")
       os.system("chage -M 26 -W 18 dcuser > /dev/null 2>&1")
       r=password_age()
       os.system("chage -M 99999 -W 7 root > /dev/null 2>&1")
       os.system("chage -M 99999 -W 7 dcuser > /dev/null 2>&1")

    if r=="FAIL":
          return "SUCCESS"
    else:
          return "FAIL"


if __name__ == '__main__':
    print set_passwd_aging()
