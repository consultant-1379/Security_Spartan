#!/usr/bin/python
"""
# ********************************************************************
# Name       : NTC_enable_sticky_bit.py
# Purpose    : Test Case to verify sticky bit is enabled and no user can modify /etc.
# ********************************************************************
"""
import os
import subprocess
import commands as c
from TC_enable_sticky_bit import sticky

def change_sticky():
    if os.path.exists('/etc/') == False :
	    print "/etc not exists"
	    logging.info("%s not exists" % file)
	    return "FAIL"

    cmd = "ls -ld /etc | head -n 1 | cut -d'.' -f1"
    check = c.getoutput(cmd)[-1].lower()
    if check != 't':
 	  print "/etc has no sticky bit"
	  logging.info("/etc has no sticky bit")
	  return "FAIL"
	
    os.system("chmod -t /etc > /dev/null 2>&1")
    sticky()
    os.system("chmod +t /etc > /dev/null 2>&1")
    os.system("useradd test101  >/dev/null 2>&1")
    s=os.system("runuser -l test101 -c 'touch cd /etc/test'  >/dev/null 2>&1")
    if s==256:
      print "unable to create file: Permission denied"
    os.system("userdel -r test101  >/dev/null 2>&1")
    return "SUCCESS"

if __name__ == '__main__':

    print change_sticky()
