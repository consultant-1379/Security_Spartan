#!/usr/bin/python
""""
# ********************************************************************
# Name      : TC_disable_access_suid.py
# Purpose   : Test case to verify the access to the files with root suid is disabled.
#
# ********************************************************************
"""
import os
import commands as c
import time
import logging

def check_suid():

    allowed = ["/usr/lib/polkit-1/polkit-agent-helper-1", "/usr/sbin/usernetctl",
         "/usr/sbin/pam_timestamp_check", "/usr/sbin/mount.nfs",
         "/usr/sbin/userhelper", "/usr/sbin/unix_chkpwd", "/usr/bin/chsh",
         "/usr/bin/chfn", "/usr/bin/crontab", "/usr/bin/gpasswd",
         "/usr/bin/sudo", "/usr/bin/chage", "/usr/bin/pkexec", "/usr/bin/su",
         "/usr/bin/newgrp", "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
         "/usr/bin/passwd", "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/staprun"
        ]

    allsuid = c.getoutput("find / -perm -4000 2> /dev/null").split('\n')

    for suid in allsuid:
	if suid not in allowed:
	    logging.info("%s not allowed" % suid)
	    print "%s not allowed" % suid
	    return "FAIL"
	    
    for a in allowed:
	if a not in allsuid:
	    logging.info("%s not allowed" %a)
	    print "%s not allowed" %a
	    return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_access_suid.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/disable_access_suid.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/disable_access_suid.py error")
        print "FAIL"
        exit()

    print check_suid()
