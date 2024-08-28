#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : disable_access_suid.py
# Purpose   :This disables the access to files with root suid.
# ********************************************************************
"""
import subprocess
import os
import time
import logging
import shutil
from Verify_NH_Config import configure_nh
from user_verification import user_verification
file_name = "/ericsson/security/log/Apply_NH_Logs/suid_list"

def root_uid():
    """This function disables the access to files with root suid."""
    avoid = ["/usr/lib/polkit-1/polkit-agent-helper-1", "/usr/sbin/usernetctl",
             "/usr/sbin/pam_timestamp_check", "/usr/sbin/mount.nfs",
             "/usr/sbin/userhelper", "/usr/sbin/unix_chkpwd", "/usr/bin/chsh",
             "/usr/bin/chfn", "/usr/bin/crontab", "/usr/bin/gpasswd",
             "/usr/bin/sudo", "/usr/bin/chage", "/usr/bin/pkexec", "/usr/bin/su",
             "/usr/bin/newgrp", "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
             "/usr/bin/passwd", "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/staprun"
            ]
    os.system("sh /ericsson/security/bin/spinner_suid.sh &")
    if not os.path.exists("/ericsson/security/bin/checkfile"):
        os.mknod("/ericsson/security/bin/checkfile")
    os.system(r'find / \( -path /JUMP -o -path /eniq/data -o -path /net \) -prune -o -perm -4000\
 -type f -print> /ericsson/security/bin/log.txt 2>/dev/null')
    data1 = open("/ericsson/security/bin/log.txt", 'r').read().split("\n")
    os.system("rm -rf /ericsson/security/bin/log.txt /ericsson/security/bin/checkfile")
    suid_removed, check = list(), False
    for file_name in data1:
        if file_name and file_name not in avoid:
            cmd1 = "chmod u-s %s 2>/dev/null"%(file_name)
            status = subprocess.call(cmd1, shell=True)
            if status:
                logging.warning('SUID permission removal for the file %s , \
was unsuccessful.', file_name)
                check = True
            else:
                logging.info('SUID has been removed for the file %s', file_name)
                print 'SUID has been removed for the file {} '.format(file_name)
                suid_removed.append(file_name)
    if check:
        print "SUID permission removal was unsuccessful for certain files , refer to the \
log file for further information on the files."
    if suid_removed:
        open(file_name, "w").write('\n'.join(suid_removed))
        open(file_name, "a").write('\n')
        print "\nSUID permission changed filenames are listed in  \033[93m/ericsson/security/log/\
Apply_NH_Logs/suid_list\033[00m file"
        logging.info('Files whose SUID permission has been removed are listed in the \
/ericsson/security/log/Apply_NH_Logs/suid_list file')
    else:
        print "\n**********None of the files have SUID as root**********\n"
        logging.info('None of the files have SUID as root')
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    if os.path.exists(file_name):
        dest = "/ericsson/security/log/Apply_NH_Logs/suid_list_bkp" + str(timestamp)
        shutil.copyfile('/ericsson/security/log/Apply_NH_Logs/suid_list', dest)

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_access_suid.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        root_uid()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
        os.system("rm -rf /ericsson/security/bin/checkfile")
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!\n\n"
