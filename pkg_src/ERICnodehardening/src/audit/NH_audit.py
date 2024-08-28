#!/usr/bin/python
"""
This script is used to list down all the files and directories for auditing purpose.
"""
# coding: utf-8
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
# Name      : NH_audit.py
# Purpose   : This script is used to list down all the files
#               and directories for auditing purpose.
# ********************************************************************
import os
import subprocess
import logging
from multiprocessing import Process

def multi_thread(cmd, feature):
    """Function to target during multi-threading"""
    logging.info("Generating a list of %s", feature)
    subprocess.call(cmd, shell=True)
    logging.info("Generated a list of %s", feature)

def audit():
    """Function to start audit from NH_Compliance.py"""
    threads, process = list(), ['SGID', 'SUID', 'File_full', 'Dir_full', 'no_owner', '750']
    print '\n'+'*'*20+'Capturing audit logs under /ericsson/security/audit/logs \
directory'+'*'*20+'\n'
    os.system("mkdir -p /ericsson/security/audit/logs")
    threads.append(Process(target=multi_thread, args=(r'find / \( -path /JUMP -o -path\
 /eniq/data -o -path /net \) -prune -o -perm -2000 -type f -print > /ericsson/security/audit/logs\
/SGID.log 2> /dev/null', 'SGID files as SGID.log')))
    print '\nAudit for any SGID files present on the system is completed, refer to the \
/ericsson/security/audit/logs/SGID.log for further details.'
    threads.append(Process(target=multi_thread, args=(r'find / \( -path /JUMP -o -path\
 /eniq/data -o -path /net \) -prune -o -perm -4000 -type f -print > /ericsson/security/audit/logs\
/SUID.log 2> /dev/null', 'SUID files as SUID.log')))
    print '\nAudit for any SUID files present on the system is completed, refer to the \
/ericsson/security/audit/logs/SUID.log for further details.'
    threads.append(Process(target=multi_thread, args=(r'find / \( -path /JUMP -o -path\
 /eniq/data -o -path /net \) -prune -o -perm -0002 -type f -print > /ericsson/security/audit/logs\
/files_full_perm.log 2> /dev/null', 'files which have full permission aas files_full_perm.log')))
    print '\nAudit for any world-writable directories present on the system is completed, refer to \
/ericsson/security/audit/logs/dir_full_perm.log for further details.'
    threads.append(Process(target=multi_thread, args=(r'find / \( -path /JUMP -o -path\
 /eniq/data -o -path /net \) -prune -o -perm -type d -0002 -print  > /ericsson/security/audit/logs\
/dir_full_perm.log 2> /dev/null', 'directories which have full permission as dir_full_perm.log')))
    print '\nAudit for any world-writable files present on the system is completed, refer to \
/ericsson/security/audit/logs/files_full_perm.log for further details.'
    threads.append(Process(target=multi_thread, args=(r'find / \( -path /JUMP -o -path\
 /eniq/data -o -path /net \) -prune -o -type d -nouser > /ericsson/security/audit/logs/files_no\
_owner.log 2> /dev/null', 'files with no owner as files_no_owner.log')))
    print '\nAudit for any files with no owner assigned is completed, refer to \
/ericsson/security/audit/logs/files_no_owner.log for further details.'
    threads.append(Process(target=multi_thread, args=(r'find / \( -path /JUMP -o -path\
 /eniq/data -o -path /net \) -prune -o -type d -perm 750 ! -perm 750 > /ericsson/security/audit/\
logs/check_home_dir_perm.log 2> /dev/null', 'directories which have 750 permission \
as check_home_dir_perm.log')))
    print '\nAudit for insecure home directory for users is completed, refer to \
/ericsson/security/audit/logs/check_home_dir_perm.log for further details.\n'
    print 'Please wait till Audit logs are captured..\r',
    for trd in threads:
        trd.start()
    for trd in threads:
        trd.join(600)
    for trd, name in zip(threads, process):
        if trd.is_alive():
            trd.terminate()
            logging.warning("Terminating the %s permission check, as this process exceeded the \
10 min threshold for the process completion.", name)
    subprocess.call('ls -d */ > /ericsson/security/audit/logs/executable_dir.log 2> \
/dev/null', shell=True)
    logging.info("Audit for listing executable directories is completed, refer to \
/ericsson/security/audit/logs/executable_dir.log for further details.")
    print 'Audit for listing executable directories is completed, refer to \
/ericsson/security/audit/logs/executable_dir.log for further details.'
    subprocess.call('ls -l /etc/passwd > /ericsson/security/audit/logs/root_perm.log; ls -l\
 /etc/shadow >> /ericsson/security/audit/logs/root_perm.log; ls -l /etc/group >>\
 /ericsson/security/audit/logs/root_perm.log 2> /dev/null', shell=True)
    logging.info("Audit for listing the ownership permission for /etc/passwd, /etc/shadow ,\
/etc/group is completed, refer to root_perm.log")
    print '\nAudit for listing the ownership permission for /etc/passwd, /etc/shadow ,/etc/group \
is completed, refer to /ericsson/security/audit/logs/root_perm.log'
    subprocess.call("awk -F: '{print $3}' /etc/passwd | sort |uniq -d >> \
/ericsson/security/audit/logs/duplicate_ids.log", shell=True)
    logging.info("Audit for identifying any Users with duplicate UIDs on the system is completed,\
 refer to /ericsson/security/audit/logs/duplicate_ids.log for further details.")
    print "\nAudit for identifying any Users with duplicate UIDs on the system is completed. \
refer to /ericsson/security/audit/logs/duplicate_ids.log for further details.\n"
    os.system("rm -rf /ericsson/security/audit/*.pyc")
if __name__ == '__main__':
#        audit() # EQEV-65551 #
    print "\n\033[93mWARNING : This Script is not supported to be executed manually, for more\
 details refer to ENIQ Node Hardening SAG...\033[00m\n"
    exit(1)
