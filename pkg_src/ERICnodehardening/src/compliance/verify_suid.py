#!/usr/bin/python
"""This script verifies if suid privilege has been removed for all the system files or not"""
import os
def root_suid_check():
    """This function verifies if suid privilege has been removed for all the system files or not"""
    files = ["/usr/lib/polkit-1/polkit-agent-helper-1", "/usr/sbin/usernetctl",
             "/usr/sbin/pam_timestamp_check", "/usr/sbin/mount.nfs", "/usr/sbin/userhelper",
             "/usr/sbin/unix_chkpwd", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/crontab",
             "/usr/bin/gpasswd", "/usr/bin/sudo", "/usr/bin/chage", "/usr/bin/pkexec",
             "/usr/bin/su", "/usr/bin/newgrp", "/usr/bin/umount",
             "/usr/libexec/dbus-1/dbus-daemon-launch-helper", "/usr/bin/mount", "/usr/bin/passwd",
             "/usr/bin/staprun"]
    os.system(r'find / \( -path /JUMP -o -path /eniq/data -o -path /net \) -prune -o -perm -4000\
 -type f -print> /ericsson/security/compliance/log.txt 2>/dev/null')
    data1 = open("/ericsson/security/compliance/log.txt", 'r').read().split("\n")
    os.system("rm -rf /ericsson/security/compliance/log.txt")
    arr = []
    for file_name in data1:
        if file_name not in files and file_name:
            print file_name
            arr.append(file_name)
    if arr:
        return "NON-COMPLIANT:  EXECUTE 'disable_access_suid.py' TO MAKE IT COMPLIANT"
    return "COMPLIANT"

if __name__ == '__main__':
    root_suid_check()
