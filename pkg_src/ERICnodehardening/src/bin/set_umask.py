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
# Name      : set_umask.py
# Purpose   : This script sets the umask to 027 for all the users
#               except the system users.
#
# ********************************************************************
"""
import os
import time
import logging
import subprocess
from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
def umask_all():
    """This function is to sets the umask value"""
    backup_files('/etc/profile', [])
    with open("/etc/profile", 'r') as fin:
        data = fin.readlines()
        umask_022 = '    umask 022\n'
        a = 0
        for i in data:
            if i == umask_022:
                a = data.index(i)
        if data[a+2] == 'if [ $UID -gt 999 ] && [ "`/usr/bin/id -gn`" = "`/usr/bin/id -un`" ]; then\n' \
and data[a+3] == umask_022 and data[a+4] == 'elif [ $UID -gt 199 -a $UID -le 999 ] && \
[ "`/usr/bin/id -gn`" != "`/usr/bin/id -un`" ]; then\n' and data[a+5] == umask_022 and \
data[a+6] == 'elif [ $UID -gt 999 ] && [ "`/usr/bin/id -gn`" != "`/usr/bin/id -un`" ]; then\n' and \
data[a+7] == '    umask 027\n' and data[a+8] == 'fi\n':
            indices=[a+2,a+3,a+4,a+5,a+6,a+7,a+8]
            for i in sorted(indices, reverse=True):
                del data[i]
    with open("/etc/profile", 'w') as fout:
        fout.writelines(''.join(data))
    with open("/etc/profile", 'r') as fin:
        data2 = fin.readlines()
        default_config_line = "if [ $UID -gt 199 ]"
        b = 0
        for i in data2:
            if default_config_line in i:
                b = data2.index(i)
                data2[b] = '''if [ $UID -gt 199 ] && [ "`/usr/bin/id -gn`" = "`/usr/bin/id -un`" ]; then\n'''
                data2[b+1]='    umask 027\n'
                data2[b+3]='    umask 022\n'

    with open("/etc/profile", 'w') as fout:
        fout.writelines(''.join(data2))
    print "\n**********Successfully enforced secure umask configuration for the OS users\
**********\n"
    logging.info('Successfully configured umask for OS users')
if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_umask.log'
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
        umask_all()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
