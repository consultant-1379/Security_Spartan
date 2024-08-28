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
# Name      : set_history_logging.py
# Purpose   : This script enables history logging.
# ********************************************************************
"""

import os
import time
import logging
import subprocess

from Verify_NH_Config import configure_nh
from user_verification import user_verification

def history_logs():
    """This function enables history logging"""
    with open('/etc/profile', 'r') as fin:
        data = fin.read()
    if 'export PATH\nfunction HistSyslog { echo -n \"USER $USER : PWD $PWD : \
CMD = $BASH_COMMAND : FROM $SSH_CONNECTION\" :Term  `tty`:  | grep -v -e \"echo -ne \"| \
logger -p local6.notice -i ; }\ntrap HistSyslog DEBUG' not in data:
        data = data + 'export PATH\nfunction HistSyslog { echo -n "USER $USER : PWD $PWD : CMD = \
$BASH_COMMAND : FROM $SSH_CONNECTION" :Term  `tty`:  | grep -v -e "echo -ne "| \
logger -p local6.notice -i ; }\ntrap HistSyslog DEBUG'

    if '\nexport HISTTIMEFORMAT=\"%d/%m/%y %T \"' not in data:
        data = data+'\nexport HISTTIMEFORMAT=\"%d/%m/%y %T \"'

    with open('/etc/profile', 'w') as fout:
        fout.write(data)

    with open('/etc/rsyslog.conf', 'r') as fin:
        data1 = fin.read()
    if 'local6.notice                                                /var/log/cmdlog\n*.info;\
mail.none;authpriv.none;cron.none;local6.!notice                /var/log/messages' not in data1:
        data1 = data1+ 'local6.notice                                                /var/log/\
cmdlog\n*.info;mail.none;authpriv.none;cron.none;local6.!notice                /var/log/messages'

    with open('/etc/rsyslog.conf', 'w') as fout:
        fout.write(data1)

    subprocess.call('systemctl restart rsyslog', shell=True)
    print "\n**********History timestamp has been successfully enabled!**********\n"
    logging.info('History timestamp has been successfully enabled')

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_history_logging.log'
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
        history_logs()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
