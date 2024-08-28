#!/usr/bin/python

"""This script verifies if history logging has beend enbled or not"""

def hist_cmp():
    """This function verifies if history logging has beend enbled or not"""
    with open('/etc/profile', 'r') as fin:
        data = fin.read()
    if 'export PATH\nfunction HistSyslog { echo -n \"USER $USER : PWD $PWD : CMD = $BASH_COMMAND : \
FROM $SSH_CONNECTION\" :Term  `tty`:  | grep -v -e \"echo -ne \"| logger -p local6.notice -i ; }\
\ntrap HistSyslog DEBUG' in data:
        flag1 = 1
    else:
        flag1 = 0
    if '\nexport HISTTIMEFORMAT=\"%d/%m/%y %T \"' in data:
        flag2 = 1
    else:
        flag2 = 0

    with open('/etc/rsyslog.conf', 'r') as fin:
        data1 = fin.read()
    if 'local6.notice                                                /var/log/cmdlog\n*.info;mail.none;authpriv.none;\
cron.none;local6.!notice                /var/log/messages' in data1:
        flag3 = 1
    else:
        flag3 = 0

    if flag1 == 1 and flag2 == 1 and flag3 == 1:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'set_history_logging.py' TO MAKE IT COMPLIANT"

if  __name__ == '__main__':
    hist_cmp()
