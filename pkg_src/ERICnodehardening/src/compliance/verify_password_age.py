#!/usr/bin/python
"""This script verifies if the password age for all users except \
root, storadm, storobs and dcuser has been set to 60 or not"""
import subprocess


def check_password_aging():
    """This function verifies if the password age for all users \
except root, storadm, storobs and dcuser has been set to 60 or not"""
    count = 0

    with open("/etc/passwd", "r") as fin:
        data = fin.readlines()

    for i in data:
        if i != '\n':
            data1 = i.split(":")
            if (data1[0] != "dcuser") and (data1[0] != "root") and (data1[0] != "storadm") and \
(data1[0] != "storobs") and (int(data1[2]) > 999):
                age = subprocess.check_output("chage -l %s | sed '6!d' | \
cut -d':' -f 2" % data1[0], shell=True)
                age = age.replace('\n', '')
                if age != ' 60':
                    count = count + 1
    if count == 0:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'set_password_aging.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_password_aging()
