#!/usr/bin/python
"""
# *********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# *********************************************************************
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
# Name      : stor_pass_change.py
# Purpose   : This program is to change the existiing
#             credentials based on the requirement
# ********************************************************************
"""

import os
import re
import subprocess
import pexpect

class Pchange(object):
    """ To change the password """
    def __init__(self):
        """ Variable initialization """
        self.abs_path = "/ericsson/storage/etc"

    def read_pass(self):
        """ This function is to read the password """
        try:
            subprocess.call('{0}/decrypt.sh {1}/sourcefile.gpg'\
                            .format(self.abs_path, self.abs_path), shell=True)
        except Exception:
            print "problem with the /ericsson/storage/etc/sourcefile"

    def find_pass(self):
        """ This function is to find the password from sourcefile """
        try:
            with open("/ericsson/storage/etc/sourcefile", 'r') as fil:
                for i in fil.readlines():
                    if "SAPASSWD" in i:
                        self.pw = "".join(re.findall(r"'(.*?)'", i, re.DOTALL))
        except Exception:
            print "Storage password is not available"

    def passchange(self, user):
        """ This function to change the password """
        try:
            self.user = user
            process = pexpect.spawn('passwd '+self.user)
            process.expect('.*assword: ')
            process.sendline(self.pw)
            process.expect('.*assword: ')
            process.sendline(self.pw)
            #process.expect('.+#.+')
            process.sendline('exit')
            process.close()
        except Exception:
            print "Could not perform the storage password change"

    def remove_file(self):
        """ This function remove the file """
        try:
            file_path = self.abs_path+"/sourcefile"
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            print "could not remove file {0} , remove manually".format(file_path)

    @classmethod
    def storage(cls):
        """This function calls other functions to reset the storage user password"""
        obj = Pchange()
        obj.read_pass()
        obj.find_pass()
        users_list = ['storadm']
        for user in users_list:
            obj.passchange(user)
        obj.remove_file()

if __name__ == "__main__":
    print "\n\033[93mWARNING : \033[00m This Script is not supported to be "\
          "executed manually, for more details refer to ENIQ Node Hardening SAG...\n"
