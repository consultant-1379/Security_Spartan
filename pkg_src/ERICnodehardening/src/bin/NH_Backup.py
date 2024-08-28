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
# Name      : NH_Backup.py
# Purpose   : This script creates backup of configuration files that
#             gets edited while applying node hardening.
# ********************************************************************
"""

import os
import subprocess

def backup_files(file, file_list):
    """This script creates backup of configuration file"""
    if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES") is False:
        os.system("mkdir -p /ericsson/security/BACKUP_CONFIG_FILES")
    if file != 0:
        check = subprocess.check_output("ls /ericsson/security/BACKUP_CONFIG_FILES", \
shell=True).split()
        file0 = file.replace('/', '0')
        if file0 not in check and os.path.exists(file):
            os.system("cp -p "+file+" /ericsson/security/BACKUP_CONFIG_FILES/"+file0)
            os.system("rm -rf /ericsson/security/bin/*.pyc")
    if file_list != []:
        for files in file_list:
            backup_files(files, [])
    os.system("rm -rf /ericsson/security/bin/*.pyc")
