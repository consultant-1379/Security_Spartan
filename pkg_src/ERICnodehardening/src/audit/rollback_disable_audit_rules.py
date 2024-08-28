#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2021 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : rollback_disable_audit_rules.py
# Purpose   : This script will rollback the disabled rules to default state
#             present in /var/log/audit
# Reason    : EQEV-102069
# Revision  : A
# ********************************************************************
"""
from __future__ import print_function
import os
import sys
import shutil
import logging
import  time
sys.path.insert(0, '/ericsson/security/bin')
from user_verification import user_verification

def remove_user_added_files(rem):
    '''Remove customized rules files from /etc/audit/rules.d/ dir'''
    try:
        for _, cis_file in enumerate(rem):
            os.system('rm -rf %s' %cis_file +' > /dev/null 2>&1')
            logging.info("INFO: Removing customized rules in file %s", cis_file)
    except OSError:
        logging.info("One or more customized audit files are not found!!")

def check_user_added_files(rem):
    '''Check all the ciscat rules files exist return True else False'''
    for _, cis_file in enumerate(rem):
        file_exists = os.path.exists(cis_file)
        if file_exists is False:
            return False
    return True
def enable_rule_default():
    '''This function will rollback the rules to default configuration'''
    try:
        rem = ['/etc/audit/rules.d/50-MAC_policy.rules', '/etc/audit/rules.d/50-system_local.rules',
               '/etc/audit/rules.d/50-time_change.rules', '/etc/audit/rules.d/50-perm_mod.rules',
               '/etc/audit/rules.d/50-mounts.rules', '/etc/audit/rules.d/50-access.rules',
               '/etc/audit/rules.d/50-deletion.rules', '/etc/audit/rules.d/50-actions.rules',
               '/etc/audit/rules.d/50-modules.rules', '/etc/audit/rules.d/50-privileged.rules',
               '/etc/audit/rules.d/50-identity.rules', '/etc/audit/rules.d/50-scope.rules',
               '/etc/audit/rules.d/50-session.rules', '/etc/audit/rules.d/50-logins.rules']
        print("************ Rollback is started *****************")
        logging.info("************ Rollback is started *****************")
        logging.info("Rules setting the configurated started from default to config.txt")
        if os.path.exists("/ericsson/security/audit/default_config.txt")is True and \
check_user_added_files(rem) is True:
            shutil.copy("/ericsson/security/audit/default_config.txt", "/ericsson/security/audit/\
config.txt")
            os.system('rm -rf /ericsson/security/audit/customize_flag_status.txt')
            remove_user_added_files(rem)
            logging.info('Started the execution of /ericsson/security/bin/\
ensure_user_group_info.py')
            os.system("python /ericsson/security/bin/ensure_user_group_info.py")
            logging.info('Finished the execution of /ericsson/security/bin/\
ensure_user_group_info.py')
            logging.info('Started the execution of /ericsson/security/bin/\
ensure_sys_admin_scope.py')
            os.system("python /ericsson/security/bin/ensure_sys_admin_scope.py")
            logging.info('Finished the execution of /ericsson/security/bin/\
ensure_sys_admin_scope.py')
            logging.info('Started the execution of /ericsson/security/bin/enforce_system_mount.py')
            os.system("python /ericsson/security/bin/enforce_system_mount.py")
            logging.info('Finished the execution of /ericsson/security/bin/enforce_system_mount.py')
            logging.info('Started the execution of /ericsson/security/bin/ensure_file_auth.py')
            os.system("python /ericsson/security/bin/ensure_file_auth.py")
            logging.info('Finished the execution of /ericsson/security/bin/ensure_file_auth.py')
            logging.info('Started the execution of /ericsson/security/bin/\
discretionary_access_control.py')
            os.system("python /ericsson/security/bin/discretionary_access_control.py")
            logging.info('Finished the execution /ericsson/security/bin/\
discretionary_access_control.py')
            logging.info('Started the execution of /ericsson/security/bin/ensure_sys_admin_cmd.py')
            os.system("python /ericsson/security/bin/ensure_sys_admin_cmd.py")
            logging.info('Finished the execution of /ericsson/security/bin/ensure_sys_admin_cmd.py')
            logging.info('Started the execution of /ericsson/security/bin/ensure_system_access.py')
            os.system("python /ericsson/security/bin/ensure_system_access.py")
            logging.info('Finished the execution of /ericsson/security/bin/ensure_system_access.py')
            logging.info('Started the execution of /ericsson/security/bin/ensure_date_time_info.py')
            os.system("python /ericsson/security/bin/ensure_date_time_info.py")
            logging.info('Finished the execution of /ericsson/security/bin/\
ensure_date_time_info.py')
            logging.info('Started the execution of /ericsson/security/bin/\
ensure_system_network.py')
            os.system("python /ericsson/security/bin/ensure_system_network.py")
            logging.info('Finished the execution of /ericsson/security/bin/\
ensure_system_network.py')
            logging.info('Started the execution of /ericsson/security/bin/ensure_file_deletion.py')
            os.system("python /ericsson/security/bin/ensure_file_deletion.py")
            logging.info('Finished the execution of /ericsson/security/bin/ensure_file_deletion.py')
            logging.info('Started the execution of /ericsson/security/bin/ensure_kernel_module.py')
            os.system("python /ericsson/security/bin/ensure_kernel_module.py")
            logging.info('Finished the execution of /ericsson/security/bin/ensure_kernel_module.py')
            logging.info('Started the execution of /ericsson/security/bin/\
ensure_login_logout_events.py')
            os.system('python /ericsson/security/bin/ensure_login_logout_events.py')
            logging.info('Finished the execution of /ericsson/security/bin/\
ensure_login_logout_events.py')
            logging.info('Started the execution of /ericsson/security/bin/\
ensure_session_info.py')
            os.system('python /ericsson/security/bin/ensure_session_info.py')
            logging.info('Finished the execution of /ericsson/security/bin/\
ensure_session_info.py')
            logging.info('Started the execution of /ericsson/security/bin/\
ensure_user_priviliged_cmd.py')
            os.system("python /ericsson/security/bin/ensure_user_priviliged_cmd.py")
            logging.info('Finished the execution of /ericsson/security/bin/\
ensure_user_priviliged_cmd.py')
            logging.info("********Successfully Rolled back CIS-CAT recommended audit rules********")
            os.system("python /ericsson/security/audit/audit_config.py")
            logging.info("************ Rollback done succesfully ************")
            print("************ Rollback done succesfully ************")
            logging.warning('The server will reboot now')
            os.system("sleep 3s")
            os.system('reboot')
        else:
            print("No Default backup is found, hence can't rollback")
            logging.info("No Default backup is found, hence can't rollback")
    except (IOError, OSError):
        logging.info("File not exist")

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FILE_NAME = TIMESTR + '_rollback_disable_rules.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FILE_NAME,
                        format=FORMAT_STRING)
    enable_rule_default()