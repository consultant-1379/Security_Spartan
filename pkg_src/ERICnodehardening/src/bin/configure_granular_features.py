#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2023 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : configure_granular_features.py
# Purpose   : This script provides options to the user to choose and
#             enforce required category
# Author    : ZAKHBAT
# Reason    : EQEV-113847, EQEV-129908
# ********************************************************************
"""

import time
import os
import logging
import subprocess
import sys

from sentinel_hardening import log_func
from Verify_NH_Config import configure_nh
from user_verification import user_verification
from set_password_aging import pass_age
from set_password_policy import change_hashing_algo
from set_inactive_days import set_inactive
from set_umask import umask_all
from restrict_cron import cron
from restrict_at import at
from tcp_wrappers import tcp_wrap
from set_autologout import auto_logout
from set_grace_time import ssh_login
from enable_sticky_bit import sticky_bit
from disable_access_suid import root_uid
from set_file_permissions import set_permission
from su_restriction import restrict_su_command
from disable_root_switch import sudo_switch
from set_path_integrity import verify_path
from configure_sshd import agent_fwdng
from enable_ssh_login import ssh_user
from disable_X11Forwarding import x11_forwarding
from disable_AllowTcpForwarding import allow_tcp_forwarding
from disable_GatewayPorts import disable_gatewayports
from enable_sshHostKey_verification import enable_ssh_hostkey
from enable_ssh_proto_v2 import ssh_protocol
from add_cipher import add_cipher
from set_ssh_banner import ssh_ban
from set_motd_banner import motd
from set_maxauthtries import set_maxauth
from add_keyexchng_algorithm import add_kex
from enforce_ssh_timeout import ssh_timeout
from set_maxstartups import set_maxstart
from enable_ignoreRhosts import enable_ignorerhosts
from disable_ssh_emptypasswords import disable_ssh_emptypasswords
from disable_ssh_userenvironment import disable_ssh_userenvironment
from disable_hostbasedAuthentication import disable_hostbased_authentication
from reverse_fwd import reverse_fwd
from verify_static_ip_config import ip_config
from disable_Ipv6_autoconf import disable_ipv6_autoconf
from disable_SR import disable_source
from configure_icmp import icmp_configure
from disable_icmp_broadcast import icmp_broadcast
from disable_secure_icmp import disable_secure
from enable_suspicious_packets import enable_packets
from disable_icmp_responses import icmp_responses
from enable_reverse_path_filter import enable_rev_path_filter
from enable_tcp_syncookies import enable_tcp_syncookies
from disable_ipv6_advertisements import disable_ipv6_adv
from set_cron_log import cron_log
from enforce_selinux import check_se_status
from enable_firewall import firewall
from list_rpms import check_rpms
from list_inactive_users import user_login
from nh_summary import generate_report
from sentinel_hardening import get_netan_ip
from sentinel_hardening import netan_whitelisting
from mask_alt_ctrl_del import ctrl_del
from ensure_date_time_info import customized_date_time_info
from ensure_user_group_info import customized_user_group_info
from ensure_system_network import customized_system_network
from ensure_system_access import customized_system_access
from ensure_kernel_module import customized_kernel_module
from discretionary_access_control import customized_disec_access
from ensure_file_auth import customized_file_auth
from ensure_user_priviliged_cmd import customized_user_priviliged_cmd
from enforce_system_mount import customized_system_mount
from ensure_file_deletion import customized_file_deletion
from ensure_sys_admin_scope import customized_sys_admin_scope
from ensure_auditconf_immutable import immutable_auditconf
from ensure_sys_admin_cmd import customized_sys_admin_cmd
from ensure_login_logout_events import customized_login_logout
from ensure_session_info import customized_session_info
from reboot import reboot
sys.path.insert(0, '/ericsson/security/audit')
from audit_config import Logaudit

def configure_granular_features(option):
    '''This function will enforce the category of features of selected by user'''

    if option=='1':
        print "\n**********Started the Enforcing of User Restrictions Features**********\n"
        logging.info("**********Started the Enforcing of User Restrictions Features**********")

        logging.info('Started the execution of /ericsson/security/bin/set_password_aging.py')
        pass_age()
        logging.info('Finished the execution of /ericsson/security/bin/set_password_aging.py')
        logging.info('Started the execution of /ericsson/security/bin/set_inactive_days.py')
        set_inactive()
        logging.info('Finished the execution of /ericsson/security/bin/set_inactive_days.py')
        logging.info('Started the execution of /ericsson/security/bin/set_umask.py')
        umask_all()
        logging.info('Finished the execution of /ericsson/security/bin/set_umask.py')
        logging.info('Started the execution of /ericsson/security/bin/restrict_cron.py')
        cron()
        logging.info('Finished the execution of /ericsson/security/bin/restrict_cron.py')
        logging.info('Started the execution of /ericsson/security/bin/restrict_at.py')
        at()
        logging.info('Finished the execution of /ericsson/security/bin/restrict_at.py')
        logging.info('Started the execution of /ericsson/security/bin/tcp_wrappers.py')
        tcp_wrap()
        logging.info('Finished the execution of /ericsson/security/bin/tcp_wrappers.py')

        print "\n\x1b[32m**********Successfully Enforced User Restrictions Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced User Restrictions Features**********")

    elif option=='2':
        print "\n**********Started the Enforcing of User Session Management Features**********\n"
        logging.info("**********Started the Enforcing of User Session Management Features**********")

        logging.info('Started the execution of /ericsson/security/bin/set_autologout.py')
        auto_logout()
        logging.info('Finished the execution of /ericsson/security/bin/set_autologout.py')
        logging.info('Started the execution of /ericsson/security/bin/set_grace_time.py')
        ssh_login()
        logging.info('Finished the execution of /ericsson/security/bin/set_grace_time.py')

        print "\n\x1b[32m**********Successfully Enforced User Session Management Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced User Session Management Features**********")

    elif option=='3':
        print "\n**********Started the Enforcing of Secure File Configuration and Restrictions\
 Features**********\n"
        logging.info("**********Started the Enforcing of Secure File Configuration and Restrictions\
 Features**********")

        logging.info('Started the execution of /ericsson/security/bin/enable_sticky_bit.py')
        sticky_bit()
        logging.info('Finished the execution of /ericsson/security/bin/enable_sticky_bit.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_access_suid.py')
        root_uid()
        logging.info('Finished the execution of /ericsson/security/bin/disable_access_suid.py')
        logging.info('Started the execution of /ericsson/security/bin/set_file_permissions.py')
        set_permission()
        logging.info('Finished the execution of /ericsson/security/bin/set_file_permissions.py')
        logging.info('Started the execution of /ericsson/security/bin/su_restriction.py')
        restrict_su_command()
        logging.info('Finished the execution of /ericsson/security/bin/su_restriction.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_root_switch.py')
        sudo_switch()
        logging.info('Finished the execution of /ericsson/security/bin/disable_root_switch.py')
        logging.info('Started the execution of /ericsson/security/bin/set_path_integrity.py')
        verify_path()
        logging.info('Finished the execution of /ericsson/security/bin/set_path_integrity.py')

        print "\n\x1b[32m**********Successfully Enforced Secure File Configuration and Restrictions\
 Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced Secure File Configuration and Restrictions\
 Features**********")

    elif option=='4':
        print "\n**********Started the Enforcing of Secure SSH Configuration Features**********\n"
        logging.info("**********Started the Enforcing of Secure SSH Configuration Features**********")

        logging.info('Started the execution of /ericsson/security/bin/configure_sshd.py')
        agent_fwdng()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/configure_sshd.py')
        logging.info('Started the execution of /ericsson/security/bin/enable_ssh_login.py')
        ssh_user(0)
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/enable_ssh_login.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_x11_forwarding.py')
        x11_forwarding()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/disable_X11Forwarding.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_AllowTcpForwarding.py')
        allow_tcp_forwarding()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/disable_AllowTcpForwarding.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_GatewayPorts.py')
        disable_gatewayports()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/disable_GatewayPorts.py')
        logging.info('Started the execution of /ericsson/security/bin/enable_sshHostKey_verification.py')
        enable_ssh_hostkey()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/enable_sshHostKey_verification.py')
        logging.info('Started the execution of /ericsson/security/bin/enable_ssh_proto_v2.py')
        ssh_protocol()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/enable_ssh_proto_v2.py')
        logging.info('Started the execution of /ericsson/security/bin/add_cipher.py')
        add_cipher()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/add_cipher.py')
        logging.info('Started the execution of /ericsson/security/bin/set_ssh_banner.py')
        ssh_ban()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/set_ssh_banner.py')
        logging.info('Started the execution of /ericsson/security/bin/set_motd_banner.py')
        motd()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/set_motd_banner.py')
        logging.info('Started the execution of /ericsson/security/bin/set_maxauthtries.py')
        set_maxauth()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/set_maxauthtries.py')
        logging.info('Started execution of /ericsson/security/bin/add_keyexchng_algorithm.py')
        add_kex()
        os.system("sleep 3s")
        logging.info('Finished execution of /ericsson/security/bin/add_keyexchng_algorithm.py')
        logging.info('Started the execution of /ericsson/security/bin/enforce_ssh_timeout.py')
        ssh_timeout()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/enforce_ssh_timeout.py')
        logging.info('Started the execution of /ericsson/security/bin/set_maxstartups.py')
        set_maxstart()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/set_maxstartups.py')
        logging.info('Started the execution of /ericsson/security/bin/enable_ignoreRhosts.py')
        enable_ignorerhosts()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/enable_ignoreRhosts.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_ssh_emptypasswords.py')
        disable_ssh_emptypasswords()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/disable_ssh_emptypasswords.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_ssh_userenvironment.py')
        disable_ssh_userenvironment()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/disable_ssh_userenvironment.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_hostbasedAuthentication.py')
        disable_hostbased_authentication()
        os.system("sleep 3s")
        logging.info('Finished the execution of /ericsson/security/bin/disable_hostbasedAuthentication.py')

        print "\n\x1b[32m**********Successfully Enforced Secure SSH Configuration Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced Secure SSH Configuration Features**********")

    elif option=='5':
        print "\n**********Started the Enforcing of Hardening Network Configuration and Parameters\
 Features**********\n"
        logging.info("**********Started the Enforcing of Hardening Network Configuration and Parameters \
Features**********")

        logging.info('Started the execution of /ericsson/security/bin/reverse_fwd.py')
        reverse_fwd()
        logging.info('Finished the execution of /ericsson/security/bin/reverse_fwd.py')
        logging.info('Started the execution of /ericsson/security/bin/verify_static_ip_config.py')
        ip_config()
        logging.info('Finished the execution of /ericsson/security/bin/verify_static_ip_config.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_Ipv6_autoconf.py')
        disable_ipv6_autoconf()
        logging.info('Finished the execution of /ericsson/security/bin/disable_Ipv6_autoconf.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_SR.py')
        disable_source()
        logging.info('Finished the execution of /ericsson/security/bin/disable_SR.py')
        logging.info('Started the execution of /ericsson/security/bin/configure_icmp.py')
        icmp_configure()
        logging.info('Finished the execution of /ericsson/security/bin/configure_icmp.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_icmp_broadcast.py')
        icmp_broadcast()
        logging.info('Finished the execution of /ericsson/security/bin/disable_icmp_broadcast.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_secure_icmp.py')
        disable_secure()
        logging.info('Finished the execution of /ericsson/security/bin/disable_secure_icmp.py')
        logging.info('Started the execution of /ericsson/security/bin/enable_suspicious_packets.py')
        enable_packets()
        logging.info('Finished the execution of /ericsson/security/bin/enable_suspicious_packets.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_icmp_responses.py')
        icmp_responses()
        logging.info('Finished the execution of /ericsson/security/bin/disable_icmp_responses.py')
        logging.info('Started the execution of /ericsson/security/bin/enable_reverse_path_filter.py')
        enable_rev_path_filter()
        logging.info('Finished the execution of /ericsson/security/bin/enable_reverse_path_filter.py')
        logging.info('Started the execution of /ericsson/security/bin/enable_tcp_syncookies.py')
        enable_tcp_syncookies()
        logging.info('Finished the execution of /ericsson/security/bin/enable_tcp_syncookies.py')
        logging.info('Started the execution of /ericsson/security/bin/disable_ipv6_advertisements.py')
        disable_ipv6_adv()
        logging.info('Finished the execution of /ericsson/security/bin/disable_ipv6_advertisements.py')

        print "\n\x1b[32m**********Successfully Enforced Hardening Network Configuration and Parameters\
 Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced Hardening Network Configuration and Parameters \
Features**********")

    elif option=='6':
        print "\n**********Started the Enforcing of Task Scheduler Features**********\n"
        logging.info("**********Started the Enforcing of Task Scheduler Features**********")

        logging.info('Started the execution of /ericsson/security/bin/set_cron_log.py')
        cron_log()
        logging.info('Finished the execution of /ericsson/security/bin/set_cron_log.py')

        print "\n\x1b[32m**********Successfully Enforced Task Scheduler Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced Task Scheduler Features**********")

    elif option == '7':
        print "\n**********Started the Enforcing of System Policy and Firewall Restrictions\
 Features**********\n"
        logging.info("**********Started the Enforcing of System Policy and Firewall Restrictions\
 Features**********")

        logging.info('Started the execution of /ericsson/security/bin/enforce_selinux.py')
        check_se_status()
        logging.info('Finished the execution of /ericsson/security/bin/enforce_selinux.py')
        logging.info('Started the execution of /ericsson/security/bin/enable_firewall.py')
        firewall()
        logging.info('Finished the execution of /ericsson/security/bin/enable_firewall.py')

        print "\n\x1b[32m**********Successfully Enforced System Policy and Firewall Restrictions\
 Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced System Policy and Firewall Restrictions\
 Features**********")

    elif option=='8':
        print "\n**********Started the Enforcing of System Monitoring Features**********\n"
        logging.info("**********Started the Enforcing of System Monitoring Features**********")

        logging.info('Started the execution of  /ericsson/security/bin/list_rpms.py')
        check_rpms()
        logging.info('Finished the execution of  /ericsson/security/bin/list_rpms.py')
        logging.info('Started the execution of /ericsson/security/bin/list_inactive_users.py')
        user_login()
        logging.info('Finished the execution of /ericsson/security/bin/list_inactive_users.py')
        logging.info('Started the execution of /ericsson/security/bin/nh_summary.py')
        generate_report()
        logging.info('Finished the execution of /ericsson/security/bin/nh_summary.py')

        print "\n\x1b[32m**********Successfully Enforced System Monitoring Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced System Monitoring Features**********")

    elif option=='9':
        print "\nm**********Started the Enforcing of Sentinal Port Configuration for\
 Network Analytics Server Features**********\n"
        logging.info("**********Started the Enforcing of Sentinal Port Configuration for Network\
 Analytics Server Features**********")

        WHITELIST_IP = get_netan_ip()
        if not WHITELIST_IP:
            print "\nNetAN is not configured on the server!\n"
            logging.error('\nNetAN is not configured on the server!\n')
        else:
            netan_whitelisting(WHITELIST_IP)
            print "\n\x1b[32m**********Successfully Enforced Sentinal Port Configuration for\
 Network Analytics Server Features**********\x1b[0m\n"
            logging.info("**********Successfully Enforced Sentinal Port Configuration for Network\
 Analytics Server Features**********")

    elif option=='10':
        print "\n**********Started the Enforcing of Prevent Accidental Reboot Category Features**********\n"
        logging.info("**********Started the Enforcing of Prevent Accidental Reboot Category Features**********")

        logging.info('Started the execution of /ericsson/security/bin/mask_alt_ctrl_del.py')
        ctrl_del()
        logging.info('Finished the execution of /ericsson/security/bin/mask_alt_ctrl_del.py')

        print "\n\x1b[32m**********Successfully Enforced Prevent Accidental Reboot Category Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced Prevent Accidental Reboot Category Features**********")


    elif option=='11':
        print "\n**********Started the Enforcing of Logs and Audit Features**********\n"
        logging.info("**********Started the Enforcing of Logs and Audit Features**********")

        logging.info('Started the execution of /ericsson/security/audit/audit_config.py')
        Logaudit().check_flags_file()
        Logaudit().default_config_backup()
        Logaudit().check_customized_rules()
        if not Logaudit().service_check():
            log_func(1, 'configure_granular_features', LOG_PATH)
            exit(1)
        logging.info('Finished the execution of /ericsson/security/audit/audit_config.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_date_time_info.py')
        customized_date_time_info()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_date_time_info.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_user_group_info.py')
        customized_user_group_info()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_user_group_info.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_system_network.py')
        customized_system_network()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_system_network.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_system_access.py')
        customized_system_access()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_system_access.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_kernel_module.py')
        customized_kernel_module()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_kernel_module.py')
        logging.info('Started the execution of /ericsson/security/bin/discretionary_access_control.py')
        customized_disec_access()
        logging.info('Finished the execution of /ericsson/security/bin/discretionary_access_control.py')
        logging.info('Started the execution of /ericsson/security/bin/file_auth.py')
        customized_file_auth()
        logging.info('Finished the execution of /ericsson/security/bin/file_auth.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_user_priviliged_cmd.py')
        customized_user_priviliged_cmd()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_user_priviliged_cmd.py')
        logging.info('Started the execution of /ericsson/security/bin/enforce_system_mount.py')
        customized_system_mount()
        logging.info('Finished the execution of /ericsson/security/bin/enforce_system_mount.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_file_deletion.py')
        customized_file_deletion()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_file_deletion.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_sys_admin_scope.py')
        customized_sys_admin_scope()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_sys_admin_scope.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_auditconf_immutable.py')
        immutable_auditconf()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_auditconf_immutable.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_sys_admin_cmd.py')
        customized_sys_admin_cmd()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_sys_admin_cmd.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_login_logout_events.py')
        customized_login_logout()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_login_logout_events.py')
        logging.info('Started the execution of /ericsson/security/bin/ensure_session_info.py')
        customized_session_info()
        logging.info('Finished the execution of /ericsson/security/bin/ensure_session_info.py')

        print "\n\x1b[32m**********Successfully Enforced Logs and Audit Features**********\x1b[0m\n"
        logging.info("**********Successfully Enforced Logs and Audit Features**********")

    else:
        print"\n**********Entered Input Is Invalid. Features are not Enforced.**********\n"
        logging.info("**********Entered Input Is Invalid. Features are not Enforced.**********")

def user_input():
    '''This function will take the input from the user'''

    for _ in range(2):
        categories_list =["1: User Restrictions", "2: User Session Management", "3: Secure File\
 Configuration and Restrictions", "4: Secure SSH Configuration", "5: Hardening Network configuration\
 and parameters", "6: Task Scheduler", "7: System Policy and Firewall Restrictions", "8: System Monitoring",\
 "9: Sentinal Port Configuration for Network Analytics Server", "10: Prevent Accidental Reboot", "11: Logs and Audit"]

        for element in categories_list:
            print(element)
        print "\nNOTE: Automatic reboot is triggered on the server, post successful granular hardening \
configuration.\n"

        selected_category = list([x for x in raw_input("\nPlease Select Category Of Features To Be\
 Enforced: ").split()])
        check = all([item.isdigit() for item in selected_category])

        options_list = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']
        count = 0
        count = sum(1 for i in selected_category if i in options_list)

        if check == True and count == len(selected_category)  and count > 0:
            logging.info('Started the execution of /ericsson/security/bin/set_password_policy.py')
            change_hashing_algo()
            logging.info('Finished the execution of /ericsson/security/bin/set_password_policy.py')
            print "\n\x1b[32m**********Successfully Enforced Password Policies**********\x1b[0m\n"
            logging.info("**********Successfully Enforced Password Policies**********")
            [configure_granular_features(option) for option in selected_category]
            return True
        else:
            print"\n**********Entered Input Is Invalid**********"
            print("\033[93m\nPlease Choose One Or More Options From 1 to 11 Categories\033[00m\n")

    print("\nYou have exceeded the maximum number of attempts. Exiting...\n")
    return False

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_configure_granular_features.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'configure_granular_features.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        user_input_result = user_input()
        log_func(SCRIPT_NAME, 1, LOG_PATH)
        if user_input_result:
            logging.info('The server is rebooting now')
            reboot()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"