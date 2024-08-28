#!/usr/bin/python
"""
# ***************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ***************************************************************************
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
# ******************************************************************************
# Name      : Apply_Node_Hardening.py
# Purpose   : This script applies all the Node Hardening procedures sequentially.
#
#
# ******************************************************************************
"""

import time
import os
import logging
import subprocess
import sys
import getpass

from user_verification import user_verification
from set_ssh_banner import ssh_ban
from set_cron_log import cron_log
from restrict_cron import cron
from restrict_at import at
from set_grace_time import ssh_login
from list_inactive_users import user_login
from set_umask import umask_all
from enable_ssh_login import ssh_user
from set_autologout import auto_logout
from add_cipher import add_cipher
from list_rpms import check_rpms
from enforce_selinux import check_se_status
from configure_sshd import agent_fwdng
from tcp_wrappers import tcp_wrap
from set_password_aging import pass_age
from reverse_fwd import reverse_fwd
from disable_SR import disable_source
from enable_firewall import firewall
from set_password_policy import change_hashing_algo
from reboot import reboot
from verify_static_ip_config import ip_config
from mask_alt_ctrl_del import ctrl_del
from enable_sticky_bit import sticky_bit
from enable_ssh_proto_v2 import ssh_protocol
from disable_icmp_broadcast import icmp_broadcast
from disable_access_suid import root_uid
from set_motd_banner import motd
from configure_icmp import icmp_configure
from disable_AllowTcpForwarding import allow_tcp_forwarding
from disable_X11Forwarding import x11_forwarding
from disable_GatewayPorts import disable_gatewayports
from disable_Ipv6_autoconf import disable_ipv6_autoconf
from enable_sshHostKey_verification import enable_ssh_hostkey
from Verify_NH_Config import open_mws_ports
from Verify_NH_Config import open_eniq_ports
from sentinel_hardening import get_netan_ip
from sentinel_hardening import netan_whitelisting
from pre_nh_checks import Precheck
from set_file_permissions import set_permission
from set_inactive_days import set_inactive
from disable_icmp_responses import icmp_responses
from enable_reverse_path_filter import enable_rev_path_filter
from enable_suspicious_packets import enable_packets
from disable_secure_icmp import disable_secure
from disable_ipv6_advertisements import disable_ipv6_adv
from enable_tcp_syncookies import enable_tcp_syncookies
from set_path_integrity import verify_path
from su_restriction import restrict_su_command
from set_maxauthtries import set_maxauth
from add_keyexchng_algorithm import add_kex
from enforce_ssh_timeout import ssh_timeout
from set_maxstartups import set_maxstart
from infra_nh import head
from disable_ssh_userenvironment import disable_ssh_userenvironment
from disable_ssh_emptypasswords import disable_ssh_emptypasswords
from disable_hostbasedAuthentication import disable_hostbased_authentication
from enable_ignoreRhosts import enable_ignorerhosts
from ensure_user_group_info import customized_user_group_info
from ensure_sys_admin_scope import customized_sys_admin_scope
from enforce_system_mount import customized_system_mount
from ensure_file_auth import customized_file_auth
from discretionary_access_control import customized_disec_access
from ensure_sys_admin_cmd import customized_sys_admin_cmd
from ensure_login_logout_events import customized_login_logout
from ensure_session_info import customized_session_info
from ensure_system_access import customized_system_access
from ensure_date_time_info import customized_date_time_info
from ensure_system_network import customized_system_network
from ensure_file_deletion import customized_file_deletion
from ensure_auditconf_immutable import immutable_auditconf
from ensure_kernel_module import customized_kernel_module
from ensure_user_priviliged_cmd import customized_user_priviliged_cmd
from sudologs_rotate import sudo_log
from disable_root_switch import sudo_switch
from nh_summary import generate_report

sys.path.insert(0, '/ericsson/security/audit')
from audit_config import Logaudit
from audit_automate_cron import get_automated_audit_cron
os.environ['TERM'] = 'xterm'

def logger(state, script, log_path):
    """This function is to provide a general log header and footer"""
    if state == 0:
        open(log_path, 'a').write('*'*95+'\n')
        host = subprocess.check_output('hostname', shell=True).replace('\n', '')
        start_time = time.strftime("%Y-%m-%d_%H-%M-%S")
        open(log_path, 'a').write(host+' '*(95-len(host)-len(start_time))+start_time+'\n')
        open(log_path, 'a').write(script+'\n')
        open(log_path, 'a').write('*'*95+'\n')
    elif state == 1:
        open(log_path, 'a').write('*'*95+'\nLog file location:\n')
        open(log_path, 'a').write(log_path+'\n'+'*'*95+'\n')
        print "Script logs are saved at : \033[93m %s \033[00m" % log_path

def change_permissions(items, mode):
    """This is to change the permissions of log directories and files"""
    for path in items:
        for root, dirs, files in os.walk(path, topdown=False):
            os.chmod(root, mode)
            for dir in [os.path.join(root, d) for d in dirs]:
                os.chmod(dir, mode)
            for file in [os.path.join(root, f) for f in files]:
                os.chmod(file, mode)
    os.system("setfacl -d -m other::000 /ericsson/security/log 1> /dev/null 2>&1")
    os.system("setfacl -d -m other::000 /ericsson/security/audit/logs 1> /dev/null 2>&1")

def main():
    """This function encasulates all the node hardening procedures"""
    logging.info("\nTaking the backup of configuration files. . .\n")
    subprocess.call("cp /etc/pam.d/system-auth /etc/pam.d/system-auth_backup_%s" % timestr, shell=True)
    subprocess.call("cp /etc/profile /etc/profile_backup_%s" % timestr, shell=True)
    subprocess.call("cp /etc/pam.d/password-auth /etc/pam.d/password-auth_backup_%s" % timestr, shell=True)
    subprocess.call("cp /etc/logrotate.conf /etc/logrotate.conf_backup_%s" % timestr, shell=True)
    subprocess.call("cp /etc/ssh/sshd_config /etc/ssh/sshd_config_backup_%s" % timestr, shell=True)
    subprocess.call("cp /etc/ssh/ssh_config /etc/ssh/ssh_config_backup_%s" % timestr, shell=True)
    subprocess.call("cp /etc/login.defs /etc/login.defs_backup_%s" % timestr, shell=True)

    #EQEV - 103109 Removal of ntp related hardening in MWS & ENIQ-S
    os.system("rm -rf /ericsson/security/BACKUP_CONFIG_FILES/0etc0ntp.conf")

    logging.info('Starting log collection of Node hardening Pre Check')
    Precheck('/ericsson/security/log/Apply_NH_Logs/pre_check_data.log').start_pre_check()
    print "Collected specific service status in pre_check_data.log file for troubleshooting purposes."
    logging.info('Finished collecting Node hardening Pre Check')

    logging.info('Started the execution of /ericsson/security/audit/audit_config.py')
    Logaudit().check_flags_file()
    Logaudit().default_config_backup()
    Logaudit().check_customized_rules()
    if not Logaudit().service_check():
        logger(1, 'Apply_Node_Hardening.py', LOG_PATH)
        exit(1)
    logging.info('Finished the execution of /ericsson/security/audit/audit_config.py')
    logging.info('Started the execution of /ericsson/security/bin/enforce_selinux.py')
    check_se_status()
    logging.info('Finished the execution of /ericsson/security/bin/enforce_selinux.py')
    logging.info('Started the execution of  /ericsson/security/bin/list_rpms.py')
    check_rpms()
    logging.info('Finished the execution of  /ericsson/security/bin/list_rpms.py')
    logging.info('Started the execution of /ericsson/security/bin/set_password_policy.py')
    change_hashing_algo()
    logging.info('Finished the execution of /ericsson/security/bin/set_password_policy.py')
    logging.info('Started the execution of /ericsson/security/bin/enable_ssh_login.py')
    ssh_user(0)
    logging.info('Finished the execution of /ericsson/security/bin/enable_ssh_login.py')
    logging.info('Started the execution of /ericsson/security/bin/set_autologout.py')
    auto_logout()
    logging.info('Finished the execution of /ericsson/security/bin/set_autologout.py')
    logging.info('Started the execution of /ericsson/security/bin/add_cipher.py')
    add_cipher()
    logging.info('Finished the execution of /ericsson/security/bin/add_cipher.py')
    logging.info('Started the execution of /ericsson/security/bin/configure_sshd.py')
    agent_fwdng()
    logging.info('Finished the execution of /ericsson/security/bin/configure_sshd.py')
    logging.info('Started the execution of /ericsson/security/bin/tcp_wrappers.py')
    tcp_wrap()
    logging.info('Finished the execution of /ericsson/security/bin/tcp_wrappers.py')
    logging.info('Started the execution of /ericsson/security/bin/set_password_aging.py')
    pass_age()
    logging.info('Finished the execution of /ericsson/security/bin/set_password_aging.py')
    logging.info('Started the execution of /ericsson/security/bin/reverse_fwd.py')
    reverse_fwd()
    logging.info('Finished the execution of /ericsson/security/bin/reverse_fwd.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_SR.py')
    disable_source()
    logging.info('Finished the execution of /ericsson/security/bin/disable_SR.py')
    logging.info('Started the execution of /ericsson/security/bin/enable_firewall.py')
    firewall()
    logging.info('Finished the execution of /ericsson/security/bin/enable_firewall.py')
    logging.info('Started the execution of /ericsson/security/bin/configure_icmp.py')
    icmp_configure()
    logging.info('Finished the execution of /ericsson/security/bin/configure_icmp.py')
#    logging.info('Started the execution of /ericsson/security/bin/capture_performance.py')
#    performance()
#    logging.info('Finished the execution of /ericsson/security/bin/capture_performance.py')
    logging.info('Started the execution of /ericsson/security/bin/set_ssh_banner.py')
    ssh_ban()
    logging.info('Finished the execution of /ericsson/security/bin/set_ssh_banner.py')
    logging.info('Started the execution of /ericsson/security/bin/set_cron_log.py')
    cron_log()
    logging.info('Finished the execution of /ericsson/security/bin/set_cron_log.py')
    logging.info('Started the execution of /ericsson/security/bin/restrict_cron.py')
    cron()
    logging.info('Finished the execution of /ericsson/security/bin/restrict_cron.py')
    logging.info('Started the execution of /ericsson/security/bin/restrict_at.py')
    at()
    logging.info('Finished the execution of /ericsson/security/bin/restrict_at.py')
    logging.info('Started the execution of /ericsson/security/bin/set_grace_time.py')
    ssh_login()
    logging.info('Finished the execution of /ericsson/security/bin/set_grace_time.py')
    logging.info('Started the execution of /ericsson/security/bin/set_umask.py')
    umask_all()
    logging.info('Finished the execution of /ericsson/security/bin/set_umask.py')
    logging.info('Started the execution of /ericsson/security/bin/list_inactive_users.py')
    user_login()
    logging.info('Finished the execution of /ericsson/security/bin/list_inactive_users.py')
    logging.info('Started the execution of /ericsson/security/bin/verify_static_ip_config.py')
    ip_config()
    logging.info('Finished the execution of /ericsson/security/bin/verify_static_ip_config.py')
    logging.info('Started the execution of /ericsson/security/bin/mask_alt_ctrl_del.py')
    ctrl_del()
    logging.info('Finished the execution of /ericsson/security/bin/mask_alt_ctrl_del.py')
    logging.info('Started the execution of /ericsson/security/bin/enable_sticky_bit.py')
    sticky_bit()
    logging.info('Finished the execution of /ericsson/security/bin/enable_sticky_bit.py')
    logging.info('Started the execution of /ericsson/security/bin/enable_ssh_proto_v2.py')
    ssh_protocol()
    logging.info('Finished the execution of /ericsson/security/bin/enable_ssh_proto_v2.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_icmp_broadcast.py')
    icmp_broadcast()
    logging.info('Finished the execution of /ericsson/security/bin/disable_icmp_broadcast.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_access_suid.py')
    root_uid()
    logging.info('Finished the execution of /ericsson/security/bin/disable_access_suid.py')
    logging.info('Started the execution of /ericsson/security/bin/set_motd_banner.py')
    motd()
    logging.info('Finished the execution of /ericsson/security/bin/set_motd_banner.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_AllowTcpForwarding.py')
    allow_tcp_forwarding()
    logging.info('Finished the execution of /ericsson/security/bin/disable_AllowTcpForwarding.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_X11Forwarding.py')
    x11_forwarding()
    logging.info('Finished the execution of /ericsson/security/bin/disable_X11Forwarding.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_GatewayPorts.py')
    disable_gatewayports()
    logging.info('Finished the execution of /ericsson/security/bin/disable_GatewayPorts.py')
    logging.info('Started the execution of /ericsson/security/bin/enable_sshHostKey_verification.py')
    enable_ssh_hostkey()
    logging.info('Finished the execution of /ericsson/security/bin/enable_sshHostKey_verification.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_Ipv6_autoconf.py')
    disable_ipv6_autoconf()
    logging.info('Finished the execution of /ericsson/security/bin/disable_Ipv6_autoconf.py')
    logging.info('\nChanging the log file permissions\n')
    logging.info('Started the execution of /ericsson/security/bin/set_file_permissions.py')
    set_permission()
    logging.info('Finished the execution of /ericsson/security/bin/set_file_permissions.py')
    logging.info('Started the execution of /ericsson/security/bin/set_inactive_days.py')
    set_inactive()
    logging.info('Finished the execution of /ericsson/security/bin/set_inactive_days.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_icmp_responses.py')
    icmp_responses()
    logging.info('Finished the execution of /ericsson/security/bin/disable_icmp_responses.py')
    logging.info('Started the execution of /ericsson/security/bin/enable_reverse_path_filter.py')
    enable_rev_path_filter()
    logging.info('Finished the execution of /ericsson/security/bin/enable_reverse_path_filter.py')
    logging.info('Started the execution of /ericsson/security/bin/enable_suspicious_packets.py')
    enable_packets()
    logging.info('Finished the execution of /ericsson/security/bin/enable_suspicious_packets.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_secure_icmp.py')
    disable_secure()
    logging.info('Finished the execution of /ericsson/security/bin/disable_secure_icmp.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_ipv6_advertisements.py')
    disable_ipv6_adv()
    logging.info('Finished the execution of /ericsson/security/bin/disable_ipv6_advertisements.py')
    logging.info('Started the execution of /ericsson/security/bin/enable_tcp_syncookies.py')
    enable_tcp_syncookies()
    logging.info('Finished the execution of /ericsson/security/bin/enable_tcp_syncookies.py')
    logging.info('Started the execution of /ericsson/security/bin/set_path_integrity.py')
    verify_path()
    logging.info('Finished the execution of /ericsson/security/bin/set_path_integrity.py')
    logging.info('Started the execution of /ericsson/security/bin/su_restriction.py')
    restrict_su_command()
    logging.info('Finished the execution of /ericsson/security/bin/su_restriction.py')
    logging.info('Started execution of /ericsson/security/bin/add_keyexchng_algorithm.py')
    add_kex()
    logging.info('Finished execution of /ericsson/security/bin/add_keyexchng_algorithm.py')
    logging.info('Started the execution of /ericsson/security/bin/set_maxauthtries.py')
    set_maxauth()
    logging.info('Finished the execution of /ericsson/security/bin/set_maxauthtries.py')
    logging.info('Started the execution of /ericsson/security/bin/enforce_ssh_timeout.py')
    ssh_timeout()
    logging.info('Finished the execution of /ericsson/security/bin/enforce_ssh_timeout.py')
    logging.info('Started the execution of /ericsson/security/bin/set_maxstartups.py')
    set_maxstart()
    logging.info('Finished the execution of /ericsson/security/bin/set_maxstartups.py')
    logging.info('Started the execution of /ericsson/security/bin/infra_nh.py')
    head()
    logging.info('Finished the execution of /ericsson/security/bin/infra_nh.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_ssh_userenvironment.py')
    disable_ssh_userenvironment()
    logging.info('Finished the execution of /ericsson/security/bin/disable_ssh_userenvironment.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_ssh_emptypasswords.py')
    disable_ssh_emptypasswords()
    logging.info('Finished the execution of /ericsson/security/bin/disable_ssh_emptypasswords.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_hostbasedAuthentication.py')
    disable_hostbased_authentication()
    logging.info('Finished the execution of /ericsson/security/bin/disable_hostbasedAuthentication.py')
    logging.info('Started the execution of /ericsson/security/bin/enable_ignoreRhosts.py')
    enable_ignorerhosts()
    logging.info('Finished the execution of /ericsson/security/bin/enable_ignoreRhosts.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_user_group_info.py')
    customized_user_group_info()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_user_group_info.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_sys_admin_scope.py')
    customized_sys_admin_scope()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_sys_admin_scope.py')
    logging.info('Started the execution of /ericsson/security/bin/enforce_system_mount.py')
    customized_system_mount()
    logging.info('Finished the execution of /ericsson/security/bin/enforce_system_mount.py')
    logging.info('Started the execution of /ericsson/security/bin/file_auth.py')
    customized_file_auth()
    logging.info('Finished the execution of /ericsson/security/bin/file_auth.py')
    logging.info('Started the execution of /ericsson/security/bin/discretionary_access_control.py')
    customized_disec_access()
    logging.info('Finished the execution of /ericsson/security/bin/discretionary_access_control.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_sys_admin_cmd.py')
    customized_sys_admin_cmd()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_sys_admin_cmd.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_system_access.py')
    customized_system_access()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_system_access.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_date_time_info.py')
    customized_date_time_info()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_date_time_info.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_system_network.py')
    customized_system_network()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_system_network.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_file_deletion.py')
    customized_file_deletion()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_file_deletion.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_kernel_module.py')
    customized_kernel_module()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_kernel_module.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_auditconf_immutable.py')
    immutable_auditconf()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_auditconf_immutable.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_user_priviliged_cmd.py')
    customized_user_priviliged_cmd()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_user_priviliged_cmd.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_login_logout_events.py')
    customized_login_logout()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_login_logout_events.py')
    logging.info('Started the execution of /ericsson/security/bin/ensure_session_info.py')
    customized_session_info()
    logging.info('Finished the execution of /ericsson/security/bin/ensure_session_info.py')
    logging.info('Started the execution of /ericsson/security/bin/sudologs_rotate.py')
    sudo_log()
    logging.info('Finished the execution of /ericsson/security/bin/sudologs_rotate.py')
    logging.info('Started the execution of /ericsson/security/bin/disable_root_switch.py')
    sudo_switch()
    logging.info('Finished the execution of /ericsson/security/bin/disable_root_switch.py')
    logging.info('Started the execution of /ericsson/security/audit/audit_automate_cron.py')
    get_automated_audit_cron()
    logging.info('Finished the execution of /ericsson/security/audit/audit_automate_cron.py')
    logging.info('Started the execution of /ericsson/security/bin/nh_summary.py')
    generate_report()
    logging.info('Finished the execution of /ericsson/security/bin/nh_summary.py')
    change_permissions(['/ericsson/security/audit/logs', '/ericsson/security/log'], 0o640)
    logging.info('\nFinished changing the log file permissions\n')
    os.system("rm -rf /ericsson/security/bin/*.pyc")

def ans():
    """This function verifies whether the script is called by ansible"""
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    action = action.split()
    if "--ansible" in action:
        logging.info("Called by Ansible, Skipping reboot!")
    else:
        reboot()

if __name__ == '__main__':
    user_verification()
    print "\n"+"+"*68+"\x1b[32m\"HARDENING THE SERVER\"\x1b[0m"+"+"*78+"\n"
    print "\nNOTE: Automatic reboot is triggered on the server, post successful node hardening \
configuration.\n"
    disp = raw_input("\033[93m\"Do you still want to proceed? (y/n):?\"\033[00m ")

    if (disp == 'y') or (disp == 'Y'):
        timestr = time.strftime("%Y%m%d-%H%M%S")
        fname = timestr + '_Apply_Node_Hardening.log'
        os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs")
        format_string = '%(levelname)s: %(asctime)s: %(message)s'
        logging.basicConfig(level=logging.DEBUG,
                            filename="/ericsson/security/log/Apply_NH_Logs/%s" % fname,
                            format=format_string)
        LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/%s" % fname
        logger(0, 'Apply_Node_Hardening.py', LOG_PATH)
        check_mount_point = os.path.ismount("/JUMP")
        mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
        eniq_insttype_path = os.path.exists("/eniq/installation/config/")

        if mws_insttype_path is True:
            mws_insttype = subprocess.check_output("cat /ericsson/config/inst_type", shell=True)
            server_config_name = subprocess.check_output("cat /ericsson/config\
/ericsson_use_config | cut -d'=' -f 2", shell=True)
            server_config_name = server_config_name.replace('\n', '')

            if (check_mount_point is True) and ('rhelonly' in mws_insttype) and ('mws' in server_config_name):
                print "\n"+"*"*35+"Proceeding with MWS Node hardening"+"*"*48+"\n"
                main()
                print "\nOpening the required ports on the MWS server...\n"
                logging.info("\nOpening the required ports on the MWS server...\n")
                open_mws_ports()
                logging.info('The server is rebooting now')
                logger(1, 'Apply_Node_Hardening.py', LOG_PATH)
                ans()
            else:
                print "\nMWS configuration is not complete.Please verify the configuration!\n"
                logging.error('MWS configuration is not complete.Please verify the configuration!')
                logger(1, 'Apply_Node_Hardening.py', LOG_PATH)
                exit(1)
        elif eniq_insttype_path is True:
            print "\n"+"*"*35+"Proceeding with ENIQ-S Node hardening"+"*"*48+"\n"
            main()
            print "\nOpening the required ports on the ENIQ server...\n"
            logging.info("\nOpening the required ports on the ENIQ server...\n")
            #EQEV-65585: Need to open ports based on server type
            open_eniq_ports()
            if os.path.exists("/ericsson/storage/etc/sourcefile") is True:
                os.system("/ericsson/security/bin/gpgenable.sh")
            WHITELIST_IP = get_netan_ip()
            if not WHITELIST_IP:
                print "\nNetAN is not configured on the server!\n"
                logging.error('\nNetAN is not configured on the server!\n')
            else:
                netan_whitelisting(WHITELIST_IP)
                print "\n"
            logging.info('The server is rebooting now')
            logger(1, 'Apply_Node_Hardening.py', LOG_PATH)
            ans()
        else:
            print "\nServer not configured either as MWS nor as Eniq\n"
            logging.error('Server not configured either as MWS nor as Eniq')
            logger(1, 'Apply_Node_Hardening.py', LOG_PATH)
            exit(1)
    elif (disp == 'n') or (disp == 'N'):
        print"\n"
        exit(1)
    else:
        print "Invalid Option\n"
        exit(1)
