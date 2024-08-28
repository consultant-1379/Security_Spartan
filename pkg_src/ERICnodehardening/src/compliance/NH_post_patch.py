#!/usr/bin/python
"""
# ****************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ****************************************************************************
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
# Name      : NH_post_patch.py
# Purpose   : This script verifies if the patch upgrade has altered any
#             hardening functionality in the server. If so, it re-applies the same.
#
#
# ******************************************************************************
"""
import os
from os import path
import time
import sys
import logging
import signal
sys.path.insert(0, '/ericsson/security/bin')
import user_verification
from user_verification import user_verification
from verify_selinux import check_sestatus
from verify_firewall import check_firewall
from verify_umask import check_umask
from verify_cipher import check_cipher
from verify_password_policy import check_password_complexity
from verify_autologout import check_autologout
from verify_listing_rpms import check_listing_rpms
from cron_log_audit import cron_log_cmp
from grace_time_audit import grace_cmp
from restrict_at_audit import at_restrict_cmp
from restrict_cron_audit import cron_restrict_cmp
from verify_tcp_wrappers import tcp_cmp
from verify_ssh_login import check_ssh_login
from verify_mask import ctrl_alt_del
from verify_icmp_config import icmp_check
from verify_static_ip import dhcp_staticip_check
from verify_suid import root_suid_check
from verify_ssh_v2 import ssh_protocol_check
from verify_icmp import check_icmp
from verify_agent_fwdng import check_sshd_config
from verify_SR import check_sr_status
from verify_sticky_bit import check_sticky_bit
from verify_reverse_fwd import check_reverse_fwd
from verify_motd_banner import check_motd_banner
from verify_password_age import check_password_aging
from verify_sshd_banner import check_banner
from verify_AllowTCPForwording import allowtcp_forwarding_check
from verify_X11Forwarding import x11_forwarding_check
from verify_GatewayPorts import check_gatewayports_status
from verify_sshHostKeyVerification import check_ssh_hostkey_status
from verify_Ipv6_autoconf import check_ipv6_autoconf_status
from verify_audit import check_audit_config
from verify_file_permissions import verify_permissions
from verify_inactive import check_inactive
from verify_icmp_responses import check_icmp_status
from verify_reverse_path_filter import check_rev_path
from verify_suspicious_packets import check_packets
from verify_secure_icmp import check_secure_icmp
from verify_ipv6_advertisements import check_ipv6_adv
from verify_tcp_syncookies import check_tcp_syncookies
from verify_path_integrity import check_integrity
from verify_su_restriction import check_restriction
from verify_set_maxauth import check_maxauthtries
from verify_keyexchng_algorithm import check_kex
from verify_ssh_timeout import check_sshtimeout
from verify_set_maxstart import check_maxstartup
from verify_ssh_userenvironment import check_ssh_userenvironment
from verify_ssh_emptypasswords import check_ssh_emptypasswords
from verify_ignoreRhosts import check_ignorerhosts
from verify_hostbasedAuthentication import check_hostbased_authentication
from verify_sys_admin_scope import check_sys_admin_scope
from verify_user_group_info import check_user_group_info
from verify_system_mount import check_mounts
from verify_file_auth import check_file_auth
from verify_discec_access import check_disec_access
from verify_sys_admin_cmd import check_sys_admin_cmd
from verify_system_access import check_system_access
from verify_date_time_info import check_date_time_info
from verify_system_network import check_system_network
from verify_file_deletion import check_file_deletion
from verify_kernel_module import check_kernel_module
from verify_auditconf_immutable import check_auditconf_immutable
from verify_user_priviliged_cmd import check_user_privileged_cmd
from verify_sudologs_rotate import verify_sudo_log
from verify_disable_root_switch import verify_disable_root_switch
from verify_audit_automate_cron import verify_audit_automate_cron
sys.path.insert(0, '/ericsson/security/bin')
from enforce_selinux import check_se_status
from enable_firewall import firewall
from set_umask import umask_all
import add_cipher
from add_cipher import add_cipher
from set_password_policy import change_hashing_algo
from set_password_aging import pass_age
from set_autologout import auto_logout
from list_rpms import check_rpms
from set_cron_log import cron_log
from set_grace_time import ssh_login
from restrict_at import at
from restrict_cron import cron
from tcp_wrappers import tcp_wrap
from enable_ssh_login import ssh_user
from mask_alt_ctrl_del import ctrl_del
from disable_icmp_broadcast import icmp_broadcast
from enable_ssh_proto_v2 import ssh_protocol
from verify_static_ip_config import ip_config
from disable_access_suid import root_uid
from configure_icmp import icmp_configure
from set_ssh_banner import ssh_ban
from set_motd_banner import motd
from disable_SR import disable_source
import reverse_fwd
from reverse_fwd import reverse_fwd
from configure_sshd import agent_fwdng
from enable_sticky_bit import sticky_bit
from disable_X11Forwarding import x11_forwarding
from disable_AllowTcpForwarding import allow_tcp_forwarding
from disable_GatewayPorts import disable_gatewayports
from disable_Ipv6_autoconf import disable_ipv6_autoconf
from enable_sshHostKey_verification import enable_ssh_hostkey
from Verify_NH_Config import configure_nh
from Verify_NH_Config import block_tftp_if_present
from Verify_NH_Config import remove_deprecated_ports_if_present
from set_file_permissions import set_permission
import set_inactive_days
from set_inactive_days import set_inactive
import disable_icmp_responses
from disable_icmp_responses import icmp_responses
import enable_reverse_path_filter
from enable_reverse_path_filter import enable_rev_path_filter
import enable_suspicious_packets
from enable_suspicious_packets import enable_packets
import disable_secure_icmp
from disable_secure_icmp import disable_secure
import disable_ipv6_advertisements
from disable_ipv6_advertisements import disable_ipv6_adv
import enable_tcp_syncookies
from enable_tcp_syncookies import enable_tcp_syncookies
import set_path_integrity
from set_path_integrity import verify_path
import su_restriction
from su_restriction import restrict_su_command
import add_keyexchng_algorithm
from add_keyexchng_algorithm import add_kex
import set_maxauthtries
from set_maxauthtries import set_maxauth
from enforce_ssh_timeout import ssh_timeout
import set_maxstartups
from set_maxstartups import set_maxstart
import disable_ssh_userenvironment
from disable_ssh_userenvironment import disable_ssh_userenvironment
import disable_ssh_emptypasswords
from disable_ssh_emptypasswords import disable_ssh_emptypasswords
from enable_ignoreRhosts import enable_ignorerhosts
from disable_hostbasedAuthentication import disable_hostbased_authentication
import ensure_sys_admin_scope
from ensure_sys_admin_scope import sys_admin_scope
import ensure_user_group_info
from ensure_user_group_info import user_group_info
import enforce_system_mount
from enforce_system_mount import system_mount
import ensure_file_auth
from ensure_file_auth import file_auth
import  discretionary_access_control
from  discretionary_access_control import disec_access
import ensure_sys_admin_cmd
from ensure_sys_admin_cmd import sys_admin_cmd
import ensure_system_access
from ensure_system_access import ensure_system_access
import ensure_date_time_info
from ensure_date_time_info import ensure_date_time_info
import ensure_system_network
from ensure_system_network import ensure_system_network
import ensure_file_deletion
from ensure_file_deletion import ensure_file_deletion
import ensure_kernel_module
from ensure_kernel_module import ensure_kernel_module
import ensure_auditconf_immutable
from ensure_auditconf_immutable import immutable_auditconf
import ensure_user_priviliged_cmd
from ensure_user_priviliged_cmd import user_priviliged_cmd
import sudologs_rotate
from sudologs_rotate import sudo_log
from disable_root_switch import sudo_switch
import reboot
from reboot import reboot
sys.path.insert(0, '/ericsson/security/audit')
from audit_config import Logaudit
from audit_automate_cron import get_automated_audit_cron
class NullWriter(object):
    """This class is a null writer class that would hide the stdout"""
    def write(self, arg):
        """This method points to the stdout"""
        pass
timestr = time.strftime("%Y%m%d-%H%M%S")
fname = timestr + 'NH_post_patch.log'
os.system("mkdir -p /ericsson/security/log/Restore_NH_post_patch")
format_string = '%(levelname)s: %(asctime)s: %(message)s'
logging.basicConfig(level=logging.DEBUG,
                    filename="/ericsson/security/log/Restore_NH_post_patch/%s" % fname,
                    format=format_string)
if path.exists("/ericsson/security/compliance/Reports/Compliance_Report.txt") is False:
    print "\nERROR:File doesn't exist! : " \
          "/ericsson/security/compliance/Reports/Compliance_Report.txt\n"
    logging.error("\nERROR:File doesn't exist! : "
                  "/ericsson/security/compliance/Reports/Compliance_Report.txt\n")
    exit(1)
def harden_server():
    """This function is to check if the server is node hardened"""
    flag_status = 0
    print "\n#################################################Capturing Compliance " \
          "Report post patch#################################################\n"
    logging.info("\n#################################################Capturing Compliance Report \
post patch#################################################\n")
    os.system("/ericsson/security/compliance/NH_Compliance.py > /ericsson/security/compliance/Reports/\
Compliance_Report_new.txt")
    with open('/ericsson/security/compliance/Reports/Compliance_Report.txt', 'r') as file1:
        with open('/ericsson/security/compliance/Reports/Compliance_Report_new.txt', 'r') as file2:
            difference = set(file2).difference(file1)
    with open('/ericsson/security/compliance/Reports/diff_output_file.txt', 'w') as file_out:
        for line in difference:
            file_out.write(line)
    if os.stat("/ericsson/security/compliance/Reports/diff_output_file.txt").st_size == 0:
        print "\nALL APPLIED NODE HARDENING PROCEDURES ARE PERSISTANT IN THE SERVER.HENCE" \
              " EXITING. . .\n"
        logging.info("\nALL APPLIED NODE HARDENING PROCEDURES ARE PERSISTANT IN THE "
                     "SERVER.HENCE EXITING. . .\n")
        print "Script logs are saved at : \033[93m/ericsson/security/log/Restore_" \
              "NH_post_patch/\033[00m directory!"
        cleanup_on_exit()
        exit()
    else:
        print "\n****************************Proceeding with the node hardening restore" \
              "****************************\n"
        logging.info("\nProceeding with the node hardening restore\n")
        for line in open('/ericsson/security/compliance/Reports/diff_output_file.txt'):
            rec = line.strip()
            if rec.startswith('Verification of Audit Configuration completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                Logaudit().service_check()
                sys.stdout = oldstdout
                audit_status = check_audit_config()
                if audit_status == "COMPLIANT":
                    print "\nSuccessfully enforced audit configuration on the server\n"
                    logging.info("\nSuccessfully enforced audit configuration on the server\n")
                else:
                    print "\nFailed to enforced audit configuration on the server\n"
                    logging.error("\nFailed to enforced audit configuration on the server\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of SELinux status completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                check_se_status()
                sys.stdout = oldstdout
                sestatus_check = check_sestatus()
                if sestatus_check == "COMPLIANT":
                    print "\nSuccessfully enforced selinux!\n"
                    logging.info("\nSuccessfully enforced selinux!\n")
                else:
                    print "\nFailed to enforce selinux\n"
                    logging.error("\nFailed to enforce selinux\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of firewall status completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                firewall()
                configure_nh()
                sys.stdout = oldstdout
                firewalld_check = check_firewall()
                if firewalld_check == "COMPLIANT":
                    print "\nSuccessfully enabled firewalld!\n"
                    logging.info("\nSuccessfully enabled firewalld!\n")
                else:
                    print "\nFailed to enable firewalld\n"
                    logging.error("\nFailed to enable firewalld\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of secure umask configuration for all the '
                              'non-system users (UID > 1000) completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                umask_all()
                sys.stdout = oldstdout
                umask_check = check_umask()
                if umask_check == "COMPLIANT":
                    print "\nSuccessfully set umask as 027 for all the users except " \
                          "root and system users\n"
                    logging.info("\nSuccessfully set umask as 027 for all the users "
                                 "except root and system users\n")
                else:
                    print "\nFailed to set umask as 027 for all the normal users\n"
                    logging.error("\nFailed to set umask as 027 for all the normal users\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of strong ciphers and MAC for SSH communication'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                add_cipher()
                sys.stdout = oldstdout
                cipher_check = check_cipher()
                if cipher_check == "COMPLIANT":
                    print "\nSuccessfully added strong MACs and Ciphers\n"
                    logging.info("\nSuccessfully added strong MACs and Ciphers\n")
                else:
                    print "\nFailed to add the strong Ciphers and MACs\n"
                    logging.error("\nFailed to add the strong Ciphers and MACs\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of password policy is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                change_hashing_algo()
                passwd_check = check_password_complexity()
                sys.stdout = oldstdout
                if passwd_check == "COMPLIANT":
                    print "\nSuccessfully set the password policy\n"
                    logging.info("\nSuccessfully set the password policy\n")
                else:
                    print "\nFailed to set password policy\n"
                    logging.error("\nFailed to set password policy\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of password aging configuration completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                pass_age()
                sys.stdout = oldstdout
                page_check = check_password_aging()
                if page_check == "COMPLIANT":
                    print "\nSuccessfully set the password age!\n"
                    logging.info("\nSuccessfully set the password age!\n")
                else:
                    print "\nFailed to set password age!\n"
                    logging.error("\nFailed to set password age!\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of Automatic logout configuration completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                auto_logout()
                sys.stdout = oldstdout
                logout_check = check_autologout()
                if logout_check == "COMPLIANT":
                    print "\nSuccessfully set autologout to 900 seconds\n"
                    logging.info("\nSuccessfully set autologout to 900 seconds\n")
                else:
                    print "\nFailed to set autologout to 900 seconds\n"
                    logging.error("\nFailed to set autologout to 900 seconds\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of installed rpm list captured '
                              'in /ericsson/security/log/rpm_logs'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                check_rpms()
                sys.stdout = oldstdout
                list_check = check_listing_rpms()
                if list_check == "COMPLIANT":
                    print "\nSuccessfully listed the rpms " \
                          "under /ericsson/security/log/rpmlogs path!\n"
                    logging.info("\nSuccessfully listed the rpms "
                                 "under /ericsson/security/log/rpmlogs path!\n")
                else:
                    print "\nFailed to capture the rpm list\n"
                    logging.error("\nFailed to capture the rpm list\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of log rotation for /var/log files completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                cron_log()
                sys.stdout = oldstdout
                logrotate_check = cron_log_cmp()
                if logrotate_check == "COMPLIANT":
                    print "\nSuccessfully set logrotate!\n"
                    logging.info("\nSuccessfully set logrotate!\n")
                else:
                    print "\nFailed to set logrotate!\n"
                    logging.error("\nFailed to set logrotate!\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of Login grace time completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ssh_login()
                sys.stdout = oldstdout
                gracetime_check = grace_cmp()
                if gracetime_check == "COMPLIANT":
                    print "\nSuccessfully set the grace time\n"
                    logging.info("\nSuccessfully set the grace time\n")
                else:
                    print "\nFailed to set the gracetime\n"
                    logging.error("\nFailed to set the gracetime\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of user access and management '
                              'for at scheduler completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                at()
                sys.stdout = oldstdout
                at_check = at_restrict_cmp()
                if at_check == "COMPLIANT":
                    print "\nSuccessfully restricted the user access " \
                          "and management of 'at' command!\n"
                    logging.info("\nSuccessfully restricted the user "
                                 "access and management of 'at' command!\n")
                else:
                    print "\nFailed to restrict the user access and management of 'at' command!\n"
                    logging.error("\nFailed to restrict the user access and "
                                  "management of 'at' command!\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of user access and management '
                              'for cron scheduler completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                cron()
                sys.stdout = oldstdout
                cron_check = cron_restrict_cmp()
                if cron_check == "COMPLIANT":
                    print "\nSuccessfully restricted the user access " \
                          "and management of 'cron' command!\n"
                    logging.info("\nSuccessfully restricted the user access "
                                 "and management of 'cron' command!\n")
                else:
                    print "\nFailed to restrict the user access " \
                          "and management of 'cron' command!\n"
                    logging.error("\nFailed to restrict the user access "
                                  "and management of 'cron' command!\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of FTP access restriction completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                tcp_wrap()
                sys.stdout = oldstdout
                tcp_wrap_check = tcp_cmp()
                if tcp_wrap_check == "COMPLIANT":
                    print "\nSuccessfully secured services with TCP wrappers\n"
                    logging.info("\nSuccessfully secured 3services with TCP wrappers\n")
                else:
                    print "\nFailed to secure services with TCP wrappers\n"
                    logging.error("\nFailed to secure services with TCP wrappers\n")
                    flag_status = flag_status + 1
#            if rec.startswith('Performance logs are captured and are saved in a file '
#                              'under /ericsson/security/log/performance_logs'):
#                nullwrite = NullWriter()
#                oldstdout = sys.stdout
#                sys.stdout = nullwrite
#                performance()
#                sys.stdout = oldstdout
#                log_check = check_performance_logs()
#                if log_check == "COMPLIANT":
#                    print "\nSuccessfully captured performance logs!\n"
#                else:
#                    print "\nFailed to capture performance logs!\n"
            if rec.startswith('Verification of SSH access restriction is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ssh_user(0)
                ssh_login_check = check_ssh_login()
                sys.stdout = oldstdout
                if ssh_login_check == 'COMPLIANT':
                    print "\nSuccessfully restricted SSH login\n"
                    logging.info("\nSuccessfully restricted SSH login\n")
                else:
                    print "\nFailed to restrict SSH login\n"
                    logging.error("\nFailed to restrict SSH login\n")
                    flag_status = flag_status + 1
            if rec.startswith("Verification of 'ctrl+alt+del' mask completed"):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ctrl_del()
                sys.stdout = oldstdout
                set_mask_check = ctrl_alt_del()
                if set_mask_check == "COMPLIANT":
                    print "\nSuccesfully set mask for ctrl+alt+del\n"
                    logging.info("\nSuccesfully set mask for ctrl+alt+del\n")
                else:
                    print "\nFailed to set mask for ctrl+alt+del\n"
                    logging.error("\nFailed to set mask for ctrl+alt+del\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of disabled ICMP broadcasts is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                icmp_broadcast()
                sys.stdout = oldstdout
                set_icmp_check = icmp_check()
                if set_icmp_check == "COMPLIANT":
                    print "\nSuccessfully disabled ICMP broadcast\n"
                    logging.info("\nSuccessfully disabled ICMP broadcast\n")
                else:
                    print "\nFailed to disable ICMP broadcast\n"
                    logging.error("\nFailed to disable ICMP broadcast\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of SSH v2 enforcement is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ssh_protocol()
                sys.stdout = oldstdout
                ssh_v2_check = ssh_protocol_check()
                if ssh_v2_check == "COMPLIANT":
                    print "\nSuccessfully enabled SSH V2!\n"
                    logging.info("\nSuccessfully enabled SSH V2!\n")
                else:
                    print "\nFailed to enable SSH V2\n"
                    logging.error("\nFailed to enable SSH V2\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of static IP configuration for IPv4 is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ip_config()
                sys.stdout = oldstdout
                static_ip_check = dhcp_staticip_check()
                if static_ip_check == "COMPLIANT":
                    print "\nSuccesfully configured Static IP\n"
                    logging.info("\nSuccesfully configured Static IP\n")
                else:
                    print "\nFailed to configure Static IP\n"
                    logging.error("\nFailed to configure Static IP\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of SUID files present on the system is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                root_uid()
                sys.stdout = oldstdout
                suid_check = root_suid_check()
                if suid_check == "COMPLIANT":
                    print "\nAccess to files with root SUID is disabled\n"
                    logging.info("\nAccess to files with root SUID is disabled\n")
                else:
                    print "\nFailed to disable access to files with root SUID"
                    logging.error("\nFailed to disable access to files with root SUID")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of disabled vulnerable ICMP types is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                icmp_configure()
                sys.stdout = oldstdout
                icmp_verify = icmp_check()
                if icmp_verify == "COMPLIANT":
                    print "\nSuccessfully configured ICMP\n"
                    logging.info("\nSuccessfully configured ICMP\n")
                else:
                    print "\nFailed to configure ICMP\n"
                    logging.error("\nFailed to configure ICMP\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of pre logon banner configuration is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ssh_ban()
                sys.stdout = oldstdout
                sshd_banner_check = check_banner()
                if sshd_banner_check == "COMPLIANT":
                    print "\nSuccessfully set the ssh login banner message\n"
                    logging.info("\nSuccessfully set the ssh login banner message\n")
                else:
                    print "\nFailed to set ssh login banner message\n"
                    logging.error("\nFailed to set ssh login banner message\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of post logon banner configuration is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                motd()
                sys.stdout = oldstdout
                motd_banner_check = check_motd_banner()
                if motd_banner_check == "COMPLIANT":
                    print "\nSuccessfully set the motd login banner message\n"
                    logging.info("\nSuccessfully set the motd login banner message\n")
                else:
                    print "\nFailed to set motd login banner message\n"
                    logging.error("\nFailed to set motd login banner message\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of disabled source routing '
                              'for IPv4 communication is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                disable_source()
                sys.stdout = oldstdout
                sr_check = check_sr_status()
                if sr_check == "COMPLIANT":
                    print "\nSuccessfully disabled Source Routing\n"
                    logging.info("\nSuccessfully disabled Source Routing\n")
                else:
                    print "\nFailed to disable Source Routing\n"
                    logging.error("\nFailed to disable Source Routing\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of strict reverse path '
                              'forwarding for IPv4 communication is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                reverse_fwd()
                sys.stdout = oldstdout
                rev_fwd_check = check_reverse_fwd()
                if rev_fwd_check == "COMPLIANT":
                    print "\nSuccessfully enabled reverse path forwarding\n"
                    logging.info("\nSuccessfully enabled reverse path forwarding\n")
                else:
                    print "\nFailed to enable reverse path forwarding\n"
                    logging.error("\nFailed to enable reverse path forwarding\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of agent forwarding configuration'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                agent_fwdng()
                sys.stdout = oldstdout
                agt_fwd_check = check_sshd_config()
                if agt_fwd_check == "COMPLIANT":
                    print "\nSuccessfully disabled AgentForwarding\n"
                    logging.info("\nSuccessfully disabled AgentForwarding\n")
                else:
                    print "\nFailed to disable AgentForwarding\n"
                    logging.error("\nFailed to disable AgentForwarding\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of sticky bit enforcement for '
                              'system configuration file protection is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                sticky_bit()
                sys.stdout = oldstdout
                sticky_check = check_sticky_bit()
                if sticky_check == "COMPLIANT":
                    print "\nSuccessfully set sticky bit for recommended set of files\n"
                    logging.info("\nSuccessfully set sticky bit for recommended set of files\n")
                else:
                    print "\nFailed to set sticky bit for recommended set of files\n"
                    logging.error("\nFailed to set sticky bit for recommended set of files\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of disabled TcpForwarding for '
                              'SSH server communication is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                allow_tcp_forwarding()
                sys.stdout = oldstdout
                tcp_fwd_check = allowtcp_forwarding_check()
                if tcp_fwd_check == "COMPLIANT":
                    print "\nSuccessfully set AllowTcpForwarding to 'no'\n"
                    logging.info("\nSuccessfully set AllowTcpForwarding to 'no'\n")
                else:
                    print "\nFailed to set AllowTcpForwarding to 'no'\n"
                    logging.error("\nFailed to set AllowTcpForwarding to 'no'\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of disabled X11Forwarding for '
                              'SSH server communication is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                x11_forwarding()
                sys.stdout = oldstdout
                x11fwd_check = x11_forwarding_check()
                if x11fwd_check == "COMPLIANT":
                    print "\nSuccessfully set X11Forwarding to 'no'\n"
                    logging.info("\nSuccessfully set X11Forwarding to 'no'\n")
                else:
                    print "\nFailed to set X11Forwarding to 'no'\n"
                    logging.error("\nFailed to set X11Forwarding to 'no'\n")
                    flag_status = flag_status + 1
            if rec.startswith("Verification of disabled GatewayPorts for "
                              "SSH client communication is completed"):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                disable_gatewayports()
                sys.stdout = oldstdout
                gatewayports_verify = check_gatewayports_status()
                if gatewayports_verify == "COMPLIANT":
                    print "\nSuccessfully disabled GatewayPorts\n"
                    logging.info("\nSuccessfully disabled GatewayPorts\n")
                else:
                    print "\nFailed to disabled GatewayPorts\n"
                    logging.error("\nFailed to disabled GatewayPorts\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of sshHostKey configuration'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                enable_ssh_hostkey()
                sys.stdout = oldstdout
                sshhostkey_check = check_ssh_hostkey_status()
                if sshhostkey_check == "COMPLIANT":
                    print "\nSuccessfully activated ssh host key dns verification\n"
                    logging.info("\nSuccessfully activated ssh host key dns verification\n")
                else:
                    print "\nFailed to activate ssh host key dns verification\n"
                    logging.error("\nFailed to activate ssh host key dns verification\n")
                    flag_status = flag_status + 1
            if rec.startswith("Verification of disabled autoconf (dynamic IP assignment) "
                              "feature, for IPv6 communication is completed"):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                disable_ipv6_autoconf()
                sys.stdout = oldstdout
                ipv6autoconf_check = check_ipv6_autoconf_status()
                if ipv6autoconf_check == "COMPLIANT":
                    print "\nSuccessfully disabled Ipv6 autoconf\n"
                    logging.info("\nSuccessfully disabled Ipv6 autoconf\n")
                else:
                    print "\nFailed to disabled Ipv6 autoconf\n"
                    logging.error("\nFailed to disabled Ipv6 autoconf\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of file permissions according to the recommendation \
is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                set_permission()
                sys.stdout = oldstdout
                permission_check = verify_permissions()
                if permission_check == "COMPLIANT":
                    print "\nSuccessfully set strong file permissions\n"
                    logging.info("\nSuccessfully set strong file permissions\n")
                else:
                    print "\nFailed to set strong file permissions\n"
                    logging.error("\nFailed to set strong file permissions\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of inactive password lock is 30 days is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                set_inactive()
                sys.stdout = oldstdout
                inactive_days_check = check_inactive()
                if inactive_days_check == "COMPLIANT":
                    print "\nSuccessfully verified Inactive User Account Lock\n"
                    logging.info("\nSuccessfully verified Inactive User Account Lock\n")
                else:
                    print "\nFailed to verify Inactive User Account Lock\n"
                    logging.error("\nFailed to verify Inactive User Account Lock\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of disabled bogus ICMP responses is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                icmp_responses()
                sys.stdout = oldstdout
                icmp_response_check = check_icmp_status()
                if icmp_response_check == "COMPLIANT":
                    print "\nSuccessfully disabled bogus ICMP responses!\n"
                    logging.info("\nSuccessfully disabled bogus ICMP responses\n")
                else:
                    print "\nFailed to disabled bogus ICMP responses\n"
                    logging.error("\nFailed to disabled bogus ICMP responses\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of reverse path filtering is configured'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                enable_rev_path_filter()
                sys.stdout = oldstdout
                reverse_path_check = check_rev_path()
                if reverse_path_check == "COMPLIANT":
                    print "\nSuccessfully enabled reverse path filtering\n"
                    logging.info("\nSuccessfully enabled reverse path filtering\n")
                else:
                    print "\nFailed to enable reverse path filtering\\n"
                    logging.error("\nFailed to enable reverse path filtering\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of enabling suspicious packets is configured'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                enable_packets()
                sys.stdout = oldstdout
                suspicious_packet_check = check_packets()
                if suspicious_packet_check == "COMPLIANT":
                    print "\nSuccessfully ensured suspicious packets are logged\n"
                    logging.info("\nSuccessfully ensured suspicious packets are logged\n")
                else:
                    print "\nFailed to ensure suspicious packets are logged\n"
                    logging.error("\nFailed to ensure suspicious packets are logged\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of disabled Secure ICMP redirects is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                disable_secure()
                sys.stdout = oldstdout
                secure_icmp_check = check_secure_icmp()
                if secure_icmp_check == "COMPLIANT":
                    print "\nSuccessfully disabled secure ICMP redirects\n"
                    logging.info("\nSuccessfully disabled secure ICMP redirects\n")
                else:
                    print "\nFailed to disabled secure ICMP redirects\n"
                    logging.error("\nFailed to disabled secure ICMP redirects\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of not accepting Ipv6 router '
                              'advertisements is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                disable_ipv6_adv()
                sys.stdout = oldstdout
                ipv6_adv_check = check_ipv6_adv()
                if ipv6_adv_check == "COMPLIANT":
                    print "\nSuccessfully ensured Ipv6 router advertisements are not accepted\n"
                    logging.info("\nSuccessfully ensured Ipv6 router advertisements "
                                 "are not accepted\n")
                else:
                    print "\nFailed to ensure Ipv6 router advertisements are not accepted\n"
                    logging.error("\nFailed to ensure Ipv6 router advertisements "
                                  "are not accepted\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of enable TCP SYN cookies is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                enable_tcp_syncookies()
                sys.stdout = oldstdout
                tcp_syncookies_check = check_tcp_syncookies()
                if tcp_syncookies_check == "COMPLIANT":
                    print "\nSuccessfully enabled TCP SYN cookies\n"
                    logging.info("\nSuccessfully enabled TCP SYN cookies\n")
                else:
                    print "\nFailed to enable TCP SYN cookies\n"
                    logging.error("\nFailed to enable TCP SYN cookies\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of root PATH integrity is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                verify_path()
                sys.stdout = oldstdout
                integrity_path_check = check_integrity()
                if integrity_path_check == "COMPLIANT":
                    print "\nSuccessfully verified root PATH integrity\n"
                    logging.info("\nSuccessfully verified root PATH integrity\n")
                else:
                    print "\nFailed to verify root PATH integrity\n"
                    logging.error("\nFailed to verify root PATH integrity\n")
                    flag_status = flag_status + 1
            if rec.startswith('Verification of su restriction is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                restrict_su_command()
                sys.stdout = oldstdout
                su_restriction_check = check_restriction()
                if su_restriction_check == "COMPLIANT":
                    print "\nSuccessfully verified su restriction\n"
                    logging.info("\nSuccessfully verified su restriction\n")
                else:
                    print "\nFailed to verify su restriction\n"
                    logging.error("\nFailed to verify su restriction\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of number of authentication attempts permitted'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                set_maxauth()
                sys.stdout = oldstdout
                set_maxauth_check = check_maxauthtries()
                if set_maxauth_check == "COMPLIANT":
                    print "\nSuccessfully set maxauthtries value to '4'\n"
                    logging.info("\nSuccessfully set maxauthtries value to '4'\n")
                else:
                    print "\nFailed to set maxauthtries value to '4'\n"
                    logging.error("\nFailed to set maxauthtries value to '4'\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of strong Key Exchange Algorithms according to the \
recommendation is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                add_kex()
                sys.stdout = oldstdout
                kex_check = check_kex()
                if kex_check == "COMPLIANT":
                    print "\nSuccessfully set strong Key Exchange algorithms\n"
                    logging.info("\nSuccessfully set strong Key Exchange algorithms\n")
                else:
                    print "\nFailed to set strong Key Exchange algorithms\n"
                    logging.error("\nFailed to set Key Exchange algorithms\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of SSH idle session timeout according to the \
recommendation is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ssh_timeout()
                sys.stdout = oldstdout
                ssh_timeout_check = check_sshtimeout()
                if ssh_timeout_check == "COMPLIANT":
                    print "\nSuccessfully set SSH idle timeout session\n"
                    logging.info("\nSuccessfully set SSH idle timeout session\n")
                else:
                    print "\nFailed to set SSH idle timeout session\n"
                    logging.error("\nFailed to set SSH idle timeout session\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verifies the maximum number of concurrent '
                              'unauthenticated connections permitted'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                set_maxstart()
                sys.stdout = oldstdout
                set_maxstart_check = check_maxstartup()
                if set_maxstart_check == "COMPLIANT":
                    print "\nSuccessfully set Maxstartups value\n"
                    logging.info("\nSuccessfully set Maxstartups value\n")
                else:
                    print "\nFailed to set Maxstartups value\n"
                    logging.error("\nFailed to set Maxstartups value\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of ensure SSH permit user environment '
                              'is disabled is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                disable_ssh_userenvironment()
                sys.stdout = oldstdout
                ssh_userenvironment_check = check_ssh_userenvironment()
                if ssh_userenvironment_check == "COMPLIANT":
                    print "\nSuccessfully collected SSH permit user environment is disabled!\n"
                    logging.info("\nSuccessfully collected SSH permit user "
                                 "environment is disabled!")
                else:
                    print "\nFailed to collect SSH permit user environment is disabled!\n"
                    logging.error("\nFailed to collect SSH permit user environment is disabled!\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of ensure SSH permit empty '
                              'passwords is disabled is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                disable_ssh_emptypasswords()
                sys.stdout = oldstdout
                ssh_emptypasswords_check = check_ssh_emptypasswords()
                if ssh_emptypasswords_check == "COMPLIANT":
                    print "\nSuccessfully collected SSH permit empty passwords is disabled!\n"
                    logging.info("\nSuccessfully collected SSH permit empty passwords "
                                 "is disabled!")
                else:
                    print "\nFailed to collect SSH permit empty passwords is disabled!\n"
                    logging.error("\nFailed to collect SSH permit empty passwords is disabled!\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of enable SSH ignoreRhosts is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                enable_ignorerhosts()
                sys.stdout = oldstdout
                ignorerhosts_check = check_ignorerhosts()
                if ignorerhosts_check == "COMPLIANT":
                    print "\nSuccessfully enabled SSH ignoreRhosts\n"
                    logging.info("\nSuccessfully enabled SSH ignoreRhosts")
                else:
                    print "\nFailed to enable SSH ignoreRhosts\n"
                    logging.error("\nFailed to enable SSH ignoreRhosts\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of disabled SSH hostbasedAuthentication is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                disable_hostbased_authentication()
                sys.stdout = oldstdout
                hostbasedauthentication_check = check_hostbased_authentication()
                if hostbasedauthentication_check == "COMPLIANT":
                    print "\nSuccessfully disabled SSH hostbasedAuthentication\n"
                    logging.info("\nSuccessfully disabled SSH hostbasedAuthentication")
                else:
                    print "\nFailed to disable SSH hostbasedAuthentication\n"
                    logging.error("\nFailed to disable SSH hostbasedAuthentication\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of the changes to system administration '
                              'scope (sudoers) are collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                sys_admin_scope()
                sys.stdout = oldstdout
                sys_admin_scope_check = check_sys_admin_scope()
                if sys_admin_scope_check == "COMPLIANT":
                    print "\nSuccessfully set changes to system administration scope " \
                          "(sudoers) are collected is completed\n"
                    logging.info("\nSuccessfully set changes to system administration scope "
                                 "(sudoers) are collected is completed\n")
                else:
                    print "\nFailed to set changes to system administration scope " \
                          "(sudoers) are collected is completed\n"
                    logging.error("\nFailed to set changes to system administration scope "
                                  "(sudoers) are collected is completed\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of events that modify user/group '
                              'information are collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                user_group_info()
                sys.stdout = oldstdout
                user_group_info_check = check_user_group_info()
                if user_group_info_check == "COMPLIANT":
                    print "\nSuccessfully set the events that modify user/group " \
                          "information are collected is completed\n"
                    logging.info("\nSuccessfully set the events that modify user/group "
                                 "information are collected is completed\n")
                else:
                    print "\nFailed to set the events that modify user/group " \
                          "information are collected is completed\n"
                    logging.error("\nFailed to set the events that modify user/group "
                                  "information are collected is completed\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of successful file system mounts '
                              'are collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                system_mount()
                sys.stdout = oldstdout
                system_mount_check = check_mounts()
                if system_mount_check == "COMPLIANT":
                    print "\nSuccessfully verified file system mounts are collected\n"
                    logging.info("\nSuccessfully verified file system mounts are collected\n")
                else:
                    print "\nFailed to verify system mounts are collected\n"
                    logging.error("\nFailed to verify system mounts are collected\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of unauthorized unsuccessful '
                              'file access attempts are collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                file_auth()
                sys.stdout = oldstdout
                file_auth_check = check_file_auth()
                if file_auth_check == "COMPLIANT":
                    print "\nSuccessfully verified unsuccessful unauthorized file " \
                          "access attempts are collected\n"
                    logging.info("\nSuccessfully verified unsuccessful unauthorized "
                                 "file access attempts are collected\n")
                else:
                    print "\nFailed to verify unsuccessful unauthorized " \
                          "file access attempts are collected\n"
                    logging.error("\nFailed to verify unsuccessful unauthorized "
                                  "file access attempts are collected\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of discretionary access control permission '
                              'modification events are collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                disec_access()
                sys.stdout = oldstdout
                disec_access_check = check_disec_access()
                if disec_access_check == "COMPLIANT":
                    print "\nSuccessfully verified discretionary access control " \
                          "permission modification events are collected\n"
                    logging.info("\nSuccessfully verified discretionary access control "
                                 "permission modification events are collected\n")
                else:
                    print "\nFailed to verify discretionary access control " \
                          "permission modification events are collected\n"
                    logging.error("\nFailed to verify discretionary access "
                                  "control permission modification events are collected\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of system administrator command executions '
                              '(sudo) are collected for 64 bit systems'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                sys_admin_cmd()
                sys.stdout = oldstdout
                sys_admin_cmd_check = check_sys_admin_cmd()
                if sys_admin_cmd_check == "COMPLIANT":
                    print "\nSuccessfully verified system administrator command executions " \
                          "(sudo) are collected\n"
                    logging.info("\nSuccessfully verified system administrator "
                                 "command executions (sudo) are collected\n")
                else:
                    print "\nFailed to verify system administrator command " \
                          "executions (sudo) are collected\n"
                    logging.error("\nFailed to system administrator command "
                                  "executions (sudo) are collected\n")

            if rec.startswith('Verification of system administrator '
                              'command executions (sudo) are collected'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ensure_system_access()
                sys.stdout = oldstdout
                system_access_check = check_system_access()
                if system_access_check == "COMPLIANT":
                    print "\nSuccessfully collected modified systems mandatory access controls\n"
                    logging.info("\nSuccessfully collected modified systems "
                                 "mandatory access controls\n")
                else:
                    print "\nFailed to collect modified systems mandatory access controls\n"
                    logging.error("\nFailed to collect modified systems "
                                  "mandatory access controls\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of modified date and time '
                              'information are collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ensure_date_time_info()
                sys.stdout = oldstdout
                date_time_info_check = check_date_time_info()
                if date_time_info_check == "COMPLIANT":
                    print "\nSuccessfully collected modified date and time information\n"
                    logging.info("\nSuccessfully collected modified date and time information")
                else:
                    print "\nFailed to collect modified date and time information\n"
                    logging.error("\nFailed to collect modified date and time information\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of modified systems network '
                              'environment are collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ensure_system_network()
                sys.stdout = oldstdout
                system_network_check = check_system_network()
                if system_network_check == "COMPLIANT":
                    print "\nSuccessfully collected modified systems network environment\n"
                    logging.info("\nSuccessfully collected modified systems network environment")
                else:
                    print "\nFailed to collect modified systems network environment\n"
                    logging.error("\nFailed to collect modified systems network environment\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of file deletion events are collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ensure_file_deletion()
                sys.stdout = oldstdout
                file_deletion_check = check_file_deletion()
                if file_deletion_check == "COMPLIANT":
                    print "\nSuccessfully collected file deletion events\n"
                    logging.info("\nSuccessfully collected file deletion events")
                else:
                    print "\nFailed to collect file deletion events\n"
                    logging.error("\nFailed to collect file deletion events\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of kernel module loading and unloading are \
collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                ensure_kernel_module()
                sys.stdout = oldstdout
                kernel_module_check = check_kernel_module()
                if kernel_module_check == "COMPLIANT":
                    print "\nSuccessfully collected kernel module loading and unloading\n"
                    logging.info("\nSuccessfully collected kernel loading and unloading")
                else:
                    print "\nFailed to collect kernel module loading and unloading\n"
                    logging.error("\nFailed to collect kernel module loading and unloading\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of audit configuration is immutable is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                immutable_auditconf()
                sys.stdout = oldstdout
                immutable_auditconf_check = check_auditconf_immutable()
                if immutable_auditconf_check == "COMPLIANT":
                    print "\nSuccessfully verified audit configuration is immutable\n"
                    logging.info("\nSuccessfully verified audit configuration is immutable\n")
                else:
                    print "\nFailed to verify audit configuration is immutable\n"
                    logging.error("\nFailed to verify audit configuration is immutable\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of use of privileged commands is '
                              'collected is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                user_priviliged_cmd()
                sys.stdout = oldstdout
                user_priviliged_cmd_check = check_user_privileged_cmd()
                if user_priviliged_cmd_check == "COMPLIANT":
                    print "\nSuccessfully verified use of privileged commands is collected\n"
                    logging.info("\nSuccessfully verified use of privileged "
                                 "commands is collected\n")
                else:
                    print "\nFailed to verify use of privileged commands is collected\n"
                    logging.error("\nFailed to verify use of privileged commands is collected\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of sudo log rotation policy  '
                              'is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                sudo_log()
                sys.stdout = oldstdout
                sudo_log_check = verify_sudo_log()
                if sudo_log_check == "COMPLIANT":
                    print "\nSuccessfully verified sudo log rotation policy\n"
                    logging.info("\nSuccessfully verified sudo log rotation policy\n")
                else:
                    print "\nFailed to verify sudo log rotation policy\n"
                    logging.error("\nFailed to verify sudo log rotation policy\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of disabling root user switching '
                              'is completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                sudo_switch()
                sys.stdout = oldstdout
                disable_root_switch = verify_disable_root_switch()
                if disable_root_switch == "COMPLIANT":
                    print "\nSuccessfully verified disabling of root user switching\n"
                    logging.info("\nSuccessfully verified disabling of root user switching\n")
                else:
                    print "\nFailed to verify disabling of root user switching\n"
                    logging.error("\nFailed to verify disabling of root user switching\n")
                    flag_status = flag_status + 1

            if rec.startswith('Verification of consolidating audit logs completed'):
                nullwrite = NullWriter()
                oldstdout = sys.stdout
                sys.stdout = nullwrite
                get_automated_audit_cron()
                sys.stdout = oldstdout
                logout_check = verify_audit_automate_cron()
                if logout_check == "COMPLIANT":
                    print "\nSuccessfully set coinsolidation of audit logs\n"
                    logging.info("\nSuccessfully set coinsolidation of audit logs\n")
                else:
                    print "\nFailed to set coinsolidation of audit logs\n"
                    logging.error("\nFailed to set coinsolidation of audit logs\n")
                    flag_status = flag_status + 1
#       ------------------------------------------------------------------------------
#       Verify the pre and post patch node hardening configuration.
#       ------------------------------------------------------------------------------
#        print "\nCapturing the compliance report output...\n"
#        os.system("/ericsson/security/compliance/NH_Compliance.py > \
#/ericsson/security/compliance/Reports/Compliance_Report_1.txt")
#        try:
#            output = subprocess.check_output("diff /ericsson/security/compliance/Reports/"
#                                             "Compliance_Report.txt /ericsson/security/"
#                                             "compliance/Reports/Compliance_Report_1.txt",
#                                             shell=True, stderr=subprocess.STDOUT)
#        except subprocess.CalledProcessError as e:
#            output = True
#            if e.returncode != 1:
#            	logging.error("\33[31m RuntimeError \033[0m: command '{}' return"
#                              " with error (code {}): {}".format(e.cmd, e.returncode, e.output))
#                print "\33[31m Error occurred during post patch verification, " \
#                      "the node hardening compliance check has failed\033[0m. " \
#                      "Please refer to the \033[93m/ericsson/security/log/restore" \
#                      "_NH_post_patch/\033[00m directory for detailed logs."
#                sys.exit(1)

#        if flag_status != 0:
#            return "NON-COMPLIANT"
#        else:
#            return "COMPLIANT"

        return flag_status

def cleanup_on_exit():
    """This function defines clean up on exit"""
    os.system("rm -rf /ericsson/security/compliance/*.pyc")
    os.system("rm -rf /ericsson/security/bin/*.pyc")
    os.system("rm -rf /ericsson/security/audit/*.pyc")
if __name__ == '__main__':
    user_verification()
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # blocks tftp port(69) if it is open.
    block_tftp_if_present()
    remove_deprecated_ports_if_present("MWS")
    remove_deprecated_ports_if_present("ENIQ")
    compliant_status = harden_server()
    if compliant_status == 0:
        print "\n\x1b[32m\"SUCCESSFULLY RESTORED COMPLIANT STATUS OF FEATURES !!!\"\x1b[0m\n"
        logging.info("\nSUCCESSFULLY RESTORED COMPLIANT STATUS OF FEATURES !!!\n")
        cleanup_on_exit()
        os.system("rm -rf /ericsson/security/compliance/Reports/*.txt")
        print "Script logs are saved at : \033[93m/ericsson/security/log/Restore_NH_post" \
              "_patch/\033[00m directory!"
        reboot()
    else:
        print "\n\x1b[31m\"UNABLE TO RESTORE COMPLIANT STATUS OF FEATURES!!!\"\x1b[0m\n"
        logging.error("\nUNABLE TO RESTORE COMPLIANT STATUS OF FEATURES!!!\n")
        print "Script logs are saved at : \033[93m/ericsson/security/log/Restore_NH_" \
              "post_patch/\033[00m directory!"
        cleanup_on_exit()
        exit(1)
