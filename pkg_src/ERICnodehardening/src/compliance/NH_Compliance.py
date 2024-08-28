#!/usr/bin/python

"""This script encapsulates all the compliance check for node hardening"""

import os
import sys
import logging
import time
import subprocess
import signal

from verify_selinux import check_sestatus
from verify_firewall import check_firewall
from verify_umask import check_umask
from verify_cipher import check_cipher
from verify_password_policy import check_password_complexity
from verify_password_age import check_password_aging
from verify_autologout import check_autologout
from verify_listing_rpms import check_listing_rpms
from cron_log_audit import cron_log_cmp
from grace_time_audit import grace_cmp
from restrict_at_audit import at_restrict_cmp
from verify_tcp_wrappers import tcp_cmp
from restrict_cron_audit import cron_restrict_cmp
from verify_ssh_login import check_ssh_login
from verify_mask import ctrl_alt_del
from verify_icmp_config import icmp_check
from verify_ssh_v2 import ssh_protocol_check
from verify_static_ip import dhcp_staticip_check
from verify_suid import root_suid_check
from verify_icmp import check_icmp
from verify_motd_banner import check_motd_banner
from verify_reverse_fwd import check_reverse_fwd
from verify_SR import check_sr_status
from verify_sshd_banner import check_banner
from verify_agent_fwdng import check_sshd_config
from verify_sticky_bit import check_sticky_bit
from verify_AllowTCPForwording import allowtcp_forwarding_check
from verify_X11Forwarding import x11_forwarding_check
from verify_GatewayPorts import check_gatewayports_status
from verify_sshHostKeyVerification import check_ssh_hostkey_status
from verify_Ipv6_autoconf import check_ipv6_autoconf_status
from verify_audit import check_audit_config
from post_nh_checks import start_post_check
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
from verify_user_group_info import check_user_group_info
from verify_sys_admin_scope import check_sys_admin_scope
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
from verify_session_info import verify_audit_session_info
from verify_login_logout_events import verify_login_logout
from verify_sudologs_rotate import verify_sudo_log
from verify_disable_root_switch import verify_disable_root_switch
from verify_audit_automate_cron import verify_audit_automate_cron

sys.path.insert(0, '/ericsson/security/audit')
from NH_audit import audit
os.environ['TERM'] = 'xterm'

def check_status(status):
    """This function verifies provides the color defenition for the status to be displayed"""
    if status == "COMPLIANT":
        return u"[\u001b[32mCOMPLIANT\u001b[0m]"
    else:
        return u"[\u001b[31m%s\u001b[0m]" % status

def main():
    """This function encapsulates all the compliance check for node hardening"""
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_Compliance_logs'
    os.system("mkdir -p /ericsson/security/log/Compliance_Logs")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Compliance_Logs/%s" % fname,
                        format=format_str)

    log_file = '/ericsson/security/log/Compliance_Logs/%s' % fname
    open(log_file, 'a').write('*'*95+'\n')
    host = subprocess.check_output('hostname', shell=True).replace('\n', '')
    open(log_file, 'a').write(host+' '*(95-len(host)-len(timestr))+timestr+'\n')
    open(log_file, 'a').write('NH_Compliance.py\n')
    open(log_file, 'a').write('*'*95+'\n')

    auditstatus = check_audit_config()
    return_status = check_status(auditstatus)
    print "\nVerification of Audit Configuration completed\t\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of Audit Configuration completed\t\t\t\t\t%s', auditstatus)

    sestatus = check_sestatus()
    return_status = check_status(sestatus)
    print "\nVerification of SELinux status completed\t\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of SELinux status completed\t\t\t\t\t\t%s', sestatus)

    fdstatus = check_firewall()
    return_status = check_status(fdstatus)
    print "\nVerification of firewall status completed\t\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of firewall status completed\t\t\t\t\t%s', fdstatus)

    umask_status = check_umask()
    return_status = check_status(umask_status)
    print "\nVerification of secure umask configuration completed\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of secure umask configuration completed\t\t\t\t\t\t\t%s', umask_status)

    cipher_status = check_cipher()
    return_status = check_status(cipher_status)
    print "\nVerification of strong ciphers and MAC for SSH " \
          "communication\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of strong ciphers and MAC for SSH communication\t\t\t%s',
                 cipher_status)

    complexity_status = check_password_complexity()
    return_status = check_status(complexity_status)
    print "Verification of password policy is completed\t\t\t\t\t\t\t\t%s\n" % return_status
    logging.info("Verification of password policy is completed\t\t\t\t\t%s", complexity_status)

    status_age = check_password_aging()
    return_status = check_status(status_age)
    print "\nVerification of password aging configuration " \
          "completed\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of password aging configuration completed\t\t\t\t%s', status_age)

    status_logout = check_autologout()
    return_status = check_status(status_logout)
    print "\nVerification of Automatic logout configuration " \
          "completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of Automatic logout configuration '
                 'completed\t\t\t\t%s', status_logout)

    status_rpm_file = check_listing_rpms()
    return_status = check_status(status_rpm_file)
    print "\nVerification of installed rpm list captured in /ericsson/security/log/rpm_logs\
\t\t\t\t%s" % return_status
    logging.info('Verification of installed rpm list captured in \
\n\t\t\t\t/ericsson/security/log/rpm_logs\t\t\t\t\t\t\t%s', status_rpm_file)

    status_logrotate = cron_log_cmp()
    return_status = check_status(status_logrotate)
    print "\nVerification of log rotation for /var/log files " \
          "completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of log rotation for /var/log files \
completed\t\t\t%s', status_logrotate)

    status_grace = grace_cmp()
    return_status = check_status(status_grace)
    print "\nVerification of Login grace time completed\t\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of Login grace time completed\t\t\t\t\t%s', status_grace)

    status_at = at_restrict_cmp()
    return_status = check_status(status_at)
    print "\nVerification of user access and management for at scheduler \
completed\t\t\t\t\t%s" % return_status
    logging.info('Verification of user access and management for at scheduler \
completed\t\t%s', status_at)

    status_cron = cron_restrict_cmp()
    return_status = check_status(status_cron)
    print "\nVerification of user access and management for cron scheduler \
completed\t\t\t\t\t%s" % return_status
    logging.info('Verification of user access and management for cron scheduler \
completed\t\t%s', status_cron)

    status_tcp_wrappers = tcp_cmp()
    return_status = check_status(status_tcp_wrappers)
    print "\nVerification of FTP access restriction completed\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of FTP access restriction '
                 'completed\t\t\t\t\t%s', status_tcp_wrappers)

    status_login = check_ssh_login()
    return_status = check_status(status_login)
    print "\nVerification of SSH access restriction is completed\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of SSH access restriction is completed\t\t\t\t%s', status_login)

    status_mask = ctrl_alt_del()
    return_status = check_status(status_mask)
    print "\nVerification of 'ctrl+alt+del' mask completed\t\t\t\t\t\t\t\t%s" % return_status
    logging.info("Verification of 'ctrl+alt+del' mask completed\t\t\t\t\t%s", status_mask)

    status_icmp = icmp_check()
    return_status = check_status(status_icmp)
    print "\nVerification of disabled ICMP broadcasts is completed\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of disabled ICMP broadcasts is completed\t\t\t\t%s', status_icmp)

    status_ssh_proto = ssh_protocol_check()
    return_status = check_status(status_ssh_proto)
    print "\nVerification of SSH v2 enforcement is completed\t\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of SSH v2 enforcement is completed\t\t\t\t\t%s', status_ssh_proto)

    ip_config = dhcp_staticip_check()
    return_status = check_status(ip_config)
    print "\nVerification of static IP configuration for IPv4 is " \
          "completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of static IP configuration for IPv4 is completed\t\t\t%s',
                 ip_config)

    status_suid = root_suid_check()
    return_status = check_status(status_suid)
    print "\nVerification of SUID files present on the system is " \
          "completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of SUID files present on the system is '
                 'completed\t\t\t%s', status_suid)

    status_icmp = check_icmp()
    return_status = check_status(status_icmp)
    print "\nVerification of disabled vulnerable ICMP types is " \
          "completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of disabled vulnerable ICMP types '
                 'is completed\t\t\t%s', status_icmp)

    status_motd = check_motd_banner()
    return_status = check_status(status_motd)
    print "\nVerification of post logon banner configuration is " \
          "completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of post logon banner configuration '
                 'is completed\t\t\t%s', status_motd)

    status_ssh = check_banner()
    return_status = check_status(status_ssh)
    print "\nVerification of pre logon banner configuration is " \
          "completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of pre logon banner configuration is '
                 'completed\t\t\t%s', status_ssh)

    status_sr = check_sr_status()
    return_status = check_status(status_sr)
    print "\nVerification of disabled source routing for IPv4 " \
          "communication is completed\t\t\t\t%s" % return_status
    logging.info('Verification of disabled source routing for IPv4 '
                 'communication is completed\t%s', status_sr)

    status_rev_fwd = check_reverse_fwd()
    return_status = check_status(status_rev_fwd)
    print "\nVerification of strict reverse path forwarding for IPv4 " \
          "communication is completed\t\t\t%s" % return_status
    logging.info('Verification of strict reverse path forwarding for '
                 'IPv4 communication is complete%s', status_rev_fwd)

    status_agt_fwd = check_sshd_config()
    return_status = check_status(status_agt_fwd)
    print "\nVerification of agent forwarding configuration\t\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of agent forwarding configuration\t\t\t\t\t%s', status_agt_fwd)

    status_sticky = check_sticky_bit()
    return_status = check_status(status_sticky)
    print "\nVerification of sticky bit enforcement for system configuration " \
          "file protection is completed\t\t%s" % return_status
    logging.info('Verification of sticky bit enforcement for system configuration file\
\n\t\t\t\t protection is completed\t\t\t\t\t\t\t%s', status_sticky)

    status_tcpfwd = allowtcp_forwarding_check()
    return_status = check_status(status_tcpfwd)
    print "\nVerification of disabled TcpForwarding for SSH server " \
          "communication is completed\t\t\t%s" % return_status
    logging.info('Verification of disabled TcpForwarding for SSH server '
                 'communication is completed\t%s', status_tcpfwd)

    status_x11_fwd = x11_forwarding_check()
    return_status = check_status(status_x11_fwd)
    print "\nVerification of disabled X11Forwarding for SSH server " \
          "communication is completed\t\t\t%s" % return_status
    logging.info('Verification of disabled X11Forwarding for SSH server '
                 'communication is completed\t%s', status_x11_fwd)

    status_gateway_ports = check_gatewayports_status()
    return_status = check_status(status_gateway_ports)
    print "\nVerification of disabled GatewayPorts for SSH client communication is \
completed\t\t\t\t%s" % return_status
    logging.info('Verification of disabled GatewayPorts for SSH client communication is \
completed\t%s', status_gateway_ports)

    status_sshhostkey = check_ssh_hostkey_status()
    return_status = check_status(status_sshhostkey)
    print "\nVerification of sshHostKey configuration\t\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of sshHostKey configuration\t\t\t\t\t\t%s', status_sshhostkey)

    status_ipv6_autoconf = check_ipv6_autoconf_status()
    return_status = check_status(status_ipv6_autoconf)
    print "\nVerification of disabled autoconf (dynamic IP assignment) feature, for \
IPv6 communication is completed\t%s" % return_status
    logging.info('Verification of disabled autoconf (dynamic IP assignment) feature, for \
\n\t\t\t\tIPv6 communication is completed\t\t\t\t\t\t\t%s', status_ipv6_autoconf)

    status_file_permission = verify_permissions()
    return_status = check_status(status_file_permission)
    print "\nVerification of file permissions according to the recommendation \
is completed\t\t\t\t%s" % return_status
    logging.info('Verification of file permissions according to the recommendation \
is completed\t%s', status_file_permission)

    status_inactive = check_inactive()
    return_status = check_status(status_inactive)
    print "\nVerification of Inactive User Account Lock \
is completed\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of Inactive User Account Lock \
is completed\t%s', status_inactive)

    status_icmp_responses = check_icmp_status()
    return_status = check_status(status_icmp_responses)
    print "\nVerification of disabled bogus ICMP responses " \
          "is completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of disabled bogus ICMP responses is '
                 'completed\t\t\t\t\t\t%s', status_icmp_responses)

    status_rev_path = check_rev_path()
    return_status = check_status(status_rev_path)
    print "\nVerification of reverse path filtering is configured\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of reverse path filtering is configured\t\t\t\t\t\t%s',
                 status_rev_path)

    status_packets = check_packets()
    return_status = check_status(status_packets)
    print "\nVerification of enabling suspicious packets " \
          "is configured\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of enabling suspicious packets is configured\t\t\t\t\t\t%s',
                 status_packets)

    status_secure_icmp = check_secure_icmp()
    return_status = check_status(status_secure_icmp)
    print "\nVerification of disabled Secure ICMP redirects is " \
          "completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of disabled Secure ICMP redirects is completed\t\t\t\t\t\t%s',
                 status_secure_icmp)

    status_ipv6_adv = check_ipv6_adv()
    return_status = check_status(status_ipv6_adv)
    print "\nVerification of not accepting Ipv6 router advertisements is \
completed\t\t\t\t\t%s" % return_status
    logging.info('Verification of not accepting Ipv6 router advertisements is \
completed\t\t\t\t\t%s', status_ipv6_adv)

    status_tcp_syncookies = check_tcp_syncookies()
    return_status = check_status(status_tcp_syncookies)
    print "\nVerification of enable TCP SYN cookies is completed\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of enable TCP SYN cookies is \
completed\t\t\t\t\t\t\t%s', status_tcp_syncookies)

    status_integrity = check_integrity()
    return_status = check_status(status_integrity)
    print "\nVerification of root PATH integrity \
is completed\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of root PATH integrity \
is completed\t%s', status_integrity)

    status_su_restriction = check_restriction()
    return_status = check_status(status_su_restriction)
    print "\nVerification of su restriction \
is completed\t\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of su restriction \
is completed\t%s', status_su_restriction)

    status_set_maxauth = check_maxauthtries()
    return_status = check_status(status_set_maxauth)
    print "\nVerification of number of authentication attempts " \
          "permitted\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of number of authentication attempts permitted\t\t\t\t\t%s',
                 status_set_maxauth)

    status_kex_algos = check_kex()
    return_status = check_status(status_kex_algos)
    print "\nVerification of strong Key Exchange Algorithms according to the recommendation \
is completed\t\t%s" % return_status
    logging.info('Verification of strong Key Exchange Algorithms according to the recommendation \
is completed\t%s', status_kex_algos)

    status_ssh_timeout = check_sshtimeout()
    return_status = check_status(status_ssh_timeout)
    print "\nVerification of SSH idle session timeout according to the recommendation \
is completed\t\t\t%s" % return_status
    logging.info('Verification of SSH idle session timeout according to the recommendation \
is completed\t\t\t%s', status_ssh_timeout)

    status_set_maxstart = check_maxstartup()
    return_status = check_status(status_set_maxstart)
    print "\nVerifies the maximum number of concurrent unauthenticated connections permitted \
\t\t\t%s" % return_status
    logging.info('\nVerifies the maximum number of concurrent unauthenticated connections \
permitted\t\t\t%s', status_set_maxstart)

    status_ssh_userenvironment = check_ssh_userenvironment()
    return_status = check_status(status_ssh_userenvironment)
    print "\nVerification of ensure SSH permit user environment is disabled is \
completed\t\t\t\t%s" % return_status
    logging.info('Verification of ensure SSH permit user environment is disabled is \
completed\t\t\t\t%s', status_ssh_userenvironment)

    status_ssh_emptypasswords = check_ssh_emptypasswords()
    return_status = check_status(status_ssh_emptypasswords)
    print "\nVerification of ensure SSH permit empty passwords is disabled is \
completed\t\t\t\t%s" % return_status
    logging.info('Verification of ensure SSH permit empty passwords is disabled is \
completed\t\t\t\t%s', status_ssh_emptypasswords)

    status_ignorerhosts = check_ignorerhosts()
    return_status = check_status(status_ignorerhosts)
    print "\nVerification of enable SSH ignoreRhosts is completed\t\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of enable SSH ignoreRhosts is \
completed\t\t\t\t\t\t\t%s', status_ignorerhosts)

    status_hostbasedauthentication = check_hostbased_authentication()
    return_status = check_status(status_hostbasedauthentication)
    print "\nVerification of disabled SSH hostbasedAuthentication is \
completed\t\t\t\t\t%s" % return_status
    logging.info('Verification of disabled SSH hostbasedAuthentication is \
completed\t\t\t\t\t%s', status_hostbasedauthentication)

    status_user_group_info = check_user_group_info()
    return_status = check_status(status_user_group_info)
    print "\nVerification of events that modify user/group information are collected \
is completed\t\t\t%s" % return_status
    logging.info('\nVerification of events that modify user/group information are collected \
is completed\t\t\t%s', status_user_group_info)

    status_sys_admin_scope = check_sys_admin_scope()
    return_status = check_status(status_sys_admin_scope)
    print "\nVerification of the changes to system administration scope (sudoers) are collected \
is completed\t\t%s" % return_status
    logging.info('\nVerification of the changes to system administration scope (sudoers) are '
                 'collected is completed\t\t\t%s', status_sys_admin_scope)

    status_system_mount = check_mounts()
    return_status = check_status(status_system_mount)
    print "\nVerification of successful file system mounts are collected " \
          "is completed\t\t\t\t%s" %return_status
    logging.info('Verification of system mounts are collected successfully is \
completed\t%s', status_system_mount)

    status_file_auth = check_file_auth()
    return_status = check_status(status_file_auth)
    print "\nVerification of unauthorized unsuccessful file access attempts " \
          "are collected is completed\t\t%s" %return_status
    logging.info('Verification of unauthorized file access attempts are collected is \
completed\t%s', status_file_auth)

    status_disec_access = check_disec_access()
    return_status = check_status(status_disec_access)
    print "\nVerification of discretionary access control permission modification " \
          "events are collected is completed \t%s" %return_status
    logging.info('Verification of system administrator command executions (sudo) are '
                 'collected is completed\t%s', status_disec_access)

    status_sys_admin_cmd = check_sys_admin_cmd()
    return_status = check_status(status_sys_admin_cmd)
    print "\nVerification of system administrator command " \
          "executions (sudo) are collected\t\t\t\t%s" %return_status
    logging.info('Verification of system administrator command executions (sudo) are collected is \
completed\t%s', status_sys_admin_cmd)
    status_system_access = check_system_access()
    return_status = check_status(status_system_access)
    print "\nVerification of systems mandatory access controls are collected is \
completed\t\t\t\t%s" % return_status
    logging.info('Verification of systems mandatory access controls are collected is \
completed\t\t\t\t\t%s', status_system_access)

    status_date_time_info = check_date_time_info()
    return_status = check_status(status_date_time_info)
    print "\nVerification of modified date and time information are collected is \
completed\t\t\t\t%s" % return_status
    logging.info('Verification of modified date and time information are collected is \
completed\t\t\t\t%s', status_date_time_info)

    status_system_network = check_system_network()
    return_status = check_status(status_system_network)
    print "\nVerification of modified systems network environment are collected is \
completed\t\t\t\t%s" % return_status
    logging.info('Verification of modified systems network environment are collected is \
completed\t\t\t\t%s', status_system_network)

    status_file_deletion = check_file_deletion()
    return_status = check_status(status_file_deletion)
    print "\nVerification of file deletion events are collected is \
completed\t\t\t\t\t\t%s" % return_status
    logging.info('Verification of file deletion events are collected is \
completed\t\t\t\t\t\t%s', status_file_deletion)

    status_kernel_module = check_kernel_module()
    return_status = check_status(status_kernel_module)
    print "\nVerification of kernel module loading and unloading are collected is \
completed\t\t\t\t%s" % return_status
    logging.info('Verification of kernel module loading and unloading are collected is \
completed\t\t\t\t%s', status_kernel_module)

    status_auditconf_immutable = check_auditconf_immutable()
    return_status = check_status(status_auditconf_immutable)
    print "\n\nVerification of audit configuration is immutable is " \
          "completed\t\t\t\t\t\t%s" %return_status
    logging.info('Verification of audit configuration is immutable is \
completed\t%s', status_auditconf_immutable)

    status_user_privileged_cmd = check_user_privileged_cmd()
    return_status = check_status(status_user_privileged_cmd)
    print "\n\nVerification of use of privileged commands is " \
          "collected is completed\t\t\t\t\t%s" %return_status
    logging.info('Verification of use of privileged commands is collected is \
completed\t%s', status_user_privileged_cmd)

    status_audit_session = verify_audit_session_info()
    return_status = check_status(status_audit_session)
    print "\n\nVerification of audit session information is " \
          "completed\t\t\t\t\t\t\t%s" %return_status
    logging.info('Verification of audit session information is \
completed\t%s', status_audit_session)

    status_audit_login_logout = verify_login_logout()
    return_status = check_status(status_audit_login_logout)
    print "\n\nVerification of audit login and logout information is " \
          "completed\t\t\t\t\t\t%s" %return_status
    logging.info('Verification of login and logout information is \
completed\t%s', status_audit_login_logout)

    status_sudo_log_rotate = verify_sudo_log()
    return_status = check_status(status_sudo_log_rotate)
    print "\n\nVerification of sudo log rotation policy " \
          "is completed\t\t\t\t\t\t\t%s" %return_status
    logging.info('Verification of sudo log rotation policy is \
completed\t%s', status_sudo_log_rotate)

    status_disable_root_switch = verify_disable_root_switch()
    return_status = check_status(status_disable_root_switch)
    print "\n\nVerification of disabling root user switching " \
          "is completed\t\t\t\t\t\t%s" %return_status
    logging.info('Verification of disabling root user switching is \
completed\t%s', status_disable_root_switch)

    status_audit_automate_cron = verify_audit_automate_cron()
    return_status = check_status(status_audit_automate_cron)
    print "\n\nVerification of consolidating audit logs " \
          "completed\t\t\t\t\t\t\t%s" %return_status
    logging.info('Verification of consolidating audit logs is \
completed\t%s', status_audit_automate_cron)

    logging.info('Starting log collection of Node hardening Post-Check')
    start_post_check()
    print "Collected specific service status in post_check_data.log file for " \
          "troubleshooting purposes."
    logging.info('Finished collecting Node hardening Post-Check')
    audit()
    logging.info('Audit details will be logged to SGID.txt,SUID.txt,\
files_full_perm.txt,dir_full_perm.txt,\n\t\t\t\tfiles_no_owner.txt,check_home_dir_perm.txt,\
compare_dir.txt,root_perm.txt files, analyse logs for more details')
    open(log_file, 'a').write('*'*95+'\nLog file location:\n')
    open(log_file, 'a').write(log_file+'\n'+'*'*95+'\n')
    os.system("rm -rf /ericsson/security/compliance/*.pyc")
    os.system("rm -rf /ericsson/security/bin/*.pyc")
    print "Please refer to 4/1543-CNA 403 2613 ENIQ-S Nodehardening Guide document \
for the details on the impact of each of the non-compliant points\n"
    os.chmod(log_file, 0o440)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    main()
