#!/usr/bin/python
"""
# ******************************************************************************
# Test Case For NH                               SCRIPT
# ******************************************************************************
#
# ******************************************************************************
# Name      : TC_Apply_NH.py
# Purpose   : This script checks Test Cases for all the Node Hardening procedures
#             sequentially.
# ******************************************************************************
"""

import time
import os
import logging
import commands as c

from TC_add_cipher import cipher
from TC_autologout import logout
from TC_Check_SE_Status import TC_se
from TC_configure_icmp import icmp_configure
from TC_configure_sshd import Agent
from TC_disable_access_suid import check_suid
from TC_disable_AllowTcpForwarding import disable_TCP
from TC_disable_GatewayPorts import disable_Gateway
from TC_disable_icmp_broadcast import icmp_broad
from TC_disable_Ipv6_autoconf import disable_Ipv6
from TC_disable_X11Forwarding import disable_X11
from TC_enable_firewall import firewall
from TC_enable_sshHostKey_verification import enable_sshHostKey
from TC_enable_ssh_login import SSH
from TC_enable_ssh_proto_v2 import version
from TC_enable_sticky_bit import sticky
from TC_mask_alt_ctrl_del import masking
from TC_restrict_at import permit_at
from TC_restrict_cron import permit_cron
from TC_reverse_fwd import reverse
from TC_set_cron_log import set_cron
from TC_set_grace_time import grace
from TC_set_motd_banner import afterlogin
from TC_set_password_aging import pass_age
from TC_set_password_policy import password
from TC_set_ssh_banner import Banner
from TC_set_umask import mask
from TC_tcp_wrappers import FTP
from TC_verify_ip_config import ip_conf
from TC_Verify_NH_Config import NH_conf
from TC_verify_static_ip_config import static
from TC_EniqSecuritySentinel import sentinal_check
from TC_audit_config import audit_testing
from TC_set_file_permissions import check_permissions
from TC_set_inactive_days import inactive_days
from TC_disable_secure_icmp import disable_secure_icmp
from TC_enable_suspicious_packets import enable_suspicious_packets
from TC_disable_icmp_responses import disable_icmp_responses
from TC_disable_ipv6_advertisements import disable_ipv6_advertisements
from TC_enable_reverse_path_filter import enable_reverse_path_filter
from TC_enable_tcp_syncookies import enable_tcp_syncookies
from TC_disable_SR import disable
from TC_add_keyexchng_algorithm import add_keyexchng_algorithm
from TC_enforce_ssh_timeout import enforce_ssh_timeout
from TC_set_maxauthtries import set_maxauthtries
from TC_set_path_integrity import set_path_integrity
from TC_su_restriction import su_restriction
from TC_set_maxstartups import set_maxstartups
from TC_ensure_user_group_info import ensure_user_group_info
from TC_ensure_sys_admin_scope import ensure_sys_admin_scope
from TC_ensure_sys_admin_cmd import ensure_sys_admin_cmd
from TC_ensure_kernel_module import ensure_kernel_module
from TC_ensure_file_deletion import ensure_file_deletion
from TC_ensure_file_auth import ensure_file_auth
from TC_ensure_date_time_info import ensure_date_time
from TC_enforce_system_mount import enforce_system_mount
from TC_ensure_system_access import ensure_system_access
from TC_ensure_user_priviliged_cmd import ensure_user_priviliged_cmd
from TC_ensure_system_network import ensure_system_network
from TC_discretionary_access_control import discretionary_access_control
from TC_disable_hostbasedAuthentication import disable_hostbasedAuthentication
from TC_disable_ssh_emptypasswords import disable_ssh_emptypasswords
from TC_disable_ssh_userenvironment import disable_ssh_userenvironment
from TC_enable_ignoreRhosts import enable_ignoreRhosts

from NTC_Check_SE_Status import NTC_se
from NTC_configure_icmp import check_icmp_configure
from NTC_configure_sshd import negative_sshd
from NTC_disable_AllowTcpForwarding import enable_TCP
from NTC_disable_GatewayPorts import enable_Gateway
from NTC_disable_X11Forwarding import enable_X11
from NTC_enable_sshHostKey_verification import disable_sshHostKey
from NTC_enable_firewall import change_firewall
from NTC_autologout import change_logout_time
from NTC_disable_access_suid import change_suid
from NTC_enable_pwd_aging import set_passwd_aging
from NTC_enable_sticky_bit import change_sticky
from NTC_restrict_at import update_at
from NTC_restrict_cron import update_cron
from NTC_tcp_wrappers import disable_FTP
from NTC_Verify_NH_Config import check_NH_conf
from NTC_set_file_permissions import check_weak_permissions
from NTC_set_inactive_days import ntc_inactive_days
from NTC_disable_secure_icmp import secure_icmp
from NTC_enable_suspicious_packets import log_suspicious_packets
from NTC_disable_icmp_responses import bogus_icmp_responses
from NTC_disable_ipv6_advertisements import ipv6_advertisements
from NTC_enable_reverse_path_filter import reverse_path_filter
from NTC_enable_tcp_syncookies import tcp_syncookies
from NTC_disable_SR import disable_SR
from NTC_enforce_ssh_timeout import ntc_enforce_ssh_timeout
from NTC_set_grace_time import ntc_set_grace_time
from NTC_set_maxauthtries import maxauthtries
from NTC_su_restriction import ntc_su_restriction
from NTC_set_maxstartups import ntc_set_maxstartups
from NTC_disable_hostbasedAuthentication import ssh_hostbasedAuthentication
from NTC_disable_ssh_emptypasswords import ssh_emptypasswords
from NTC_disable_ssh_userenvironment import ssh_userenvironment
from NTC_enable_ignoreRhosts import ignoreRhosts


def Apply_NH_TC():

    logging.info('Started the TC of TC_EniqSecuritySentinel.py')
    print "\n\n******Checking Sentinel hardening is done or not******"
    output = sentinal_check()
    print "Result : %s" % output
    if output == "SUCCESS" : print "******Finished the TC of TC_EniqSecuritySentinel.py******"
    logging.info('Finished the TC of TC_EniqSecuritySentinel.py\n')

    logging.info('Started the TC of TC_audit_config')
    print "\n\n******Checking audit log******"
    output = audit_testing()
    print "Result : %s" % output
    if output == "SUCCESS" : print "******Finished the TC of TC_audit_config******"
    logging.info('Finished the TC of TC_audit_config\n')

    logging.info('Started the TC of enforce_selinux.py')
    print "\n\n******Checking SE Linux status******"
    output = TC_se()
    print "Result : %s" % output
    if output == "SUCCESS" : print "******Finished the TC of enforce_selinux.py******"
    logging.info('Finished the TC of enforce_selinux.py\n')

    logging.info('Started the TC of set_password_policy.py')
    print "\n\n******Checking password policies are set or not ***********"
    output = password()
    print "Result : %s" % output
    if output == "SUCCESS" : print "****** Password Policies set successfully********"
    logging.info('Finished the TC of set_password_policy.py\n')

    logging.info('Started the TC of enablee_ssh_login.py')
    print "\n\n************Checking SSH login users are Allowed or Not*************"
    output = SSH()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************SSH Login allowed for users**********"
    logging.info('Finished the TC of enable_ssh_login.py\n')

    logging.info('Started the TC of set_autologout.py')
    print "\n\n******Checking Autologout is set******"
    output = logout()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Auto Logout successfull**********"
    logging.info('Finished the TC of set_autologout.py\n')

    logging.info('Started the TC of add_cipher.py')
    print "\n\n******Checking Ciphers are enabled******"
    output = cipher()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************CIPHERS added**********"
    logging.info('Finished the TC of add_cipher.py\n')

    logging.info('Started the TC of configure_sshd.py')
    print "\n\n******Checking Agent forwarding is disabled or not*******"
    output = Agent()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Agent forwarding disabled**********"
    logging.info('Finished the TC of configure_sshd.py\n')

    logging.info('Started the TC of tcp_wrappers.py')
    print "\n\n******Checking TCP Permissions *******"
    output = FTP()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************TCP Permission set**********"
    logging.info('Finished the TC of tcp_wrappers.py\n')

    logging.info('Started the TC of set_password_aging.py')
    print "\n\n******Checking password aging *******"
    output = pass_age()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Password aging is Tested **********"
    logging.info('Finished the TC of set_password_aging.py\n')

    logging.info('Started the TC of reverse_fwd.py')
    print "\n\n******Checking reverse forwarding is diabled or not*******"
    output = reverse()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Reverse Forwarding DIsabled**********"
    logging.info('Finished the TC of reverse_fwd.py\n')

    logging.info('Started the TC of disable_SR.py')
    print "\n\n******Checking SR is disabled or not*******"
    output = disable()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************SR disabled**********"
    logging.info('Finished the TC of disable_SR.py\n')

    logging.info('Started the TC of enable_firewall.py')
    print "\n\n******Checking firewallis enabled or not*******"
    output = firewall()
    print "Result : %s" % output
    if output == "SUCCESS" : print "***********Firewall Enabled**********"
    logging.info('Finished the TC of enable_firewall.py\n')

    logging.info('Started the TC of configure_icmp.py')
    print "\n\n******Checking if icmp is configured******"
    output = icmp_configure()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********ICMP Configured**********"
    logging.info('Finished the TC of configure_icmp.py\n')

    logging.info('Started the TC of set_ssh_banner.py')
    print "\n\n******Checking ssh banner************"
    output = Banner()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************SSH Banner Set**********"
    logging.info('Finished the TC of set_ssh_banner.py\n')

    logging.info('Started the TC of set_cron_log.py')
    print "\n\n******Checking cron logs are set *******"
    output = set_cron()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Cron Logs Set**********"
    logging.info('Finished the TC of set_cron_log.py\n')

    logging.info('Started the TC of restrict_cron.py')
    print "\n\n******Checking Cron Jobs are allocated *******"
    output = permit_cron()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Cron Jobs set**********"
    logging.info('Finished the TC of restrict_cron.py\n')

    logging.info('Started the TC of restrict_at.py')
    print "\n\n******Checking AT jobs******"
    output = permit_at()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************AT Jobs Set**********"
    logging.info('Finished the TC of restrict_at.py\n')

    logging.info('Started the TC of set_grace_time.py')
    print "\n\n******Checking gracetime is set********"
    output = grace()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Grace Time Set**********"
    logging.info('Finished the TC of set_grace_time.py\n')

    logging.info('Started the TC of set_umask.py')
    print "\n\n******Checking unmask 027*********"
    output = mask()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Unmask 027 set**********"
    logging.info('Finished the TC of set_umask.py\n')

    logging.info('Started the TC of verify_static_ip_config.py')
    print "\n\n******Checking static ip files *******"
    output = static()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Static IP configured**********"
    logging.info('Finished the TC of verify_static_ip_config.py\n')

    logging.info('Started the TC of mask_alt_ctrl_del.py')
    print "\n\n*******Checking mask alt+ctrl+del**************"
    output = masking()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************masked ctrl+alt+del**********"
    logging.info('Finished the TC of mask_alt_ctrl_del.py\n')

    logging.info('Started the TC of enable_sticky_bit.py')
    print "\n\n*******Checking Sticky bit is set for all files******************"
    output = sticky()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Sticky bit enabled**********"
    logging.info('Finished the TC of enable_sticky_bit.py\n')
	
    logging.info('Started the TC of enable_ssh_proto_v2.py')
    print "\n\n******Checking Protocol version******"
    output = version()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Protocol version set**********"
    logging.info('Finished the TC of enable_ssh_proto_v2.py\n')

    logging.info('Started the TC of disable_icmp_broadcast.py')
    print "\n\n*********Checking ICMP broadcast************"
    output = icmp_broad()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************ ICMP broadcast disabled**********"
    logging.info('Finished the TC of disable_icmp_broadcast.py\n')

    logging.info('Started the TC of disable_access_suid.py')
    print "\n\n******Checking SUID************"
    output = check_suid()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************ SUID Access disabled**********"
    logging.info('Finished the TC of disable_access_suid.py\n')

    logging.info('Started the TC of set_motd_banner.py')
    print "\n\n******Checking modt banner***********"
    output= afterlogin()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************molt banner set**********"
    logging.info('Finished the TC of set_motd_banner.py\n')

    logging.info('Started the TC of disable_AllowTcpForwarding.py')
    print "\n\n******Checking TCP Forwarding is disabled************"
    output= disable_TCP()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************TCP forwad disabled**********"
    logging.info('Finished the TC of disable_AllowTcpForwarding.py\n')

    logging.info('Started the TC of disable_X11Forwarding.py')
    print "\n\n******Checking X11 Forwarding is disabled or not**********"
    output= disable_X11()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************ X11 Forwarding disabled**********"
    logging.info('Finished the TC of disable_X11Forwarding.py\n')
    logging.info('Started the TC of disable_GatewayPorts.py')
    print "\n\n******Checking Gateway Ports are disabled*******"
    output= disable_Gateway()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Disabled Gateway Ports**********"
    logging.info('Finished the TC of disable_GatewayPorts.py\n')

    logging.info('Started the TC of enable_sshHostKey_verification.py')
    print "\n\n******Checking SSH Host Key is Enabled or not************"
    output= enable_sshHostKey()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************SSH Hotkey Enabled**********"
    logging.info('Finished the TC of enable_sshHostKey_verification.py\n')

    logging.info('Started the TC of disable_Ipv6_autoconf.py')
    print "\n\n******Checking IPV6 is disabled *********"
    output= disable_Ipv6()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************IPV6 disabled**********"
    logging.info('Finished the TC of disable_Ipv6_autoconf.py\n')

    logging.info('Started the TC of Verify_NH_Config.py')
    print "\n\n******This function checks open Ports and verifying them *************"
    output= NH_conf()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Enabled Ports Verified**********"
    logging.info('Finished the TC for Verify_NH_Config.py\n')

    logging.info('Started the TC of set_file_permissions.py')
    print "\n\n******This function checks file permissions *************"
    output= check_permissions()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******file permissions verified**********"
    logging.info('Finished the TC for set_file_permissions.py\n')
	
    logging.info('Started the TC of set_inactive_days.py')
    print "\n\n******This function checks for account lockout *************"
    output= inactive_days()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******seted account lockout**********"
    logging.info('Finished the TC for set_inactive_days.py\n')
	
    logging.info('Started the TC of disable_secure_icmp.py')
    print "\n\n******This function checks for secure ICMP *************"
    output= disable_secure_icmp()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******disabled secure ICMP**********"
    logging.info('Finished the TC for disable_secure_icmp.py\n')
	
    logging.info('Started the TC of enable_suspicious_packets.py')
    print "\n\n******This function checks suspicious packets are logged *************"
    output= enable_suspicious_packets()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully checked suspicious packets are logged**********"
    logging.info('Finished the TC for enable_suspicious_packets.py\n')
	
    logging.info('Started the TC of disable_icmp_responses.py')
    print "\n\n******This function checks ICMP responses are disabled *************"
    output= disable_icmp_responses()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully checked ICMP responses are disabled**********"
    logging.info('Finished the TC for disable_icmp_responses.py\n')
	
    logging.info('Started the TC of enable_reverse_path_filter.py')
    print "\n\n******This function checks reverse path filtering is enabled *************"
    output= enable_reverse_path_filter()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully checked reverse path filtering is enabled**********"
    logging.info('Finished the TC for enable_reverse_path_filter.py\n')
	
    logging.info('Started the TC of enable_tcp_syncookies.py')
    print "\n\n******This function checks tcp syn cookies is enabled *************"
    output= enable_tcp_syncookies()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully checked tcp syn cookies is enabled**********"
    logging.info('Finished the TC for enable_tcp_syncookies.py\n')
	
    logging.info('Started the TC of disable_ipv6_advertisements.py')
    print "\n\n******This function checks IPv6 router advertisements are disabled *************"
    output= disable_ipv6_advertisements()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully IPv6 router advertisements are disabled**********"
    logging.info('Finished the TC for disable_ipv6_advertisements.py\n')
	
    logging.info('Started the TC of add_keyexchng_algorithm.py')
    print "\n\n******This function checks strong keyexchange algorithms are enforced*************"
    output= add_keyexchng_algorithm()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced strong keyexchange algorithms**********"
    logging.info('Finished the TC for add_keyexchng_algorithm.py\n')
	
    logging.info('Started the TC of enforce_ssh_timeout.py')
    print "\n\n******This function checks ssh timeout is enforced*************"
    output= enforce_ssh_timeout()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ssh timeout**********"
    logging.info('Finished the TC for enforce_ssh_timeout.py\n')
	
    logging.info('Started the TC of set_grace_time.py')
    print "\n\n******This function checks grace time for ssh login is enforced*************"
    output= grace()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced grace time for ssh login**********"
    logging.info('Finished the TC for set_grace_time.py\n')
	
    logging.info('Started the TC of set_maxauthtries.py')
    print "\n\n******This function checks sshd file is having maxauthtries*************"
    output= set_maxauthtries()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced sshd file is having maxauthtries**********"
    logging.info('Finished the TC for set_maxauthtries.py\n')
	
    logging.info('Started the TC of set_path_integrity.py')
    print "\n\n******This function checks root PATH integrity is successfully enforced*************"
    output= set_path_integrity()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced root PATH integrity**********"
    logging.info('Finished the TC for set_path_integrity.py\n')
	
    logging.info('Started the TC of su_restriction.py')
    print "\n\n******This function checks su command is restricted for useres*************"
    output= su_restriction()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced su command is restricted for useres**********"
    logging.info('Finished the TC for su_restriction.py\n')
	
    logging.info('Started the set_maxstartups.py')
    print "\n\n******This function checks max startups are enforcesd on the server*************"
    output= set_maxstartups()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced max startups are enforcesd on the server**********"
    logging.info('Finished the TC for set_maxstartups.py\n')
	
    logging.info('Started the TC of ensure_user_group_info.py')
    print "\n\n******This function checks the changes in pam configuration files is collected*************"
    output= ensure_user_group_info()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_user_group_info on the server**********"
    logging.info('Finished the TC for ensure_user_group_info.py\n')

    logging.info('Started the TC of ensure_sys_admin_scope.py')
    print "\n\n******This function checks the changes in /etc/sudo and etc/sudoers is collected*************"
    output= ensure_sys_admin_scope()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_sys_admin_scope on the server**********"
    logging.info('Finished the TC for ensure_sys_admin_scope.py\n')

    logging.info('Started the TC of ensure_sys_admin_cmd.py')
    print "\n\n******This function checks changes when an unprivileged user tends to use sudo command to undergo any elevated operartions*************"
    output= ensure_sys_admin_cmd()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_sys_admin_cmd on the server**********"
    logging.info('Finished the TC for ensure_sys_admin_cmd.py\n')

    logging.info('Started the TC of ensure_kernel_module.py')
    print "\n\n******This function checks changes the use of insmod , rmmod and modprobe by unprivileged user on the server*************"
    output= ensure_kernel_module()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_kernel_module on the server**********"
    logging.info('Finished the TC for ensure_kernel_module.py\n')
    
    logging.info('Started the TC of ensure_file_deletion.py')
    print "\n\n******This function checks use of system calls associated with the deletion or renaming of files and file attributes*************"
    output= ensure_file_deletion()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_file_deletion on the server**********"
    logging.info('Finished the TC for ensure_file_deletion.py\n')

    logging.info('Started the TC of ensure_file_auth.py')
    print "\n\n******This function checks for unsuccessful attempts to access files*************"
    output= ensure_file_auth()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_file_auth on the server**********"
    logging.info('Finished the TC for ensure_file_auth.py\n')
    
    logging.info('Started the TC of ensure_date_time_info.py')
    print "\n\n******This function checks ensures where the system date and/or time has been modified.*************"
    output= ensure_date_time()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_date_time_info on the server**********"
    logging.info('Finished the TC for ensure_date_time_info.py\n')

    logging.info('Started the TC of enforce_system_mount.py')
    print "\n\n******This function ensures to monitor the use of the mount system call*************"
    output= enforce_system_mount()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced enforce_system_mount on the server**********"
    logging.info('Finished the TC for enforce_system_mount.py\n')

    logging.info('Started the TC of ensure_system_access.py')
    print "\n\n******This function ensures to monitor of SELinux mandatory access controls.*************"
    output= ensure_system_access()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_system_access on the server**********"
    logging.info('Finished the TC for ensure_system_access.py\n')

    logging.info('Started the TC of ensure_user_priviliged_cmd.py')
    print "\n\n******This function ensures privileged programs to determine if unprivileged users are running setuid and/or setgid commands*************"
    output= ensure_user_priviliged_cmd()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_user_priviliged_cmd on the server**********"
    logging.info('Finished the TC for ensure_user_priviliged_cmd.py\n')

    logging.info('Started the TC of ensure_system_network.py')
    print "\n\n******This function ensures the changes to network environment files or system calls*************"
    output= ensure_system_network()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced ensure_system_network on the server**********"
    logging.info('Finished the TC for ensure_system_network.py\n')

    logging.info('Started the TC of discretionary_access_control.py')
    print "\n\n******This function ensures to monitor changes to file permissions, attributes, ownership and group*************"
    output= discretionary_access_control()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully enforced discretionary_access_control on the server**********"
    logging.info('Finished the TC for discretionary_access_control.py\n')

    logging.info('Started the TC of disable_hostbasedAuthentication.py')
    print "\n\n******This function checks SSH host based authentication is disabled *************"
    output= disable_hostbasedAuthentication()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully SSH host based authentication is disabled**********"
    logging.info('Finished the TC for disable_hostbasedAuthentication.py\n')

    logging.info('Started the TC of disable_ssh_emptypasswords.py')
    print "\n\n******This function checks SSH permit empty passwords is disabled *************"
    output= disable_ssh_emptypasswords()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully SSH permit empty passwords is disabled**********"
    logging.info('Finished the TC for disable_ssh_emptypasswords.py\n')

    logging.info('Started the TC of disable_ssh_userenvironment.py')
    print "\n\n******This function checks SSH permit user environment is disabled *************"
    output= disable_ssh_userenvironment()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully SSH permit user environment is disabled**********"
    logging.info('Finished the TC for disable_ssh_userenvironment.py\n')

    logging.info('Started the TC of enable_ignoreRhosts.py')
    print "\n\n******This function checks SSH IgnoreRhosts is enabled *************"
    output= enable_ignoreRhosts()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******successfully SSH IgnoreRhosts is enabled**********"
    logging.info('Finished the TC for enable_ignoreRhosts.py\n')

	
    logging.info('Started the Negative TC of enable_firewall.py')
    print "\n\n******Checking negative scenarios of firewall policy******"
    output = change_firewall()
    print "Result : %s" % output
    if output == "SUCCESS" : print "***********Negative Scenario of firewall verified*********"
    logging.info('Finished the Negative TC of enable_firewall.py\n')

    logging.info('Started the Neagative TC of  set_autologout.py')
    print "\n\n******Checking negative scenarios of Autologout *************"
    output= change_logout_time()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of SE Linux verified************"
    logging.info('Finished the Negative TC for enforce_selinux.py\n')

    logging.info('Started the Neagative TC of  disable_access_suid.py')
    print "\n\n******Checking negative scenarios of SUID *************"
    output= change_suid()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of SUID verified************"
    logging.info('Finished the Negative TC for disable_access_suid.py\n')

    logging.info('Started the Neagative TC of  set_password_aging.py')
    print "\n\n******Checking negative scenarios of password aging *************"
    output= set_passwd_aging()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of password aging verified************"
    logging.info('Finished the Negative TC for set_password_aging.py\n')

    logging.info('Started the Neagative TC of  Verify_NH_Config.py')
    print "\n\n******Checking negative scenarios by opening extra ports *************"
    output= check_NH_conf()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of opened ports is verified************"
    logging.info('Finished the Negative TC for Verify_NH_Config.py\n')

    logging.info('Started the Neagative TC of  tcp_wrappers.py')
    print "\n\n******Checking negative scenarios by changing TCP permissions********"
    output= disable_FTP()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of TCP permissions verified************"
    logging.info('Finished the Negative TC for tcp_wrappers.py\n')

    logging.info('Started the Neagative TC of  restrict_cron.py')
    print "\n\n******Checking negative scenarios by deallocating Cron Jobs********"
    output= update_cron()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of CRON jobs verified************"
    logging.info('Finished the Negative TC for restrict_cron.py\n')

    logging.info('Started the Neagative TC of  restrict_at.py')
    print "\n\n******Checking negative scenarios of AT Jobs********"
    output= update_at()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of AT jobs verified************"
    logging.info('Finished the Negative TC for restrict_cron.py\n')

    logging.info('Started the Neagative TC of  enable_sticky_bit.py')
    print "\n\n******Checking negative scenarios by disabling sticky bit ********"
    output= change_sticky()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of sticky bits are verified************"
    logging.info('Finished the Negative TC for enable_sticky_bit.py\n')
	
    logging.info('Started the Neagative TC of  enforce_selinux.py')
    print "\n\n******Checking negative scenarios of SE Linux *************"
    output= NTC_se()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of SE Linux verified************"
    logging.info('Finished the Negative TC for enforce_selinux.py\n')

    logging.info('Started the Negative TC of configure_icmp.py')
    print "\n\n******checks negative scenarios by enabling icmp types *************"
    output= check_icmp_configure()
    print "Result : %s" % output
    if output == "SUCCESS" : print "**********Negative scenarios of icmp verified************"
    logging.info('Finished the Negative TC for configure_icmp.py\n')

    logging.info('Started the Negative TC of configure_sshd.py')
    print "\n\n******checks negative scenario by enabling Agent forwarding *************"
    output= negative_sshd()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Enabled Agent forwarding and verified negative scenario **********"
    logging.info('Finished the Negative TC for configure_sshd.py\n')

    logging.info('Started the Negative TC of disable_AllowTcpForwarding.py')
    print "\n\n******Checking Negative scenario by enabling AllowTcpForwarding***********"
    output= enable_TCP()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Enabled AllowTcpForwarding and verified negative scenario**********"
    logging.info('Finished the Negative TC for disable_AllowTcpForwarding.py\n')

    logging.info('Started the Negative TC of disable_GatewayPorts.py')
    print "\n\n******Checking Negative scenario by enabling GatewayPorts *************"
    output= enable_Gateway()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Enabled GatewayPorts and verified negative scenario**********"
    logging.info('Finished the Negative TC for disable_GatewayPorts.py\n')

    logging.info('Started the Negative TC of disable_X11Forwarding.py')
    print "\n\n******Checking Negative scenario by enabling X11Forwarding *************"
    output= enable_X11()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Enabled X11Forwarding and verified negative scenario*********"
    logging.info('Finished the Negative TC for disable_X11Forwarding.py\n')

    logging.info('Started the Negative TC of enable_sshHostKey_verification.py')
    print "\n\n*******Checking Negative scenario by disabling SSH Host Key*************"
    output= disable_sshHostKey()
    print "Result : %s" % output
    if output == "SUCCESS" : print "************Disabled SSH Host Key and verified negative scenario**********"
    logging.info('Finished the Negative TC for enable_sshHostKey_verification.py\n')

    logging.info('Started the Negative TC of set_file_permissions.py')
    print "\n\n******Checking Negative scenarios for file permissions *************"
    output= check_weak_permissions()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for file permissions verified****"
    logging.info('Finished the Negative TC for set_file_permissions.py\n')
	
    logging.info('Started the Negative TC of set_inactive_days.py')
    print "\n\n******Checking Negative scenarios for account lockout *************"
    output= ntc_inactive_days()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for account lockout verified****"
    logging.info('Finished the Negative TC for set_inactive_days.py\n')
	
    logging.info('Started the Negative TC of disable_secure_icmp.py')
    print "\n\n******Checking Negative scenarios for disabling secure source routing *************"
    output= secure_icmp()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for disabling source routing verified****"
    logging.info('Finished the Negative TC for disable_secure_icmp.py\n')
	
    logging.info('Started the Negative TC of enable_suspicious_packets.py')
    print "\n\n******Checking Negative scenarios for enabling suspicious packets are logged *************"
    output= log_suspicious_packets()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for enabling suspicious packets are logged is verified****"
    logging.info('Finished the Negative TC for enable_suspicious_packets.py\n')
	
    logging.info('Started the Negative TC of disable_icmp_responses.py')
    print "\n\n******Checking Negative scenarios for disabling ICMP responses *************"
    output= bogus_icmp_responses()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for disabling ICMP responses is verified****"
    logging.info('Finished the Negative TC for disable_icmp_responses.py\n')
	
    logging.info('Started the Negative TC of enable_reverse_path_filter.py')
    print "\n\n******Checking Negative scenarios for enabling reverse path filter *************"
    output= reverse_path_filter()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for enabling reverse path filter is verified****"
    logging.info('Finished the Negative TC for enable_reverse_path_filter.py\n')
	
    logging.info('Started the Negative TC of enable_tcp_syncookies.py')
    print "\n\n******Checking Negative scenarios for enabling tcp syn cookies *************"
    output= tcp_syncookies()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for enabling tcp syn cookies is verified****"
    logging.info('Finished the Negative TC for enable_tcp_syncookies.py\n')
	
    logging.info('Started the Negative TC of disable_ipv6_advertisements.py')
    print "\n\n******Checking Negative scenarios for disabling IPv6 router advertisements *************"
    output= ipv6_advertisements()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for disabling IPv6 router advertisements verified****"
    logging.info('Finished the Negative TC for disable_ipv6_advertisements.py\n')
	
    logging.info('Started the Negative TC of disable_SR.py')
    print "\n\n******Checking Negative scenarios for disabling source routing *************"
    output= disable_SR()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for disabling source routing verified****"
    logging.info('Finished the Negative TC for disable_SR.py\n')
	
    logging.info('Started the Negative TC of enforce_ssh_timeout.py')
    print "\n\n******Checking Negative scenarios for enforcing ssh timeout*************"
    output= ntc_enforce_ssh_timeout()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for enforcing SSH timeout verified****"
    logging.info('Finished the Negative TC for enforce_ssh_timeout.py\n')
	
    logging.info('Started the Negative TC of set_grace_time.py ')
    print "\n\n******Checking Negative scenarios for setting login grace time*************"
    output= ntc_set_grace_time()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for setting login grace time is verified****"
    logging.info('Finished the Negative TC for set_grace_time.py \n')

    logging.info('Started the Negative TC of set_maxauthtries.py ')
    print "\n\n******Checking Negative scenarios for setting maximum authentication for login time*************"
    output= maxauthtries()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for setting setting maximum authentication for login time is verified****"
    logging.info('Finished the Negative TC for set_maxauthtries.py \n')
	
    logging.info('Started the Negative TC of su_restriction.py ')
    print "\n\n******Checking Negative scenarios for restricting su access*************"
    output= ntc_su_restriction()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for for restricting su access is verified****"
    logging.info('Finished the Negative TC for su_restriction.py \n')
	
    logging.info('Started the Negative TC of set_maxstartups.py')
    print "\n\n******Checking Negative scenarios for max startups in the server*************"
    output= ntc_set_maxstartups()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for max startups in the server is verifies****"
    logging.info('Finished the Negative TC for set_maxstartups.py \n')

    logging.info('Started the Negative TC of disable_hostbasedAuthentication.py')
    print "\n\n******Checking Negative scenarios for disabling SSH host based authentication *************"
    output= ssh_hostbasedAuthentication()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for disabling SSH host based authentication is verified**********"
    logging.info('Finished the Negative TC for disable_hostbasedAuthentication.py\n')

    logging.info('Started the Negative TC of disable_ssh_emptypasswords.py')
    print "\n\n******Checking Negative scenarios for disabling SSH permit empty passwords *************"
    output= ssh_emptypasswords()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for disabling SSH permit empty passwords is verified**********"
    logging.info('Finished the Negative TC for disable_ssh_emptypasswords.py\n')

    logging.info('Started the Negative TC of disable_ssh_userenvironment.py')
    print "\n\n******Checking Negative scenarios for disabling SSH permit user environment *************"
    output= ssh_userenvironment()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for disabling SSH permit user environment is verified**********"
    logging.info('Finished the Negative TC for disable_ssh_userenvironment.py\n')

    logging.info('Started the Negative TC of enable_ignoreRhosts.py')
    print "\n\n******Checking Negative scenarios for enabling SSH IgnoreRhosts *************"
    output= ignoreRhosts()
    print "Result : %s" % output
    if output == "SUCCESS" : print "*******Negative scenarios for disabling SSH IgnoreRhosts is verified**********"
    logging.info('Finished the Negative TC for enable_ignoreRhosts.py\n')

    #os.system("rm -rf /ericsson/security/Test_Cases/TC_bin/*.pyc")
    os.system("rm -rf /var/tmp/TC_bin/*.pyc")

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_TC_NH.log'
    pwd = '/ericsson/security/log/'
    os.system("mkdir -p "+pwd)

    format_string = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_string)

    print "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\x1b[32m\"Testcases for NODE HARDENING\"\x1b[0m++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    Apply_NH_TC()
    pwd = '/ericsson/security/log/'
    print "Script logs are saved at : \033[93m"+pwd+"\033[00m directory!"
