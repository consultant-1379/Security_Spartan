#!/usr/bin/python
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
# *******************************************************************
# Name      : nh_summary_generate.py
# Purpose   : This script will collect data for generating NH summary
# Reason    : EQEV-103713, EQEV-118507
# Author    : ZNITGUP
# *******************************************************************
"""

import json
import re
import os
import logging
import subprocess
import sys
import random
import string

from verify_password_age import check_password_aging
from verify_umask import check_umask
from restrict_cron_audit import cron_restrict_cmp
from restrict_at_audit import at_restrict_cmp
from verify_tcp_wrappers import tcp_cmp
from verify_autologout import check_autologout
from grace_time_audit import grace_cmp
from verify_sticky_bit import check_sticky_bit
from verify_suid import root_suid_check
from verify_file_permissions import verify_permissions
from verify_disable_root_switch import verify_disable_root_switch
from verify_path_integrity import check_integrity
from verify_agent_fwdng import check_sshd_config
from verify_ssh_login import check_ssh_login
from verify_X11Forwarding import x11_forwarding_check
from verify_AllowTCPForwording import allowtcp_forwarding_check
from verify_GatewayPorts import check_gatewayports_status
from verify_sshHostKeyVerification import check_ssh_hostkey_status
from verify_ssh_v2 import ssh_protocol_check
from verify_cipher import check_cipher
from verify_sshd_banner import check_banner
from verify_motd_banner import check_motd_banner
from verify_set_maxauth import check_maxauthtries
from verify_keyexchng_algorithm import check_kex
from verify_ssh_timeout import check_sshtimeout
from verify_set_maxstart import check_maxstartup
from verify_ignoreRhosts import check_ignorerhosts
from verify_ssh_emptypasswords import check_ssh_emptypasswords
from verify_ssh_userenvironment import check_ssh_userenvironment
from verify_hostbasedAuthentication import check_hostbased_authentication
from verify_reverse_fwd import check_reverse_fwd
from verify_Ipv6_autoconf import check_ipv6_autoconf_status
from verify_SR import check_sr_status
from verify_ipv6_advertisements import check_ipv6_adv
from verify_tcp_syncookies import check_tcp_syncookies
from verify_reverse_path_filter import check_rev_path
from verify_icmp_responses import check_icmp_status
from verify_suspicious_packets import check_packets
from verify_secure_icmp import check_secure_icmp
from verify_icmp_config import icmp_check
from verify_icmp import check_icmp
from cron_log_audit import cron_log_cmp
from verify_listing_rpms import check_listing_rpms
from verify_audit import check_audit_config
from verify_mask import ctrl_alt_del
from verify_date_time_info import check_date_time_info
from verify_user_group_info import check_user_group_info
from verify_system_network import check_system_network
from verify_system_access import check_system_access
from verify_kernel_module import check_kernel_module
from verify_discec_access import check_disec_access
from verify_file_auth import check_file_auth
from verify_user_priviliged_cmd import check_user_privileged_cmd
from verify_system_mount import check_mounts
from verify_file_deletion import check_file_deletion
from verify_sys_admin_scope import check_sys_admin_scope
from verify_auditconf_immutable import check_auditconf_immutable
from verify_sys_admin_cmd import check_sys_admin_cmd
from verify_audit_automate_cron import verify_audit_automate_cron
from verify_sudologs_rotate import verify_sudo_log
from verify_static_ip import dhcp_staticip_check
from verify_firewall import check_firewall
from su_restriction import server_type

sys.path.insert(0, '/ericsson/security/bin')

PASSWORD_TEST = str("echo '%s' | /usr/bin/passwd test 2>&1 \
| tee /ericsson/security/compliance/errorlog.txt > /dev/null 2>&1")
ERROR_LOG = str("/ericsson/security/compliance/errorlog.txt")

def check_password_complexity():
    """This function is to verify the password complexity"""
    os.system("/usr/bin/sleep 1s")
    os.system("/usr/sbin/useradd test > /dev/null 2>&1")
    status_history = check_password_history()

    status_length = check_password_length()

    status_upper = check_uppercase()

    status_lower = check_lowercase()

    status_special = check_special_character()

    status_digit = check_digit()
    status_hashing = check_password_hashing()
    os.system("/usr/bin/sleep 1s")
    os.system("/usr/sbin/userdel -r test")
    os.system("rm -rf /home/test")
    os.system("rm -rf /ericsson/security/compliance/errorlog.txt")
    status_acc_lockout = check_lockout()

    if status_history and status_length and status_upper and status_lower and status_special \
and status_digit and status_hashing and status_acc_lockout:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT: EXECUTE 'set_password_policy.py' TO MAKE IT COMPLIANT"

def passwd_generator(policy_type):
    """This is to generate a random password that will be used to test password policies"""
    rand_password = ""
    rand_lowercase_string = ''.join(random.choice(string.ascii_lowercase) for _ in range(3))
    rand_uppercase_string = ''.join(random.choice(string.ascii_uppercase) for _ in range(3))
    rand_digit = ''.join(random.choice(string.digits) for _ in range(5))

    if policy_type == "history":
        rand_password = rand_lowercase_string + rand_uppercase_string +'@'+ rand_digit
    if policy_type == "length":
        rand_password = rand_lowercase_string + rand_uppercase_string
    if policy_type == "upper_Case":
        rand_password = rand_lowercase_string + '@' + rand_digit
    if policy_type == "lower_Case":
        rand_password = rand_uppercase_string + '@' + rand_digit
    if policy_type == "special_character":
        rand_password = rand_lowercase_string + rand_uppercase_string + rand_digit
    if policy_type == "digits":
        rand_password = rand_lowercase_string + rand_uppercase_string + '@'

    rand_password = str(rand_password)
    return rand_password

def check_password_history():
    """This function is to check for the password history"""
    history = passwd_generator("history")

    compliance_pwd = "/ericsson/security/compliance/passwd.sh"
    with open(compliance_pwd, 'r') as fin:
        data = fin.readlines()

    index_value = 0
    line = " spawn passwd test\n"
    if line in data:
        index_value = data.index(line)
    insert_line = " " + "send " + "'" + history + r"\r'" + "\n"
    data.insert(index_value+2, insert_line)
    data.insert(index_value+4, insert_line)
    with open(compliance_pwd, 'w') as fout:
        fout.writelines(''.join(data))

    subprocess.call(['/ericsson/security/compliance/passwd.sh > /dev/null'], shell=True)
    value = False
    subprocess.call(['/ericsson/security/compliance/passwd.sh > \
/ericsson/security/compliance/pw.txt'], shell=True)
    if 'Password has been already used. Choose another.' in \
open('/ericsson/security/compliance/pw.txt').read():
        os.system("rm -rf /ericsson/security/compliance/pw.txt")
        logging.info("Password history is set")
        value = True
    else:
        os.system("rm -rf /ericsson/security/compliance/pw.txt")
        logging.error("Password history is not set")
        value = False

    data.pop(7)
    data.pop(8)
    with open(compliance_pwd, 'w') as fout:
        fout.writelines(''.join(data))

    return value

def check_password_length():
    """This function is to check for the password length"""
    rand_pwd = passwd_generator("length")
    os.system("echo '%s' | /usr/bin/passwd test 2>&1 \
| tee /ericsson/security/compliance/errorlog.txt > /dev/null" % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 digits' in \
open('/ericsson/security/compliance/errorlog.txt').read():
        logging.info("Password length complexity has been set for 9 characters")
        return True
    else:
        logging.error("Password length complexity has not been set for 9 characters")
        return False

def check_uppercase():
    """This function is to check uppercase character"""
    rand_pwd = passwd_generator("upper_Case")
    os.system(PASSWORD_TEST % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 uppercase letters' in \
open(ERROR_LOG).read():
        logging.info("Password complexity ensures the pressence of atleast 1 uppercase character")
        return True
    else:
        logging.error("Password complexity does not ensures the pressence of atleast 1 \
uppercase character")
        return False

def check_lowercase():
    """This function is to check lowercase character"""
    rand_pwd = passwd_generator("lower_Case")
    os.system(PASSWORD_TEST % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 lowercase letters' in \
open(ERROR_LOG).read():
        logging.info("Password complexity ensures the pressence of atleast 1 lowercase character")
        return True
    else:
        logging.error("Password complexity does not ensures the pressence of atleast 1 \
lowercase character")
        return False

def check_special_character():
    """This function is to check special character"""
    rand_pwd = passwd_generator("special_character")
    os.system(PASSWORD_TEST % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 non-alphanumeric characters'\
 in open(ERROR_LOG).read():
        logging.info("Password complexity ensures the presence of atleast 1 non-alphanumeric \
character")
        return True
    else:
        logging.error("Password complexity does not ensures the presence of atleast 1 \
non-alphanumeric character")
        return False

def check_digit():
    """This function is to check the digit value"""
    rand_pwd = passwd_generator("digits")
    os.system(PASSWORD_TEST % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 digits' in \
open(ERROR_LOG).read():
        logging.info("Password complexity ensures the pressence of atleast 1 digit character")
        return True
    else:
        logging.error("Password complexity does not ensures the pressence of atleast 1 \
digit character")
        return False

def check_password_hashing():
    """this function checks whether password hashing algorithm is sha512 or not."""
    status = subprocess.check_output("/usr/sbin/authconfig --test | grep hash \
| cut -d' ' -f 6", shell=True)
    if status == 'sha512\n':
        logging.info("strong password hashing algorithm is implemented")
        return True
    else:
        logging.error("password hashing algorihm being used is md5")
        return False

def check_lockout():
    """This function verifies if account lockout has been enforced or not."""
    data = open('/etc/pam.d/password-auth').read()
    if 'auth [success=1 default=ignore] pam_succeed_if.so user in root:dcuser' in data and \
'auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=1800' in data \
and 'auth        [default=die] pam_faillock.so authfail audit deny=5  unlock_time=1800' in data \
and 'account     required      pam_faillock.so' in data:
        return True
    else:
        return False

def check_inactive():
    """This fundction verifies if the inactive password days is set to 30 or not"""
    status_default = verify_default_inactive()
    status_users = verify_set_users()
    if status_default and status_users:
        return"COMPLIANT"
    else:
        return"NON-COMPLIANT: EXECUTE 'set_inactive_days.py' TO MAKE IT COMPLIANT"
def verify_default_inactive():
    """This is to verify if the inactive password lockout is set to 30 days as default or not"""
    inactive_days = subprocess.check_output("/usr/sbin/useradd -D | grep INACTIVE", shell=True)
    if inactive_days == "INACTIVE=30\n":
        logging.info("Inactive password lock is set to 30 days")
        return True
    else:
        logging.error("Default inactive password lock is not set to 30 days")
        return False
def verify_set_users():
    """This is to verify if the present users are set with inactive password lock or not"""
    check_value = os.system(r"grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7 \
> /ericsson/security/compliance/verify_inacive_days.txt")
    if check_value != 0:
        logging.error("Unable to fetch user accounts and its inactive password lockout period")
    else:
        logging.info("Fetched user accounts and its inactive password lockout period")
    with open("/ericsson/security/compliance/verify_inacive_days.txt", 'r') as fin:
        data = fin.readlines()
    data1 = []
    expected_value = "30\n"
    for i in data:
        if i != "\n":
            data1 = i.split(':')
            if (data1[0] != "root") and (data1[0] != "storadm"):
                user = data1[0]
                fetched_value = data1[1]
                if fetched_value != expected_value:
                    logging.error("Inactive password lock is not set as 30 days for %s", user)
                    os.system("rm -rf /ericsson/security/compliance/verify_inacive_days.txt")
                    return False
                else:
                    logging.info("Inactive password lock is set to 30 day for user %s", user)
    os.system("rm -rf /ericsson/security/compliance/verify_inacive_days.txt")
    return True

def check_restriction():
    """This function verifies whether su restriction is enforced or not"""
    try:
        check_present = subprocess.\
            check_output("cat /etc/group | grep -iw sugroup | cut -d':' -f 1", shell=True)
        check_present = check_present.strip()
        type_of_server = server_type()
        type_of_eniq_server = subprocess.check_output("/usr/sbin/dmidecode -t chassis | grep Type",
                                                      shell=True)
        non_comp = "NON-COMPLIANT: EXECUTE 'su_restriction.py' TO MAKE IT COMPLIANT"
        if check_present != "sugroup":
            logging.info("sugroup is not created")
            return non_comp
        check_users = subprocess.check_output("cat /etc/group | grep -iw sugroup | cut -d':' -f 4",
                                              shell=True)
        check_users = check_users.strip().split(',')
        if type_of_server == "MWS":
            if "root" not in  check_users:
                logging.info("MWS users are not added into the group")
                return non_comp
        elif type_of_server == "ENIQ-S":
            if type_of_eniq_server.strip() == ("Type: Rack Mount Chassis"):
                if "dcuser" not in check_users or "root" not in check_users:
                    logging.info("ENIQ-S users are not added into the group")
                    return non_comp
            else:
                if "storadm" not in check_users or "dcuser" not in check_users \
                        or "root" not in check_users:
                    logging.info("ENIQ-S users are not added into the group")
                    return non_comp
        with open("/etc/pam.d/su", 'r') as fin:
            data = fin.readlines()
        configured_line = "auth            required        pam_wheel.so use_uid group=sugroup\n"
        if configured_line not in data:
            logging.info(non_comp)
            return non_comp
        return"COMPLIANT"
    except(IOError, RuntimeError, AttributeError, TypeError, OSError):
        logging.error("Could not verify su restriction")


final_list = []


def report_check_password_aging():
    '''
    Generates report  for Password Aging for OS Users
    '''
    try:
        lst = []
        feature_name = "Password Aging for OS Users"
        feature_discription = "Enables password aging for all users"
        comp_status = check_password_aging()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Password Aging for OS Users')

def report_check_password_complexity():
    '''
    Generates report for Password Complexity for OS Users
    '''
    try:
        lst = []
        feature_name = "Password Complexity for OS Users"
        feature_discription = "Enforces password policy for all users"
        comp_status = check_password_complexity()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Password Complexity for OS Users')

def report_check_umask():
    '''
    Generates report for Secure Umask Configuration for OS Users
    '''
    try:
        lst = []
        feature_name = "Secure Umask Configuration for OS Users"
        feature_discription = "Enables secure umask configuration for all user"
        comp_status = check_umask()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Secure Umask Configuration for OS Users')


def report_cron_restrict_cmp():
    '''
    Generates report for restrict user Access for cron scheduler
    '''
    try:
        lst = []
        feature_name = "Restrict user access for cron scheduler"
        feature_discription = "Restricts cron scheduler for specific user and group"
        comp_status = cron_restrict_cmp()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Restrict user access for cron scheduler')

def report_at_restrict_cmp():
    '''
    Generates report for restrict user access for at scheduler
    '''
    try:
        lst = []
        feature_name = "Restrict user access for at scheduler"
        feature_discription = "Restricts at scheduler for specific user and group"
        comp_status = at_restrict_cmp()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Restrict user access for at scheduler')

def report_tcp_cmp():
    '''
    Generates report for disable FTP Access for OS Users
    '''
    try:
        lst = []
        feature_name = "Disable FTP access for OS users"
        feature_discription = "Blocks FTP access to the server and enforces SFTP"
        comp_status = tcp_cmp()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable FTP access for OS users')

def report_check_autologout():
    '''
    Generates report for Session Time Out Post Authorization
    '''
    try:
        lst = []
        feature_name = "Session Time Out Post Authorization"
        feature_discription = "Enables automatic logoff for inactive user sessions and \
ensures that default user shell timeout is configured"
        comp_status = check_autologout()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Session Time Out Post Authorization')

def report_grace_cmp():
    '''
    Generates report for Session Time Out Pre Authorization
    '''
    try:
        lst = []
        feature_name = "Session Time Out Pre Authorization"
        feature_discription = "Calculates the grace time for an idle session before authorization"
        comp_status = grace_cmp()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Session Time Out Pre Authorization')

def report_check_sticky_bit():
    '''
    Generates report for Securing Sensitive Files
    '''
    try:
        lst = []
        feature_name = "Securing Sensitive Files"
        feature_discription = "Sticky bit is enforced to prevent accidental removal of \
server configuration"
        comp_status = check_sticky_bit()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Securing Sensitive Files')

def report_root_suid_check():
    '''
    Generates report for SUID Permission Removal
    '''
    try:
        lst = []
        feature_name = "SUID Permission Removal"
        feature_discription = "Removes any SUID permission on the files"
        comp_status = root_suid_check()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in SUID Permission Removal')

def report_verify_permissions():
    '''
    Generates report for Strong File and Directory Permissions
    '''
    try:
        lst = []
        feature_name = "Strong File and Directory Permissions"
        feature_discription = "Enforces strong directory and file permissions"
        comp_status = verify_permissions()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Strong File and Directory Permissions')

def report_verify_disable_root_switch():
    '''
    Generates report for Restrict sudo -i to switch to root user
    '''
    try:
        lst = []
        feature_name = "Restrict sudo -i to switch to root user"
        feature_discription = "Restricts switching to root user by sudo -i command provided \
by sudo privileged user"
        comp_status = verify_disable_root_switch()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Restrict sudo -i to switch to root user')

def report_check_integrity():
    '''
    Generates report for Root PATH Integrity
    '''
    try:
        lst = []
        feature_name = "Root PATH Integrity"
        feature_discription = "Ensures that /root/bin dir has been removed from \
$PATH environment variable to ensure root path integrity"
        comp_status = check_integrity()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Root PATH Integrity')

def report_check_sshd_config():
    '''
    Generates report for Disables Agent Forwarding
    '''
    try:
        lst = []
        feature_name = "Disables Agent Forwarding"
        feature_discription = "Disables agent forwarding for SSH communication"
        comp_status = check_sshd_config()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disables Agent Forwarding')

def report_x11_forwarding_check():
    '''
    Generates report for Disable X11 Forwarding
    '''
    try:
        lst = []
        feature_name = "Disable X11 Forwarding"
        feature_discription = "Disables x11 forwarding for SSH communication"
        comp_status = x11_forwarding_check()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable X11 Forwarding')

def report_allowtcp_forwarding_check():
    '''
    Generates report for Disable SSH Port Forwarding
    '''
    try:
        lst = []
        feature_name = "Disable SSH Port Forwarding"
        feature_discription = "Disables TCP forwarding for SSH communication"
        comp_status = allowtcp_forwarding_check()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable SSH Port Forwarding')

def report_check_gatewayports_status():
    '''
    Generates report for Disable Port Forwarding
    '''
    try:
        lst = []
        feature_name = "Disable Port Forwarding"
        feature_discription = "Disables gateway ports from ssh_config file to prevent remote port \
forwarding and bind to nonloop back addresses"
        comp_status = check_gatewayports_status()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable Port Forwarding')

def report_check_ssh_hostkey_status():
    '''
    Generates report for Hostkey and DNS Key Verification
    '''
    try:
        lst = []
        feature_name = "Hostkey and DNS Key Verification"
        feature_discription = "Enables SSH host key verification"
        comp_status = check_ssh_hostkey_status()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Hostkey and DNS Key Verification')

def report_ssh_protocol_check():
    '''
    Generates report for Secure SSH Protocol
    '''
    try:
        lst = []
        feature_name = "Secure SSH Protocol"
        feature_discription = "Enables SSH protocol version-2"
        comp_status = ssh_protocol_check()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Secure SSH Protocol')

def report_check_cipher():
    '''
    Generates report for Secure SSH Ciphers and MAC algorithms
    '''
    try:
        lst = []
        feature_name = "Secure SSH Ciphers and MAC algorithms"
        feature_discription = "Secure ciphers and MAC algorithms for SSH communication"
        comp_status = check_cipher()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Secure SSH Ciphers and MAC algorithms')

def report_check_banner():
    '''
    Generates report for Pre Log On Banner
    '''
    try:
        lst = []
        feature_name = "Pre Log On Banner"
        feature_discription = "SSH and SFTP pre-logon banner message"
        comp_status = check_banner()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Pre Log On Banner')

def report_check_motd_banner():
    '''
    Generates report for Post Log On Banner
    '''
    try:
        lst = []
        feature_name = "Post Log On Banner"
        feature_discription = "SSH and SFTP post logon banner message"
        comp_status = check_motd_banner()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Post Log On Banner')

def report_check_maxauthtries():
    '''
    Generates report for SSH MaxAuthTries
    '''
    try:
        lst = []
        feature_name = "SSH MaxAuthTries"
        feature_discription = "Sets the maxauthtries parameter to a lower number"
        comp_status = check_maxauthtries()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in SSH MaxAuthTries')

def report_check_kex():
    '''
    Generates report  for strong Key Exchange algorithms
    '''
    try:
        lst = []
        feature_name = "Strong Key Exchange algorithms"
        feature_discription = "Ensures that cryptographic keys are exchanged between two parties \
thus allowing use of a cryptographic algorithm"
        comp_status = check_kex()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Strong Key Exchange algorithms')

def report_check_sshtimeout():
    '''
    Generates report for SSH Idle Timeout Interval
    '''
    try:
        lst = []
        feature_name = "SSH Idle Timeout Interval"
        feature_discription = "Sets the SSH connection timeout value to 900 seconds"
        comp_status = check_sshtimeout()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in SSH Idle Timeout Interval')

def report_check_maxstartup():
    '''
    Generates report for SSH Idle Timeout Interval
    '''
    try:
        lst = []
        feature_name = "SSH MaxStartups"
        feature_discription = "Limit the unsuccessful connection attempt that help to avoid \
DoS attacks"
        comp_status = check_maxstartup()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in SSH Idle Timeout Interval')

def report_check_ignore_rhosts():
    '''
    Generates report for SSH IgnoreRhosts
    '''
    try:
        lst = []
        feature_name = "SSH IgnoreRhosts"
        feature_discription = "SSH IgnoreRhosts specifies the rhosts and hosts files that are not \
to be used in Rhosts RSA Authentication or Host based Authentication"
        comp_status = check_ignorerhosts()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in SSH IgnoreRhosts')

def report_check_ssh_emptypasswords():
    '''
    Generates report for SSH PermitEmptyPasswords
    '''
    try:
        lst = []
        feature_name = "SSH PermitEmptyPasswords"
        feature_discription = "Disables SSH server login to accounts with empty password strings"
        comp_status = check_ssh_emptypasswords()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in SSH PermitEmptyPasswords')

def report_check_ssh_userenvironment():
    '''
    Generates report for SSH PermitUserEnvironment
    '''
    try:
        lst = []
        feature_name = "SSH PermitUserEnvironment"
        feature_discription = "Disables the PermitUserEnvironment option and users are not \
allowed to add environment options to the SSH daemon command"
        comp_status = check_ssh_userenvironment()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in SSH PermitUserEnvironment')

def report_check_hostbased_authentication():
    '''
    Generates report  for SSH HostbasedAuthentication
    '''
    try:
        lst = []
        feature_name = "SSH HostbasedAuthentication"
        feature_discription = "Disables the SSH HostbasedAuthentication"
        comp_status = check_hostbased_authentication()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in SSH HostbasedAuthentication')

def report_check_reverse_fwd():
    '''
    Generates report for Strict Reverse Path Forwarding
    '''
    try:
        lst = []
        feature_name = "Strict Reverse Path Forwarding"
        feature_discription = "Restricts Reverse Path Forwarding by enabling rp_filter"
        comp_status = check_reverse_fwd()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Strict Reverse Path Forwarding')

def report_check_ipv6_autoconf_status():
    '''
    Generates report for Disable Dynamic IP Allocation for IPv6
    '''
    try:
        lst = []
        feature_name = "Disable Dynamic IP Allocation for IPv6"
        feature_discription = "Disables IPv6 autoconf feature"
        comp_status = check_ipv6_autoconf_status()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable Dynamic IP Allocation for IPv6')

def report_check_sr_status():
    '''
    Generates report for Disable Source Routing
    '''
    try:
        lst = []
        feature_name = "Disable Source Routing"
        feature_discription = "Ensure packet redirect sending and source routing for IPv4 server \
Communications is disabled and ensures that ICMP redirects are not accepted"
        comp_status = check_sr_status()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable Source Routing')

def report_check_icmp():
    '''
    Generates report for Disable Source Routing
    '''
    try:
        lst = []
        feature_name = "Block Vulnerable ICMP Responses"
        feature_discription = "Blocks vulnerable ICMP types for IPv4 and IPv6"
        comp_status = check_icmp()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable Source Routing')

def report_icmp_check():
    '''
    Generates report for Disable IPv4 and ICMP Broadcast
    '''
    try:
        lst = []
        feature_name = "Disable IPv4 and ICMP Broadcast"
        feature_discription = "Disables ICMP package broadcast"
        comp_status = icmp_check()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable IPv4 and ICMP Broadcast')

def report_check_secure_icmp():
    '''
    Generates report for Disable Secure ICMP Redirects
    '''
    try:
        lst = []
        feature_name = "Disable Secure ICMP Redirects"
        feature_discription = "Ensures that secure ICMP redirects are not accepted"
        comp_status = check_secure_icmp()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable Secure ICMP Redirects')

def report_check_packets():
    '''
    Generates report for Suspicious Packets
    '''
    try:
        lst = []
        feature_name = "Logs Suspicious Packets"
        feature_discription = "Ensures that suspicious packets are not logged"
        comp_status = check_packets()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Suspicious Packets')

def report_check_icmp_status():
    '''
    Generates report for Suspicious Packets
    '''
    try:
        lst = []
        feature_name = "Ignore Bogus ICMP Responses"
        feature_discription = "Ensures that bogus ICMP responses are ignored"
        comp_status = check_icmp_status()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Ignore Bogus ICMP Responses')

def report_check_rev_path():
    '''
    Generates report for Reverse Path Filtering
    '''
    try:
        lst = []
        feature_name = "Reverse Path Filtering"
        feature_discription = "Ensures that reverse path filtering is enabled"
        comp_status = check_rev_path()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Reverse Path Filtering')

def report_check_tcp_syncookies():
    '''
    Generates report for TCP SYN Cookies
    '''
    try:
        lst = []
        feature_name = "TCP SYN Cookies"
        feature_discription = "Ensures that TCP SYN Cookies are enabled"
        comp_status = check_tcp_syncookies()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in TCP SYN Cookies')

def report_check_ipv6_adv():
    '''
    Generates report for Disable IPv6 router advertisements
    '''
    try:
        lst = []
        feature_name = "Disable IPv6 router advertisements"
        feature_discription = "Ensures IPv6 router advertisements are not accepted"
        comp_status = check_ipv6_adv()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Disable IPv6 router advertisements')

def report_cron_log_cmp():
    '''
    Generates report for Cron Logs
    '''
    try:
        lst = []
        feature_name = "Cron Logs"
        feature_discription = "Configures the log rotation and sets the maximum limit \
for storing the cron log information"
        comp_status = cron_log_cmp()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Cron Logs')

def report_check_listing_rpms():
    '''
    Generates report for Software Package Verification
    '''
    try:
        lst = []
        feature_name = "Software Package Verification"
        feature_discription = "Capture the list of Red Hat Package Managers that are installed"
        comp_status = check_listing_rpms()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Software Package Verification')

def report_check_audit_config():
    '''
    Generates report for Server Audit Configuration
    '''
    try:
        lst = []
        feature_name = "Server Audit Configuration"
        feature_discription = "Configure the audit rules on ENIQ-S and MWS to display the \
specified server and user events on the server"
        comp_status = check_audit_config()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Server Audit Configuration')

def report_ctrl_alt_del():
    '''
    Generates report for Prevent Accidental Reboot
    '''
    try:
        lst = []
        feature_name = "Prevent Accidental Reboot"
        feature_discription = "Disable the unexpected server reboot caused by pressing Ctrl+Alt+Del"
        comp_status = ctrl_alt_del()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Prevent Accidental Reboot')


def report_check_date_time_info():
    '''
    Generates report for collection of modification of date and time information
    '''
    try:
        lst = []
        feature_name = "Collection of  modification of date and time information"
        feature_discription = "Collects the events that modify information of date and time \
which are done on the server by an unauthorized users"
        comp_status = check_date_time_info()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in collection of modification of date and time information')

def report_check_user_group_info():
    '''
    Generates report for collection of modification of user/group information
    '''
    try:
        lst = []
        feature_name = "Collection of modification of user/group information"
        feature_discription = "Ensures the modification information of user or group are collected"
        comp_status = check_user_group_info()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Collection of modification of user/group information')

def report_check_system_network():
    '''
    Generates report for Collection of modification of network environment event
    '''
    try:
        lst = []
        feature_name = "Collection of modification of network environment events"
        feature_discription = "Ensures that the modification information of system network \
environment is collected"
        comp_status = check_system_network()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Collection of modification of network environment events')

def report_check_system_access():
    '''
    Generates report for collection of modification of Mandatory Access Controls
    '''
    try:
        lst = []
        feature_name = "Collection of modification of Mandatory Access Controls"
        feature_discription = "Ensures the modification information of system mandatory \
access is collected"
        comp_status = check_system_access()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Modification of Mandatory Access Controls')

def report_check_kernel_module():
    '''
    Generates report for Collection of kernel module load and unload
    '''
    try:
        lst = []
        feature_name = "Collection of kernel module load and unload"
        feature_discription = "Monitors and logs the changes to the kernel loading and unloading \
when an unauthorized user attempts to do that on the server"
        comp_status = check_kernel_module()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Collection of kernel module load and unload')

def report_check_disec_access():
    '''
    Generates report for Collection of discretionary access control permission
    '''
    try:
        lst = []
        feature_name = "Collection of discretionary access control permission"
        feature_discription = "Ensures that modification information of the discretionary access \
control permission is collected"
        comp_status = check_disec_access()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Collection of discretionary access control permission')

def report_check_file_auth():
    '''
    Generates report for Unsuccessful unauthorized file access attempts
    '''
    try:
        lst = []
        feature_name = "Collection of unsuccessful unauthorized file access attempts"
        feature_discription = "Ensures the unsuccessful and unauthorized file access attempts are \
collected"
        comp_status = check_file_auth()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Unsuccessful unauthorized file access attempts')

def report_check_user_privileged_cmd():
    '''
    Generates report for Use of privileged commands
    '''
    try:
        lst = []
        feature_name = "Collection of use of privileged commands"
        feature_discription = "Ensures that the use of privileged commands are collected"
        comp_status = check_user_privileged_cmd()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Use of privileged commands')

def report_check_mounts():
    '''
    Generates report for Successful file system mount
    '''
    try:
        lst = []
        feature_name = "Collection of successful file system mount"
        feature_discription = "Ensures that the successful file system mounts are collected"
        comp_status = check_mounts()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Successful file system mount')

def report_check_file_deletion():
    '''
    Generates report for File deletion events by users
    '''
    try:
        lst = []
        feature_name = "Collection of file deletion events by users"
        feature_discription = "Ensures that file deletion events by users are collected"
        comp_status = check_file_deletion()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in File deletion events by users')

def report_check_sys_admin_scope():
    '''
    Generates report for Changes to system administration scope
    '''
    try:
        lst = []
        feature_name = "Collection of changes to system administration scope"
        feature_discription = "Ensures the changes to system administrator scope are collected"
        comp_status = check_sys_admin_scope()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in File deletion events by users')

def report_check_auditconf_immutable():
    '''
    Generates report for Immutable audit configuration rules
    '''
    try:
        lst = []
        feature_name = "Immutable audit configuration rules"
        feature_discription = "Ensures that the audit rules are immutable"
        comp_status = check_auditconf_immutable()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Immutable audit configuration rules')

def report_check_sys_admin_cmd():
    '''
    Generates report for System administrator command executions
    '''
    try:
        lst = []
        feature_name = "System administrator command executions"
        feature_discription = "Ensure that the system administrator command executions is collected"
        comp_status = check_sys_admin_cmd()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in System administrator command executions')

def report_verify_audit_automate_cron():
    '''
    Generates report for audit log  considilation
    '''
    try:
        lst = []
        feature_name = "Audit log  considilation"
        feature_discription = "Ensure cron jon will run everday a 11 pm every day for batch zipping"
        comp_status = verify_audit_automate_cron()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Audit log  considilation')

def report_verify_sudo_log():
    '''
    Generates report for Sudo log rotation
    '''
    try:
        lst = []
        feature_name = "Sudo log rotation"
        feature_discription = "Sudo logs rotation is configured"
        comp_status = verify_sudo_log()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Sudo log rotation')

def report_dhcp_staticip_check():
    '''
    Generates report for Static IP
    '''
    try:
        lst = []
        feature_name = "Static IP"
        feature_discription = "static ip addresss has been assigned to all \
interfaces persent in the server or not"
        comp_status = dhcp_staticip_check()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Static IP')

def report_check_firewall():
    '''
    Generates report for Firewalld services
    '''
    try:
        lst = []
        feature_name = "Firewalld services"
        feature_discription = "firewalld service is in active and enabled state or not."
        comp_status = check_firewall()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Firewalld services')

def report_check_inactive():
    '''
    Generates report for Account disable after password expiry
    '''
    try:
        lst = []
        feature_name = "Account disable after password expiry"
        feature_discription = "Account is deactivated for the users whose password has expired \
for more than 30 days"
        comp_status = check_inactive()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Account disable after password expiry')

def check_sestatus():
    """This function verifies if selinux is in enforcing mode or not"""
    status = subprocess.check_output("/usr/sbin/getenforce", shell=True)
    config_file = open("/etc/sysconfig/selinux", "r")
    for line in config_file:
        if re.match("SELINUX=enforcing", line):
            status2 = 'SELINUX=enforcing'
    if status == 'Enforcing\n' and status2 == 'SELINUX=enforcing':
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'enforce_selinux.py' TO MAKE IT COMPLIANT"

def report_check_sestatus():
    '''
    Generates report for System MAC and Policy Updates
    '''
    try:
        lst = []
        feature_name = "System MAC and Policy Updates"
        feature_discription = "Checks the SELinux status and sets it to enforcing mode \
if it is in the permissive or the disabled mode"
        comp_status = check_sestatus()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in System MAC and Policy Updates')

def report_check_restriction():
    '''
    Generates report for Access to the su command is restricted
    '''
    try:
        lst = []
        feature_name = "Access to the su command is restricted"
        feature_discription = "Restricts su access to OS users except dcuser and root"
        comp_status = check_restriction()
        lst.append(feature_name)
        lst.append(feature_discription)
        if comp_status == "COMPLIANT":
            lst.append(comp_status)
        else:
            comp_status = "NON-COMPLIANT"
            lst.append(comp_status)
        final_list.append(lst)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in Access to the su command is restricted')

def restructure_data():
    ''' This function restructure the data '''
    try:
        with open('/ericsson/security/bin/node_hardening_summary.txt', 'r') as file1:
            text = file1.read()
            patn = re.sub(r"[\()\]]", "", text)
        file1 = open("/ericsson/security/bin/node_hardening_summary.txt", "w")
        file1.write("Feature Name, Feature Description, Node Hardening Status"+"\n")
        file1.write(patn)
        file1.close()
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in restructuring the data')

def file_permission(nh_summary_file):
    '''
    Changes the permission for /ericsson/security/bin/node_hardening_summary.txt
    '''
    try:
        os.system("chmod 400 "+nh_summary_file)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to change permission!!')

def nh_summary():
    '''
    Generates NH Summary
    '''
    report_check_password_aging()
    report_check_password_complexity()
    report_check_umask()
    report_cron_restrict_cmp()
    report_at_restrict_cmp()
    report_tcp_cmp()
    report_check_autologout()
    report_grace_cmp()
    report_check_sticky_bit()
    report_root_suid_check()
    report_verify_permissions()
    report_verify_disable_root_switch()
    report_check_integrity()
    report_check_sshd_config()
    report_x11_forwarding_check()
    report_allowtcp_forwarding_check()
    report_check_gatewayports_status()
    report_check_ssh_hostkey_status()
    report_ssh_protocol_check()
    report_check_cipher()
    report_check_banner()
    report_check_motd_banner()
    report_check_maxauthtries()
    report_check_kex()
    report_check_sshtimeout()
    report_check_maxstartup()
    report_check_ignore_rhosts()
    report_check_ssh_emptypasswords()
    report_check_ssh_userenvironment()
    report_check_hostbased_authentication()
    report_check_reverse_fwd()
    report_check_ipv6_autoconf_status()
    report_check_sr_status()
    report_check_icmp()
    report_icmp_check()
    report_check_secure_icmp()
    report_check_packets()
    report_check_icmp_status()
    report_check_rev_path()
    report_check_tcp_syncookies()
    report_check_ipv6_adv()
    report_cron_log_cmp()
    report_check_listing_rpms()
    report_check_audit_config()
    report_ctrl_alt_del()
    report_check_date_time_info()
    report_check_user_group_info()
    report_check_system_network()
    report_check_system_access()
    report_check_kernel_module()
    report_check_disec_access()
    report_check_file_auth()
    report_check_user_privileged_cmd()
    report_check_mounts()
    report_check_file_deletion()
    report_check_sys_admin_scope()
    report_check_sys_admin_cmd()
    report_check_auditconf_immutable()
    report_verify_audit_automate_cron()
    report_verify_sudo_log()
    report_dhcp_staticip_check()
    report_check_firewall()
    report_check_inactive()
    report_check_sestatus()
    report_check_restriction()
if __name__ == '__main__':

    server_status = ""
    if check_server_hardening_status() == 1:
        server_status = "Full Node Hardening Summary"
    elif check_server_hardening_status() == 2:
        server_status = "Granular Node Hardening Summary"

    nh_summary()
    TMP_JSON = "/ericsson/security/bin/node_hardening_summary.json"
    NODE_HARDENDING_SUMMARY_FILE = "/ericsson/security/bin/node_hardening_summary.txt"
    with open(TMP_JSON, "w") as outfile:
        json.dump(final_list, outfile)
    json_data = open(TMP_JSON)
    data = json.load(json_data)
    f = open(NODE_HARDENDING_SUMMARY_FILE, "w")
    for d in range(0, len(data)):
        index_0 = data[d][0].encode('utf-8')
        index_1 = data[d][1].encode('utf-8')
        index_2= data[d][2].encode('utf-8')
        final_data = index_0, index_1, index_2
        f.write(str(final_data)+"\n")
    f.close()
    os.unlink(TMP_JSON)
    restructure_data()
    file_permission(NODE_HARDENDING_SUMMARY_FILE)
    os.system("rm -rf /ericsson/security/compliance/*.pyc")
