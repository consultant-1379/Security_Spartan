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
# Name      : NH_Restore.py
# Purpose   : This script removes the Node hardening configurations
#             enforced on the system.
# ********************************************************************
"""
import os
import subprocess as s
import commands
import logging
import time
from Apply_Node_Hardening import logger
from Apply_Node_Hardening import change_permissions
from user_verification import user_verification

def log_error(cmd):
    """This function is to find any runtime error in a command"""
    status = s.call(cmd, shell=True)
    if status:
        logging.error('\n'+'\33[31mRuntime error Found\033[0m'+'\n')
        print "\33[31m ERROR \033[0m: Runtime error Found"
        logger(1, restore_script, LOG_PATH)
        exit(1)

def restore_files(li_files, conf):
    """This function is to restore system files back"""
    for file in li_files:
        new = file.replace('0', '/')
        if new in ['/proc/sys/net/ipv4/conf/default/rp_filter', '/etc/selinux/config'] or file[0] != '0':
            continue
        log_error("cp -p /ericsson/security/BACKUP_CONFIG_FILES/"+file+' '+new+' 2>/dev/null')
        print "INFO: "+conf[new]+" has been Restored Succesfully"
        logging.info(conf[new]+" ["+new+']'+" has been Restored Successfully")
        if new == '/etc/ssh/sshd_config':
            log_error("systemctl restart sshd 2> /dev/null")
        elif new == "/etc/login.defs":
            data = open("/etc/passwd", "r").read().split('\n')
            print "INFO: Changing Password expiry "
            users = ["dcuser", "root", "storadm"]
            for i in data:
                if i and i.split(":")[0] not in users and (int(i.split(":")[2]) > 999):
                    log_error("chage -M 99999 " + i.split(":")[0])
                    logging.info("Password expiry configuration is restored for "+i.split(":")[0])
        elif new == "/etc/audit/rules.d/audit.rules":
            log_error("service auditd restart > /dev/null")

def configure_server():
    """This function is to find the server configuration"""
    check_mount_point = os.path.ismount("/JUMP")
    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")
    if mws_insttype_path:
        mws_insttype = s.check_output("cat /ericsson/config/inst_type", shell=True)
        server_config_name = s.check_output("cat /ericsson/config/ericsson_use_config | cut -d'=' -f 2", shell=True)
        server_config_name = server_config_name.replace('\n', '')
        if check_mount_point and 'rhelonly' in mws_insttype and 'mws' in server_config_name:
            return 'MWS'
    elif eniq_insttype_path:
        return 'ENIQ'
    else:
        return 'NOT Configured'

def check_firewall():
    """This function is to check the firewall status"""
    active_status = s.check_output("systemctl status firewalld | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = s.check_output("systemctl status firewalld | sed -n '/Loaded:/p' \
| cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)
    if active_status != "active\n" and enabled_status != "enabled\n":
        log_error("systemctl start firewalld > /dev/null")
        log_error("systemctl enable firewalld > /dev/null")

def restart_firewalld():
    """This function is to reload firewalld service"""
    logging.info('Reloading firewalld service')
    log_error("firewall-cmd --reload > /dev/null 2>&1")

def remove_ports():
    """This function is to remove the configured ports and services"""
    server_type = configure_server()
    check_firewall()
    if server_type == 'MWS':
        ports = ['53/tcp', '67/udp', '68/udp', '69/udp', '2049/tcp', '2049/udp', '20048/tcp',
                 '20048/udp', '111/tcp', '111/udp', '37726/tcp', '50740/udp']
        service = ['tftp']
        int_serv = ['mountd']
    elif server_type == 'ENIQ':
        ports = ['6389/tcp', '2640/tcp', '2641/tcp', '2642/tcp', '8443/tcp',
                 '2637/tcp', '2638/tcp', '2639/tcp', '1200/tcp', '60001/tcp', '60002/tcp',
                 '60003/tcp', '162/udp', '161/udp', '50720-50739/udp', '50740/udp', '4051-4100/tcp',
                 '60004/tcp', '60005/tcp', '1556/tcp', '13724/tcp', '13782/tcp', '37726/tcp',
                 '57006/tcp', '5093/udp']
        service = ['nfs', 'mountd', 'rpc-bind']
        int_serv = []
    else:
        print "\33[31m Error \033[0m: Server Not Configured"
        logging.error("\33[31m Server Not Configured  \033[0m")
        logger(1, restore_script, LOG_PATH)
        exit(1)
    output_redirect = " --permanent > /dev/null 2>&1"
    for p in ports:
        log_error("firewall-cmd --zone=public --remove-port="+p+output_redirect)
        logging.info("%s Port is Removed and Restored", p)
    for s in service:
        log_error("firewall-cmd --zone=public --remove-service="+s+output_redirect)
        logging.info("%s service is Removed and Restored", s)
    for i in int_serv:
        log_error("firewall-cmd --remove-service="+i+" --zone=internal --permanent > /dev/null 2>&1")
        logging.info("%s service is Removed and Restored", i)
    restart_firewalld()

def restore_icmp():
    """This function is to restore the icmp blocks"""
    icmp_types = s.check_output('cat /ericsson/security/BACKUP_CONFIG_FILES/\
icmp_config', shell=True).split()
    check_firewall()
    for icmp in icmp_types:
        log_error("firewall-cmd --remove-icmp-block="+icmp+" > /dev/null 2>&1")
        logging.info("%s ICMP type has been unblocked and restored", icmp)
    restart_firewalld()

def restore_static_ip():
    """This function is to restore the static ip"""
    interface_files = s.check_output('ls /ericsson/security/BACKUP_CONFIG_FILES/\
INTRFC_CONFIG_FILES/', shell=True).split()
    for files in interface_files:
        if os.path.exists("/etc/sysconfig/network-scripts/"+files):
            log_error("cp -p /ericsson/security/BACKUP_CONFIG_FILES/INTRFC_CONFIG_FILES/"+files+\
                      " /etc/sysconfig/network-scripts/"+files+" > /dev/null 2>&1")
            logging.info("Restored ifcfg-%s in network-scripts", files)

def remove_files(files):
    """This is to remove the files created by Node hardening"""
    rem = ['at_allow_config', 'at_deny_config', 'cron_allow_config',
           'cron_deny_config', 'host_allow_config', 'host_deny_config']
    is_remove = False
    for file in rem:
        if file in files:
            is_remove = True
            file = file.replace('_config', '')
            file = file.replace('_', '.')
            log_error("rm -rf /etc/"+file+' > /dev/null 2>&1')
            logging.info(file+" Cleaned  ")
    return "Successful" if is_remove else "Terminated(No change)"

def restore_firewall():
    """This function is to restore the firewalld status"""
    ports = s.check_output('cat /ericsson/security/BACKUP_CONFIG_FILES/open_ports_config', shell=True).split()
    check_firewall()
    if ports != []:
        for p in ports:
            log_error("firewall-cmd --zone=public --add-port="+p+" --permanent > /dev/null 2>&1")
            logging.info(p+" Port has been Restored")

def reset_permission():
    """This function resets file permission after checking existence"""
    if os.path.exists('/sys/firmware/efi'):
        files_list = ["/etc/crontab"]
    else:
        files_list = ["/boot/grub2/grub.cfg", "/etc/crontab"]

    dir_list = ["/etc/cron.d", "/etc/cron.daily",
                "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]

    for files in files_list:
        if os.path.exists(files):
            os.system("chmod 644 "+files+"> /dev/null 2>&1")
            logging.info("Reset permissions for the file "+files+" as per recommendation")
        else:
            print "File "+files+" not Exists"
            logging.info("Unable to reset "+files+"file permission as it doesn't exist")

    for dirs in dir_list:
        if os.path.exists(dirs):
            os.system("chmod 755 "+dirs+"> /dev/null 2>&1")
            logging.info("Reset permissions for the file "+dirs+" as per recommendation")
        else:
            print "File "+dirs+"not Exists"
            logging.info("Unable to reset "+dirs+"directory permission as it doesn't exist")
def reset_inactive():
    """This is to reset inactive password lock to default"""
    inactive_days = s.check_output("useradd -D | grep INACTIVE", shell=True)
    if inactive_days != "INACTIVE=-1\n":
        os.system("useradd -D -f -1")
        logging.info("Reset the inactive lockout account to default")
    return_value = os.system(r"grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7 > \
/ericsson/security/bin/inacive_days.txt")
    if return_value != 0:
        logging.error("Unable to fetch user accounts and its inactive password lockout period")
    else:
        logging.info("Fetched user accounts and its inactive password lockout period")
    with open("/ericsson/security/bin/inacive_days.txt", 'r') as fin:
        data = fin.readlines()
    data1 = []
    for i in data:
        if i != "\n":
            data1 = i.split(':')
            if (data1[0] != "root") and (data1[0] != "storadm"):
                user = data1[0]
                os.system("chage --inactive -1 %s" %user)
    os.system("rm -rf /ericsson/security/bin/inacive_days.txt")
    logging.info("Successfully reset inactive password lock to default")

def reset_su_users():
    """This is to reset su access restriction"""
    check_present = s.check_output("cat /etc/group | grep -iw sugroup | cut -d':' -f 1", shell=True)
    check_present = check_present.strip()
    if check_present != "sugroup":
        logging.info("Sub group is not present in /etc/group")
    else:
        os.system("groupdel sugroup > /dev/null 2>&1")
        logging.info("Successfully reset su restrictions")

def remove_user_added_files():
    """This is to remove the files which are not in backup_config_files folder"""
    rem = ['/etc/audit/rules.d/50-MAC_policy.rules','/etc/audit/rules.d/50-system_local.rules',
           '/etc/audit/rules.d/50-time_change.rules','/etc/audit/rules.d/50-perm_mod.rules',
           '/etc/audit/rules.d/50-mounts.rules','/etc/audit/rules.d/50-access.rules',
           '/etc/audit/rules.d/50-deletion.rules','/etc/audit/rules.d/50-actions.rules',
           '/etc/audit/rules.d/50-modules.rules','/etc/audit/rules.d/99-finalize.rules',
           '/etc/audit/rules.d/50-privileged.rules','/etc/audit/rules.d/50-identity.rules',
           '/etc/audit/rules.d/50-scope.rules' , '/etc/logrotate.d/sudo',
           '/etc/audit/rules.d/50-session.rules', '/etc/audit/rules.d/50-logins.rules']
    is_remove = False
    for file in rem:
        is_remove = True
        log_error("rm -rf "+file+' > /dev/null 2>&1')
        logging.info(file+" Cleaned  ")
    return "Successful" if is_remove else "Terminated(No change)"

def cronjob_roll_back():
    try:
        cron_file = "/ericsson/security/audit/cron_job.txt"
        cron_test = s.check_output("crontab -l", shell=True).split('\n')
        cron_audit = "45 23 * * * /usr/bin/python2.7 /ericsson/security/audit/auditlog_rotate.py \
>> /dev/null 2>&1"
        cron_nh_summary = "0 23 * * 1 /usr/bin/python2.7 \
/ericsson/security/compliance/nh_summary_generate.py >> /dev/null 2>&1"
        if cron_audit in cron_test and cron_nh_summary in cron_test:
            cron_test.remove(cron_audit)
            cron_test.remove(cron_nh_summary)
            f = open(cron_file, "w")
            for item in range(0, len(cron_test)):
                f.write(cron_test[item]+"\n")
            f.close()
        elif cron_audit in cron_test:
            cron_test.remove(cron_audit)
            f = open(cron_file, "w")
            for item in range(0, len(cron_test)):
                f.write(cron_test[item]+"\n")
            f.close()
        elif cron_nh_summary in cron_test:
            cron_test.remove(cron_nh_summary)
            f = open(cron_file, "w")
            for item in range(0, len(cron_test)):
                f.write(cron_test[item]+"\n")
            f.close()
        else:
          logging.info("Cron job is not present in crontab")
        cmd = 'crontab /ericsson/security/audit/cron_job.txt'
        os.system("sed -i \'/^$/d\' /ericsson/security/audit/cron_job.txt")
        os.system(cmd)
        os.system('systemctl restart crond')
    except (IOError, RuntimeError, AttributeError, TypeError, s.CalledProcessError, ValueError):
        print "Error in cron job rollback"
        logging.info("Error in cron job rollback")

def roll_back_rules_configurations():
    '''this function will roll back all the configuration related to audit rules disabling'''
    try:
        os.system('rm -rf /etc/audit/rules.d/50-audit_flag.rules > /dev/null 2>&1')
        logging.info("Successfully removed /etc/audit/rules.d/50-audit_flag.rules")
        os.system('rm -rf /ericsson/security/audit/customized_config.txt > /dev/null 2>&1')
        logging.info("Successfully removed /ericsson/security/audit/customized_config.txt")
        os.system('rm -rf /ericsson/security/audit/customize_flag_status.txt > /dev/null 2>&1')
        logging.info("Successfully removed /ericsson/security/audit/customize_flag_status.txt")
        os.system('rm -rf /ericsson/security/audit/disable_flag_status.txt > /dev/null 2>&1')
        logging.info("Successfully removed /ericsson/security/audit/disable_flag_status.txt")
        os.system('cp /ericsson/security/audit/default_config.txt /ericsson/security/audit/config.txt > /dev/null 2>&1')
        logging.info("Successfully copied default_config.txt > config.txt")
        os.system('rm -rf /ericsson/security/audit/default_config.txt > /dev/null 2>&1')
        logging.info("Successfully removed /ericsson/security/audit/default_config.txt")
    except OSError:
        print("INFO: Rules rollback configuration are not found")

if __name__ == '__main__':
    group_existence = s.check_output("cat /etc/group | grep ENIQ_ADMIN_ROLE | \
cut -d':' -f 1", shell=True).strip()
    if group_existence == "ENIQ_ADMIN_ROLE":
        print "Deactivate the feature to proceed further"
        exit(1)
    print '+'*68+"\x1b[32m\"NODE HARDENING ROLLBACK\"\x1b[0m"+'+'*75+"\n"
    print "NOTE: Reboot is required post successful rolback of node hardening configurations.\
\nServer will reboot automatically post successful rollback.\n"
    choice = raw_input("\033[93m\"Do you still want to proceed with the rollback procedure \
(y/n):?\"\033[00m ")
    restore_script = "NH_Restore.py"
    if (choice == 'y') or (choice == 'Y'):
        timestr = time.strftime("%Y%m%d-%H%M%S")
        fname = timestr + 'NH_Restore.log'
        os.system("mkdir -p /ericsson/NH_Rollback_logs/")
        format_str = '%(levelname)s: %(asctime)s: %(message)s'
        logging.basicConfig(level=logging.DEBUG,
                            filename="/ericsson/NH_Rollback_logs/%s" % fname,
                            format=format_str)
        LOG_PATH = "/ericsson/NH_Rollback_logs/%s" % fname
        logger(0, restore_script, LOG_PATH)
        conf = {'/etc/ssh/sshd_config': 'SSH Server configuration',
                '/etc/ssh/ssh_config':'SSH Client Configuration',
                '/etc/profile':'User Profile Configuration',
                '/etc/login.defs':'Password Expire Configuration for Non-system users(UID > 999)',
                '/etc/logrotate.d/syslog':'Logrotate Configuration',
                '/etc/logrotate.d/cron': 'Logrotate Configuration',
                '/etc/pam.d/system-auth':'Pasword Complexity Configuration',
                '/etc/pam.d/password-auth':'Password Complexity Configuration',
                '/etc/sysctl.conf':'ICMP Broadcast Configuration',
                '/etc/cron.allow':'Cron Allow Configuration',
                '/etc/cron.deny':'Cron Deny Configuration', '/etc/at.allow':'Allowed at Jobs',
                '/etc/at.deny':'Denied at Jobs', '/etc/hosts.allow':'TCP Allow',
                '/etc/hosts.deny': 'TCP Deny', '/etc/issue.net':'Pre Login Banner',
                '/etc/motd':'Post Login Banner',
                '/etc/audit/rules.d/audit.rules':'Audit configurations',
                '/root/.bash_profile':'ensure root PATH integrity',
                '/etc/pam.d/su':'su restriction Configuration',
                '/etc/issue':'Local Pre Login Banner',
                '/etc/pam.d/sudo-i':'disabling custom user to use sudo -i'}
        if not os.path.exists('/ericsson/security/BACKUP_CONFIG_FILES/'):
            print "\33[31m Error \033[0m: Backup Directory Not Found"
            logging.error("\33[31m Backup Directory Not Found \033[0m")
            logger(1, restore_script, LOG_PATH)
            exit(1)
        sever = configure_server()
        if sever != 'MWS' and sever != 'ENIQ':
            print "\33[31m Error \033[0m: Server Not Configured"
            logging.error("\33[31m Server Not Configured  \033[0m")
            logger(1, restore_script, LOG_PATH)
            exit(1)
        file_list = s.check_output("ls /ericsson/security/BACKUP_CONFIG_FILES/", shell=True).split()
        if file_list != []:
            logging.info("Restoring Configuration Files")
            print "INFO: Restoring Configuration Files"
            restore_files(file_list, conf)
            print "INFO: Restored Configuration Files"
            logging.info("Restored Configuration Files")
        if os.path.exists('/ericsson/security/BACKUP_CONFIG_FILES/icmp_config'):
            logging.info("Restoring ICMP Configuration")
            print "INFO: Restoring ICMP Configuration"
            restore_icmp()
            print "INFO: Restored ICMP Configuration"
            logging.info("Restored ICMP Configuration")
        if os.path.exists('/ericsson/security/BACKUP_CONFIG_FILES/INTRFC_CONFIG_FILES/'):
            logging.info("Restoring Network Interface Files")
            print "INFO: Restoring Network Interface Files"
            restore_static_ip()
            print "INFO: Restored Interface Files"
            logging.info("Restored Network Interface Files")
        logging.info("Initiated Clean-up Node hardening configurations")
        print "INFO: Initiated Clean-up Node hardening configurations"
        output = remove_files(file_list)
        logging.info("Node hardening Configuration clean-up "+output)
        print "INFO: Node hardening Configuration clean-up "+output
        logging.info("Restoring default Inactive User Account Lock")
        print "INFO: Restoring default Inactive User Account Lock"
        reset_inactive()
        logging.info("Restoring su access restriction")
        print "INFO: Restoring su access restriction"
        reset_su_users()
        logging.info("Restoring the scheduled cron jobs")
        print "INFO: Restoring the scheduled cron jobs"
        cronjob_roll_back()
        logging.info("Restored the scheduled cron jobs")
        print "INFO: Restored the scheduled cron jobs"
        logging.info("Removing the customised rules configurations")
        print "INFO: Removing the customised rules configurations"
        roll_back_rules_configurations()
        logging.info("Removed the customised rules configurations")
        print "INFO: Removed the customised rules configurations"
        logging.info("Restoring Firewall Configurations")
        print "INFO: Restoring Firewall Configurations"
        remove_ports()
        logging.info("Firewall configurations are restored")
        print "INFO: Firewall configurations are restored"
        print "INFO: Initiated Clean-up of user added configuration files"
        output = remove_user_added_files()
        print "INFO: User added configuration files clean-up "+output
        ctrl_status = commands.getoutput("systemctl status ctrl-alt-del.target")
        if os.path.exists('/ericsson/security/BACKUP_CONFIG_FILES/mask_config'):
            if 'reboot.target' in open('/ericsson/security/BACKUP_CONFIG_FILES/mask_config').read()\
 and 'reboot.target' not in ctrl_status:
                log_error("systemctl unmask ctrl-alt-del.target > /dev/null 2>&1")
                print "INFO: ctrl+alt+del has been Restored"
                logging.info("ctrl+alt+del has been Restored")
            else:
                print "INFO: ctrl-alt-del is already unmasked!"
        if os.path.exists('/ericsson/security/BACKUP_CONFIG_FILES/open_ports_config'):
            logging.info("Restoring Ports Configuration")
            print "INFO: Restoring Ports Configuration"
            restore_firewall()
            logging.info("Restored Ports Configuration ")
            print "INFO: Restored Ports Configuration"
        else:
            logging.info("Disabling and Stoping Firewall")
            print "INFO: Disabling and Stoping Firewall"
            log_error("systemctl stop firewalld > /dev/null 2>&1")
            log_error("systemctl disable firewalld > /dev/null 2>&1")
            logging.info("Disabled and Stoped Firewall")
            print "INFO: Disabled and Stoped Firewall"
        if os.path.exists('/ericsson/security/BACKUP_CONFIG_FILES/0etc0selinux0config'):
            logging.info("Restoring SELinux Configuration")
            print "INFO: Restoring SELinux Configuration"
            log_error("cp -p /ericsson/security/BACKUP_CONFIG_FILES/0etc0selinux0config \
/etc/selinux/config  > /dev/null 2>&1")
            logging.info("SELinux has been Restored ")
            logging.info("Restored SELinux Configuration")
            print "INFO: Restored SELinux Configuration"
        logging.info("Reset the file permissions to default")
        print "INFO: Resetting the file permissions to default"
        reset_permission()
        print("\nChanging the log file permissions\n")
        logging.info("\nChanging the log file permissions\n")
        change_permissions(['/ericsson/NH_Rollback_logs'], 0o640)
        os.system("setfacl -d -m other::000 /ericsson/NH_Rollback_logs 1> /dev/null 2>&1")
        print "INFO: Rebooting the server"
        logging.info("Rebooting the server")
        logger(1, restore_script, LOG_PATH)
        os.system("reboot")
    elif (choice == 'n') or (choice == 'N'):
        exit(1)
    else:
        print "Invalid Option\n"
        exit(1)
