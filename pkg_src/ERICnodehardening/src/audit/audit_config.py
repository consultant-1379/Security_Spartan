#!/usr/bin/python
"""This script helps to list and configure auditlog rules."""
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
# Name      : audit_config.py
# Purpose   : This script helps to list and configure auditlog rules.
#
# ********************************************************************
import os
import logging
import time
import subprocess
import sys
import shutil

sys.path.insert(0, '/ericsson/security/bin')
from NH_Backup import backup_files
RESTART = "service auditd restart 2>&1 >> /dev/null"

class Logaudit:
    """ This class will list and configure the rules """
    def __init__(self):
        self.write_path = "/etc/audit/rules.d/audit.rules"
        self.fname = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/"
        backup_files(self.write_path, [])
    def logging_header(self):
        """This function is for generating log file for manual execution"""
        timestr = time.strftime("%Y%m%d-%H%M%S")
        self.fname = '/ericsson/security/log/Apply_NH_Logs/Manual_Exec/'+timestr + '_auditlog'
        format_str = '%(levelname)s: %(asctime)s: %(message)s'
        os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
        logging.basicConfig(level=logging.DEBUG, filename=self.fname, format=format_str)
        open(self.fname, 'a').write('*'*95+'\n')
        host = subprocess.check_output('hostname', shell=True).replace('\n', '')
        open(self.fname, 'a').write(host+' '*(95-len(host)-len(timestr))+timestr+'\n')
        open(self.fname, 'a').write('audit_config.py\n')
        open(self.fname, 'a').write('*'*95+'\n')
    def logging_footer(self):
        """This function is for genarating log file footer for manual execution"""
        open(self.fname, 'a').write('*'*95+'\nLog file location:\n')
        open(self.fname, 'a').write(self.fname+'\n'+'*'*95+'\n')
        print "Script logs are saved at : \033[93m %s \033[00m" % self.fname
        os.chmod(self.fname, 0o440)
    # pylint: disable=R0201
    def update_auditd(self):
        """ Function to update the auditd.conf file """
        path = "/etc/audit/auditd.conf"
        input_path = "/ericsson/security/config/audit_input.cfg"
        size, count = 0, 0
        if not os.path.exists(input_path):
            print "Audit configuration input file (/ericsson/security/config/audit_input.cfg) \
not available on the server."
            logging.error("Audit configuration input file \
(/ericsson/security/config/audit_input.cfg) not available on the server.")
            return False
        with open(input_path, 'r') as f_read:
            inputs = f_read.read().split('\n')
        for inpt in inputs:
            try:
                if 'max log file size' in inpt:
                    size = int(inpt.split(':')[1].strip())
                elif 'max number of log files' in inpt:
                    count = int(inpt.split(':')[1].strip())
            except ValueError:
                print "\033[91mPlease enter integer only in input file \
(/ericsson/security/config/audit_input.cfg)\033[00m"
                logging.error("Non-integer is provided as input. Integer expected in input file \
(/ericsson/security/config/audit_input.cfg)")
                return False
        if size <= 0 or size > 100 or count <= 0 or count > 100:
            print "\033[91m {}\033[00m".format("The given value is wrong,\
please provide the value between 1-100")
            logging.error("Value provided is wrong,value must be between 1-100")
            return False
        with open(path, 'r')as wrt:
            read_log = wrt.readlines()
        with open(path, 'w')as wrt1:
            for i in read_log:
                if "max_log_file =" in i:
                    wrt1.write("max_log_file = "+str(size) + '\n')
                elif "num_logs =" in i:
                    wrt1.write("num_logs = "+str(count) + '\n')
                else:
                    wrt1.write(i)
        wrt1.close()
        logging.info("Audit is configured with provided inputs")
        return True
    # pylint: disable=R0201
    def check_service(self):
        """This Function to check the service and return the status"""
        active_status = subprocess.check_output("systemctl status auditd | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
        enabled_status = subprocess.check_output("systemctl status auditd | sed -n '/Loaded:/p' | \
cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)
        if active_status != "active\n" or enabled_status != "enabled\n":
            os.system(RESTART)
            logging.info('Service Status is active and enabled')
    def add_rules(self):
        """ This function to add the rules to the audit.rules """
        added_rules = ""
        read_path = "/ericsson/security/audit/config.txt"
        with open(read_path, 'r') as wrt:
            file_read = wrt.readlines()
        with open(self.write_path, 'w+') as wrt1:
            file_write = wrt1.readlines()
            for i in file_read:
                if i not in file_write:
                    wrt1.write(i)
                    added_rules += i+'\n'
        wrt1.close()
        if added_rules:
            try:
                os.system(RESTART)
                print "\nRestarting the Auditd service. . . . . ."
                print "\n**********Audit rules configured Successfully**********\n"
                open('/ericsson/security/log/Apply_NH_Logs/post_audit_\
rules.txt', 'w').write(added_rules)
                logging.info('Audit rules added are in /ericsson/security/log/Apply_NH_Logs/\
added_rules.txt')
                logging.info('Auditd Restarted Successfully')
            except (IOError,FileNotFoundError):
                print "Auditd Service restart : Failed. Check the logs here-"+\
                      "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/"
                logging.info('Failed to restart the auditd service')
                return False
        else:
            print "\n**********Audit Rules already configured**********\n"
            logging.info('Rules already configured to /etc/audit/rules.d/audit.rules')
        return True
    def service_check(self):
        """service check function act based on the user input,
        it handles the operations list and configuration"""
        os.system(RESTART)
        try:
            try:
                configured_rules = subprocess.check_output("auditctl -l", shell=True)
                timestr = time.strftime("%Y%m%d-%H%M%S")
                open('/ericsson/security/log/Apply_NH_Logs/'+timestr+'_pre_auditd_rules.txt', \
'w').write(configured_rules)
                print "\n**********Listing Audit Rules already configured on  the system in \
/ericsson/security/log/Apply_NH_Logs/%s_pre_auditd_rules.txt**********" % timestr
                logging.info('Audit rules added are in /ericsson/security/log/Apply_NH_\
Logs/%s_pre_auditd_rules.txt', timestr)

            except subprocess.CalledProcessError as E:
                print "Not able to list configured rules"
                logging.info("Not able to list configured rules. Error found:\n%s", E.output)
                return False
            if not self.update_auditd():
                return False
            if os.path.exists(self.write_path):
                self.check_service()
                if not self.add_rules():
                    return False
            else:
                print "Error: '/etc/audit/rules.d/audit.rule' file not available!!! " + \
                      "check with the Administrator"
                logging.warning("Audit file is not available please check with the Administrator")
                return False
        except KeyboardInterrupt:
            print "\nScript exited abnormally!!!"
            logging.error('Script exited abnormally')
            return False
        return True

    # pylint: disable=R0201
    def default_config_backup(self):
        '''This function will take default backup of config.txt'''

        if os.path.exists("/ericsson/security/audit/default_config.txt")is True:
            logging.info("Default configuration back up file is already present")
        else:
            os.system("touch /ericsson/security/audit/default_config.txt")
            shutil.copyfile("/ericsson/security/audit/config.txt",
                            "/ericsson/security/audit/default_config.txt")
            logging.info("Default configuration back up file is created.")
    # pylint: disable=R0201
    def check_flags_file(self):
        '''Retain the default flag
        '''
        try:
            if os.path.exists("/etc/audit/rules.d/50-audit_flag.rules") is True:
                logging.info("Found flag rules file --> 50-audit_flag.rules")
            else:
                os.system("touch /etc/audit/rules.d/50-audit_flag.rules")
                with open("/etc/audit/rules.d/50-audit_flag.rules", 'w') as flag_file:
                    flag_file.writelines("## First rule - delete all\n"+"-D\n")
                    flag_file.writelines("## Increase the buffers to survive stress events.\n"+
                                         "## Make this bigger for busy systems\n"+
                                         "-b 8192\n")
                    flag_file.writelines("## Set failure mode to syslog\n"+"-f 1\n")
                    flag_file.close()
                    logging.info("50-audit_flag.rules created to store default audit flag")
        except IOError:
            logging.error('Unable to detect/create/update flag rules file --> 50-audit_flag.rules')
    # pylint: disable=R0201
    def check_customized_rules(self):
        '''Restore the last backup customised rules to config.txt
        '''
        try:
            if os.path.exists("/ericsson/security/audit/customize_flag_status.txt") is True:
                logging.info("Customization flag status file is found")
                with open("/ericsson/security/audit/customize_flag_status.txt", 'r+') as f_status:
                    lines = f_status.readlines()
                    for _, line in enumerate(lines):
                        if line == "DISABLE_FLAG_STATUS 1":
                            logging.info("Found customized rules, retaining the same over upgrade.")
                            shutil.copyfile("/ericsson/security/audit/customized_config.txt",
                                            "/ericsson/security/audit/config.txt")
                            logging.info("Retained Customized rules over upgrade.")
                    f_status.close()
        except OSError:
            logging.info("Failed to retain Customized Audit rules. Ensure no files are\
 deleted/moved!!!")

if __name__ == "__main__":
    OBJ = Logaudit()
    OBJ.logging_header()
    OBJ.check_flags_file()
    OBJ.default_config_backup()
    OBJ.check_customized_rules()
    STATUS = OBJ.service_check()
    OBJ.logging_footer()
    if not STATUS:
        exit(1)