#!/usr/bin/python
"""
#*********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
#*********************************************************************
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
# Name      : auditlog_rotate.py
# Purpose   : Script compression & deletion all the logs and zipped files
#             present in /var/log/audit
# Reason    : EQEV-100494,EQEV-116781,EQEV-120843
# Revision  : B
# ********************************************************************
"""
import os
import glob
import logging
import time
import subprocess
import zipfile
import datetime
from datetime import datetime

def logfile(sorted_audit_list):
    '''This fucntions fetches the first and last date stamp from first and last log file'''
    lastlog_file = sorted_audit_list[-1]
    data1 = "head -n 1 " + lastlog_file + " | cut -d \")\" -f 1 \
| cut -d \"(\" -f 2 | cut -d \":\" -f 1 | cut -d \".\" -f 1"
    first_datestamp = subprocess.check_output(data1, shell=True, stderr=subprocess.PIPE)
    timestamp = float(first_datestamp)
    dt1 = datetime.fromtimestamp(timestamp//1).replace(microsecond=int((timestamp%1)*1000000))
    date_str1 = dt1.strftime("%Y%m%d-%H%M%S")

    firstlogfile =sorted_audit_list[0]
    data2 = "cat " + firstlogfile + "  | tail -n 1 | cut -d \")\" -f 1 \
| cut -d \"(\" -f 2 | cut -d \":\" -f 1 | cut -d \".\" -f 1"
    last_datestamp = subprocess.check_output(data2, shell=True, stderr=subprocess.PIPE)
    timestamp = float(last_datestamp)
    dt2 = datetime.fromtimestamp(timestamp//1).replace(microsecond=int((timestamp%1)*1000000))
    date_str2 = dt2.strftime("%Y%m%d-%H%M%S")

    return date_str1, date_str2


def audit_log_list_sorting(element):
    '''Sort the audit log list on the basis of length of element'''
    return len(element)

def get_audit_file(audit_path):
    '''Getting all the audit.log into list'''
    try:
        file_item = []
        count = 0
        for path, dirs, files in os.walk(audit_path):
            for f in files:
                fp = os.path.join(path, f)
                if os.path.getsize(fp) > 9.9e+7 and not fp.endswith('.zip'):
                    count = count+1
                    file_item.append(fp)
        sorted_audit_list = sorted(file_item, reverse=False)
        sorted_audit_list.sort(key=audit_log_list_sorting)
        return sorted_audit_list
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in get audit file')

def batch_zipping_list(batch_list):
    '''This function takes audit log as batch list and compress them into one single zip file'''
    try:
        current_time = time.strftime("%Y%m%d-%H%M%S")
        update_batch_list = []
        for file in range(0, len(batch_list)):
            list1 = batch_list[file][0:14]+'/'+current_time+'-'
            list2 = batch_list[file][15:]
            final_list = list1+list2
            update_batch_list.append(final_list)
            os.rename(str(batch_list[file]),str(final_list))
            logging.info("1. Old audit name %s, 2. Updated audit name %s", str(batch_list[file]),str(final_list))
        logging.info("updated batch zip list %s :", update_batch_list)
        date_str1, date_str2 = logfile(update_batch_list)
        date_range = date_str1 +"-" + date_str2
        zip_path = "/var/log/audit/"+"auditLog-"+date_range+".zip"
        zip_obj = zipfile.ZipFile(zip_path, 'w')
        for files in range(0, len(update_batch_list)):
            zip_obj.write(update_batch_list[files], compress_type=zipfile.ZIP_DEFLATED)
            logging.info("%s files go for batch zipping",update_batch_list[files])
            os.unlink(update_batch_list[files])
            logging.info("Successfully removed the file after batch zipping %s", update_batch_list[files])
        zip_obj.close()
        logging.info("Batch zipping is done successfully.")
    except(IOError, RuntimeError, AttributeError, TypeError,OSError):
        logging.error('Error occured in batch zipping')

def get_batch_zipping_list(audit_list):
    '''
    This function takes audit log as list and divide them into 10 number audit
    log into one batch and then further perform zipping into one zip file
    '''
    try:
        audit_list_len = len(audit_list)
        audit_not_to_be_deleted = audit_list_len%10
        motd_list = audit_list[audit_not_to_be_deleted:audit_list_len]
        count = 0
        temp_list = []
        for files in range(0, len(motd_list)):
            temp_list.append(motd_list[files])
            count = count+1
            if count == 10:
                batch_zipping_list(temp_list)
                break
        res = [i for i in motd_list if i not in temp_list]
        motd_list = res
        if len(motd_list) != 0:
            get_batch_zipping_list(motd_list)
            res = [i for i in motd_list if i not in temp_list]
            motd_list = res
        else:
            logging.info("***No item is present left for further batching***")
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in get batch zip')

def delete_oldest_zipped():

    ''' This function with deletes audit logs on the basis FIFO order creation of zip file
        to free up 1GB space
    '''
    try:
        files = glob.glob(os.path.expanduser("/var/log/audit/*.zip"))
        sorted_by_mtime_ascending = sorted(files, key=lambda t: os.stat(t).st_mtime)
        total_zip_size = 0
        zipped_item_deleted = []
        for audit_file in range(0, len(sorted_by_mtime_ascending)):
            total_zip_size += os.path.getsize(sorted_by_mtime_ascending[audit_file])/1048576
            if total_zip_size <=1060 :
                freed_space = total_zip_size
                zipped_item_deleted.append(sorted_by_mtime_ascending[audit_file])
        for item in range(0, len(zipped_item_deleted)):
            logging.info("zipped logs gets delete:%s",zipped_item_deleted[item])
            os.unlink(zipped_item_deleted[item])
        logging.info("*** %s MB of space freed from /var/log/audit***",freed_space)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured in deletion of oldest zip')

def audit_file_compression_deletion(audi_log_list):
    '''
    function do if audit dir log length is less then 10 number of logs
    then no operation will be perform else batch zipping will be happen.
    '''
    try:
        audit_list_len = len(audi_log_list)
        if  audit_list_len<10:
            logging.info('Number of audit log are less then 10 so no zipping and deletion required')
        else:
            logging.info("All files should be zipped as it more then 10 files")
            get_batch_zipping_list(audit_log_list)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured when log length is less then 10')

def audit_main(current_audit_size,limit_audit_dir, audi_log_list, get_audit_size_string):
    ''' This function do the deletion and compression of logs and zipped files'''
    try:
        logging.info("Current size:%s KB & Max size %s KB",current_audit_size, int(limit_audit_dir))
        #Checking the current directory size and and audit directory limit size
        if int(current_audit_size) >= int(limit_audit_dir):
            try:
                logging.info("***Audit file deletion started****")
                delete_oldest_zipped()
                logging.info("***Audit file deletion ends***")
                logging.info("***Audit log compression started***")
                audit_file_compression_deletion(audi_log_list)
                logging.info("***Audit log compression finished***")
            except (FileNotFoundError, OSError):
                logging.info("Exception occured")
        else:
            logging.info("***Audit dir is less then 9GB so ziping and remove all the logs***")
            audit_file_compression_deletion(audi_log_list)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Error occured while doing audit log deletion & compression')

def file_permission(audit_path):
    '''
    Changes the permission of zip files present in /var/log/audit/
    '''
    try:
        for path, dirs, files in os.walk(audit_path):
            for f in files:
                fp = os.path.join(path, f)
                if fp.endswith('.zip'):
                    os.system("chmod 400 "+fp)
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error('Failed to change permission!!')

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_auditlog_rotate.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/audit_cron")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/audit_cron/%s" % fname,
                        format=FORMAT_STRING)
    audit_log_list = get_audit_file('/var/log/audit/')
    get_audit_size_string = subprocess.check_output("du -sh /var/log/audit", shell=True).split()[0]
    current_audit_size_kb = subprocess.check_output("du /var/log/audit", shell=True).split()[0]
    # 9e+6 equal to 9GB
    AUDIT_DIR_LIMIT_KB  = 9e+6
    audit_main(current_audit_size_kb,AUDIT_DIR_LIMIT_KB, audit_log_list, get_audit_size_string)
    file_permission('/var/log/audit/')
