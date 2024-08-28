################################################################
#
# This is ERICnodehardening Product Spec File
#
################################################################
%define CXP CXP9037099
###############################################################
Summary:    ERIC nodehardening package
Name:       ERICnodehardening
Version:  R1A
Release: 00
Group:      Ericsson/ENIQ_STATS
Packager:   XNAVVIJ
BuildRoot:  %{_builddir}/%{name}_%{CXP}-%{version}%{release}
License: Ericsson AB @2019
#################################################################
%define _rpmfilename %{name}-%{version}%{release}.rpm
%description
This is the ERICnodehardening RPM package
%prep
rm -rf $RPM_BUILD_ROOT
# extract the tar file containing all the sources, to the build directory.
cd %{_sourcedir}
ls -lrt %{_sourcedir}/ERIC*
/bin/tar -xvf %{_sourcedir}/ERIC*.tar
#%build
#echo "Building the project..."
%install
#rm -rf $RPM_BUILD_ROOT
install -d -m 755 $RPM_BUILD_ROOT/ericsson/security/audit
install -d -m 755 $RPM_BUILD_ROOT/ericsson/security/compliance
install -d -m 755 $RPM_BUILD_ROOT/ericsson/security/bin
install -d -m 755 $RPM_BUILD_ROOT/ericsson/security/log
install -d -m 755 $RPM_BUILD_ROOT/ericsson/security/config
cd %{_sourcedir}/src/bin
cp -r * $RPM_BUILD_ROOT/ericsson/security/bin
cd %{_sourcedir}/src/compliance
cp * $RPM_BUILD_ROOT/ericsson/security/compliance
cd %{_sourcedir}/src/audit
cp * $RPM_BUILD_ROOT/ericsson/security/audit
cd %{_sourcedir}/src/config
cp * $RPM_BUILD_ROOT/ericsson/security/config
%files
%defattr(755,root,root)
##### bin files list
/ericsson/security/bin/Apply_Node_Hardening.py
/ericsson/security/bin/list_rpms.py
/ericsson/security/bin/configure_sshd.py
/ericsson/security/bin/set_autologout.py
/ericsson/security/bin/add_cipher.py
/ericsson/security/bin/enable_firewall.py
/ericsson/security/bin/configure_icmp.py
/ericsson/security/bin/enforce_selinux.py
/ericsson/security/bin/set_password_aging.py
/ericsson/security/bin/set_ssh_banner.py
/ericsson/security/bin/capture_performance.py
/ericsson/security/bin/list_inactive_users.py
/ericsson/security/bin/set_password_policy.py
/ericsson/security/bin/set_history_logging.py
/ericsson/security/bin/restrict_cron.py
/ericsson/security/bin/set_cron_log.py
/ericsson/security/bin/enable_ssh_login.py
/ericsson/security/bin/set_umask.py
/ericsson/security/bin/restrict_at.py
/ericsson/security/bin/disable_SR.py
/ericsson/security/bin/reboot.py
/ericsson/security/bin/reverse_fwd.py
/ericsson/security/bin/set_grace_time.py
/ericsson/security/bin/tcp_wrappers.py
/ericsson/security/bin/Cron_Log
/ericsson/security/bin/at_conf
/ericsson/security/bin/banner_ssh
/ericsson/security/bin/username
/ericsson/security/bin/cron_conf
/ericsson/security/bin/disable_icmp_broadcast.py
/ericsson/security/bin/mask_alt_ctrl_del.py
/ericsson/security/bin/verify_static_ip_config.py
/ericsson/security/bin/enable_sticky_bit.py
/ericsson/security/bin/enable_ssh_proto_v2.py
/ericsson/security/bin/disable_access_suid.py
/ericsson/security/bin/verify_ip_config.py
/ericsson/security/bin/set_motd_banner.py
/ericsson/security/bin/banner_motd
/ericsson/security/bin/Verify_NH_Config.py
/ericsson/security/bin/disable_AllowTcpForwarding.py
/ericsson/security/bin/disable_X11Forwarding.py
/ericsson/security/bin/enable_sshHostKey_verification.py
/ericsson/security/bin/disable_Ipv6_autoconf.py
/ericsson/security/bin/disable_GatewayPorts.py
/ericsson/security/bin/gpgenable.sh
/ericsson/security/bin/encrypt.sh
/ericsson/security/bin/spinner.sh
/ericsson/security/bin/enable_pwd_aging.py
/ericsson/security/bin/NH_Backup.py
/ericsson/security/bin/NH_Restore.py
/ericsson/security/bin/spinner_suid.sh
/ericsson/security/bin/vlan_ssh_restriction.py
/ericsson/security/bin/vlan_ssh_restriction_permanent.py
/ericsson/security/bin/vlan_ssh_restriction_rollback.py
/ericsson/security/bin/enable_firewall_policy.py
/ericsson/security/bin/sentinel_hardening.py
/ericsson/security/bin/sentinel_hardening_rollback.py
/ericsson/security/bin/pre_nh_checks.py
/ericsson/security/bin/stor_pass_change.py
/ericsson/security/bin/set_file_permissions.py
/ericsson/security/bin/set_passd_change_days.py
/ericsson/security/bin/pwd_change_days_rollback.py
/ericsson/security/bin/disable_icmp_responses.py
/ericsson/security/bin/disable_ipv6_advertisements.py
/ericsson/security/bin/disable_secure_icmp.py
/ericsson/security/bin/enable_reverse_path_filter.py
/ericsson/security/bin/enable_suspicious_packets.py
/ericsson/security/bin/enable_tcp_syncookies.py
/ericsson/security/bin/set_inactive_days.py
/ericsson/security/bin/add_keyexchng_algorithm.py
/ericsson/security/bin/enforce_ssh_timeout.py
/ericsson/security/bin/set_maxauthtries.py
/ericsson/security/bin/set_path_integrity.py
/ericsson/security/bin/su_restriction.py
/ericsson/security/bin/set_maxstartups.py
/ericsson/security/bin/infra_nh.py
/ericsson/security/bin/disable_hostbasedAuthentication.py
/ericsson/security/bin/disable_ssh_emptypasswords.py
/ericsson/security/bin/disable_ssh_userenvironment.py
/ericsson/security/bin/enable_ignoreRhosts.py
/ericsson/security/bin/ensure_date_time_info.py
/ericsson/security/bin/ensure_file_deletion.py
/ericsson/security/bin/ensure_system_access.py
/ericsson/security/bin/ensure_system_network.py
/ericsson/security/bin/discretionary_access_control.py
/ericsson/security/bin/ensure_file_auth.py
/ericsson/security/bin/ensure_sys_admin_cmd.py
/ericsson/security/bin/enforce_system_mount.py
/ericsson/security/bin/ensure_kernel_module.py
/ericsson/security/bin/ensure_auditconf_immutable.py
/ericsson/security/bin/ensure_user_priviliged_cmd.py
/ericsson/security/bin/ensure_user_group_info.py
/ericsson/security/bin/ensure_sys_admin_scope.py
/ericsson/security/bin/enable_sftp.py
/ericsson/security/bin/disable_sftp.py
/ericsson/security/bin/cron_sftp.py
/ericsson/security/bin/password_policies_rollback.py
/ericsson/security/bin/pwd_creation_policies.py
/ericsson/security/bin/remove_kex_algos.py
/ericsson/security/bin/nh_verification.py
/ericsson/security/bin/user_verification.py
/ericsson/security/bin/dcuser_ssh_login.py
/ericsson/security/bin/disable_ssh_login.py
/ericsson/security/bin/reenable_ssh_login.py
/ericsson/security/bin/ssh_rollback_adminrole.py
/ericsson/security/bin/inter_blade_access.py
/ericsson/security/bin/disable_dcuser_ssh_access.py
/ericsson/security/bin/restore_ssh_login.py
/ericsson/security/bin/sshd_service_restart.py
/ericsson/security/bin/remove_privileged_ssh_access.py
/ericsson/security/bin/sudologs_rotate.py
/ericsson/security/bin/disable_root_switch.py
/ericsson/security/bin/node_hardening.py
/ericsson/security/bin/nh_summary.py
/ericsson/security/bin/ensure_login_logout_events.py
/ericsson/security/bin/ensure_session_info.py
/ericsson/security/bin/configure_granular_features.py
#### /ericsson/security/bin/rollback
/ericsson/security/bin/rollback/add_cipher_rollback.py
/ericsson/security/bin/rollback/add_keyexchng_algorithm_rollback.py
/ericsson/security/bin/rollback/configure_sshd_rollback.py
/ericsson/security/bin/rollback/disable_allowtcp_forwarding_rollback.py
/ericsson/security/bin/rollback/disable_hostbasedauthentication_rollback.py
/ericsson/security/bin/rollback/disable_ssh_emptypasswords_rollback.py
/ericsson/security/bin/rollback/disable_gatewayports_rollback.py
/ericsson/security/bin/rollback/disable_ssh_userenvironment_rollback.py
/ericsson/security/bin/rollback/disable_x11_forwarding_rollback.py
/ericsson/security/bin/rollback/enable_ssh_hostkey_verification_rollback.py
/ericsson/security/bin/rollback/enable_ignorerhosts_rollback.py
/ericsson/security/bin/rollback/enable_ssh_login_rollback.py
/ericsson/security/bin/rollback/enable_ssh_proto_v2_rollback.py
/ericsson/security/bin/rollback/enforce_ssh_timeout_rollback.py
/ericsson/security/bin/rollback/set_motd_banner_rollback.py
/ericsson/security/bin/rollback/set_maxauthtries_rollback.py
/ericsson/security/bin/rollback/set_maxstartups_rollback.py
/ericsson/security/bin/rollback/set_ssh_banner_rollback.py
/ericsson/security/bin/rollback/set_autologout_rollback.py
/ericsson/security/bin/rollback/set_grace_time_rollback.py
/ericsson/security/bin/rollback/set_password_aging_rollback.py
/ericsson/security/bin/rollback/set_umask_rollback.py
/ericsson/security/bin/rollback/restrict_at_rollback.py
/ericsson/security/bin/rollback/restrict_cron_rollback.py
/ericsson/security/bin/rollback/set_inactive_days_rollback.py
/ericsson/security/bin/rollback/tcp_wrappers_rollback.py
/ericsson/security/bin/rollback/discretionary_access_control_rollback.py
/ericsson/security/bin/rollback/enforce_system_mount_rollback.py
/ericsson/security/bin/rollback/ensure_date_time_info_rollback.py
/ericsson/security/bin/rollback/ensure_file_auth_rollback.py
/ericsson/security/bin/rollback/ensure_file_deletion_rollback.py
/ericsson/security/bin/rollback/ensure_kernel_module_rollback.py
/ericsson/security/bin/rollback/ensure_login_logout_events_rollback.py
/ericsson/security/bin/rollback/ensure_session_info_rollback.py
/ericsson/security/bin/rollback/ensure_sys_admin_cmd_rollback.py
/ericsson/security/bin/rollback/ensure_sys_admin_scope_rollback.py
/ericsson/security/bin/rollback/ensure_system_access_rollback.py
/ericsson/security/bin/rollback/ensure_system_network_rollback.py
/ericsson/security/bin/rollback/ensure_user_group_info_rollback.py
/ericsson/security/bin/rollback/ensure_user_priviliged_cmd_rollback.py
/ericsson/security/bin/rollback/disable_root_switch_rollback.py
/ericsson/security/bin/rollback/set_file_permission_rollback.py
/ericsson/security/bin/rollback/set_path_integrity_rollback.py
/ericsson/security/bin/rollback/su_restriction_rollback.py
/ericsson/security/bin/rollback/disable_access_suid_rollback.py
/ericsson/security/bin/rollback/configure_icmp_rollback.py
/ericsson/security/bin/rollback/disable_Ipv6_autoconf_rollback.py
/ericsson/security/bin/rollback/disable_SR_rollback.py
/ericsson/security/bin/rollback/disable_icmp_broadcast_rollback.py
/ericsson/security/bin/rollback/disable_icmp_responses_rollback.py
/ericsson/security/bin/rollback/disable_ipv6_advertisements_rollback.py
/ericsson/security/bin/rollback/disable_secure_icmp_rollback.py
/ericsson/security/bin/rollback/enable_reverse_path_filter_rollback.py
/ericsson/security/bin/rollback/enable_suspicious_packets_rollback.py
/ericsson/security/bin/rollback/enable_tcp_syncookies_rollback.py
/ericsson/security/bin/rollback/verify_static_ip_config_rollback.py
#### /ericsson/security/log
/ericsson/security/log
#### /ericsson/security/config
/ericsson/security/config/IP_Whitelisting.cfg
/ericsson/security/config/SSH_VLAN_restriction.cfg
/ericsson/security/config/audit_input.cfg
#### compliance file list
/ericsson/security/compliance/verify_audit.py
/ericsson/security/compliance/grace_time_audit.py
/ericsson/security/compliance/verify_ip_config.py
/ericsson/security/compliance/verify_selinux.py
/ericsson/security/compliance/history_logging_audit.py
/ericsson/security/compliance/verify_listing_rpms.py
/ericsson/security/compliance/verify_ssh_login.py
/ericsson/security/compliance/cron_log_audit.py
/ericsson/security/compliance/login.sh
/ericsson/security/compliance/verify_mask.py
/ericsson/security/compliance/verify_ssh_v2.py
/ericsson/security/compliance/NH_Compliance.py
/ericsson/security/compliance/verify_autologout.py
/ericsson/security/compliance/verify_static_ip.py
/ericsson/security/compliance/verify_cipher.py
/ericsson/security/compliance/verify_password_age.py
/ericsson/security/compliance/verify_suid.py
/ericsson/security/compliance/restrict_at_audit.py
/ericsson/security/compliance/verify_firewall.py
/ericsson/security/compliance/verify_password_policy.py
/ericsson/security/compliance/verify_tcp_wrappers.py
/ericsson/security/compliance/restrict_cron_audit.py
/ericsson/security/compliance/verify_icmp_config.py
/ericsson/security/compliance/verify_pf_logs.py
/ericsson/security/compliance/verify_umask.py
/ericsson/security/compliance/verify_icmp.py
/ericsson/security/compliance/verify_motd_banner.py
/ericsson/security/compliance/verify_reverse_fwd.py
/ericsson/security/compliance/verify_SR.py
/ericsson/security/compliance/verify_sshd_banner.py
/ericsson/security/compliance/verify_sticky_bit.py
/ericsson/security/compliance/verify_agent_fwdng.py
/ericsson/security/compliance/NH_post_patch.py
/ericsson/security/compliance/verify_AllowTCPForwording.py
/ericsson/security/compliance/verify_X11Forwarding.py
/ericsson/security/compliance/verify_sshHostKeyVerification.py
/ericsson/security/compliance/verify_Ipv6_autoconf.py
/ericsson/security/compliance/verify_GatewayPorts.py
/ericsson/security/compliance/passwd.sh
/ericsson/security/compliance/post_nh_checks.py
/ericsson/security/compliance/verify_file_permissions.py
/ericsson/security/compliance/verify_icmp_responses.py
/ericsson/security/compliance/verify_ipv6_advertisements.py
/ericsson/security/compliance/verify_secure_icmp.py
/ericsson/security/compliance/verify_reverse_path_filter.py
/ericsson/security/compliance/verify_suspicious_packets.py
/ericsson/security/compliance/verify_tcp_syncookies.py
/ericsson/security/compliance/verify_inactive.py
/ericsson/security/compliance/verify_keyexchng_algorithm.py
/ericsson/security/compliance/verify_path_integrity.py
/ericsson/security/compliance/verify_set_maxauth.py
/ericsson/security/compliance/verify_ssh_timeout.py
/ericsson/security/compliance/verify_su_restriction.py
/ericsson/security/compliance/verify_set_maxstart.py
/ericsson/security/compliance/verify_hostbasedAuthentication.py
/ericsson/security/compliance/verify_ignoreRhosts.py
/ericsson/security/compliance/verify_ssh_emptypasswords.py
/ericsson/security/compliance/verify_ssh_userenvironment.py
/ericsson/security/compliance/verify_date_time_info.py
/ericsson/security/compliance/verify_file_deletion.py
/ericsson/security/compliance/verify_system_access.py
/ericsson/security/compliance/verify_system_network.py
/ericsson/security/compliance/verify_discec_access.py
/ericsson/security/compliance/verify_file_auth.py
/ericsson/security/compliance/verify_sys_admin_cmd.py
/ericsson/security/compliance/verify_system_mount.py
/ericsson/security/compliance/verify_kernel_module.py
/ericsson/security/compliance/verify_auditconf_immutable.py
/ericsson/security/compliance/verify_user_priviliged_cmd.py
/ericsson/security/compliance/verify_sys_admin_scope.py
/ericsson/security/compliance/verify_user_group_info.py
/ericsson/security/compliance/verify_sudologs_rotate.py
/ericsson/security/compliance/verify_disable_root_switch.py
/ericsson/security/compliance/verify_audit_automate_cron.py
/ericsson/security/compliance/nh_summary_generate.py
/ericsson/security/compliance/verify_login_logout_events.py
/ericsson/security/compliance/verify_session_info.py

%exclude /ericsson/security/compliance/post_nh_checks.pyc
%exclude /ericsson/security/compliance/post_nh_checks.pyo
%exclude /ericsson/security/compliance/verify_audit.pyc
%exclude /ericsson/security/compliance/verify_audit.pyo
%exclude /ericsson/security/compliance/grace_time_audit.pyc
%exclude /ericsson/security/compliance/grace_time_audit.pyo
%exclude /ericsson/security/compliance/verify_ip_config.pyc
%exclude /ericsson/security/compliance/verify_ip_config.pyo
%exclude /ericsson/security/compliance/verify_selinux.pyc
%exclude /ericsson/security/compliance/verify_selinux.pyo
%exclude /ericsson/security/compliance/history_logging_audit.pyc
%exclude /ericsson/security/compliance/history_logging_audit.pyo
%exclude /ericsson/security/compliance/verify_listing_rpms.pyc
%exclude /ericsson/security/compliance/verify_listing_rpms.pyo
%exclude /ericsson/security/compliance/verify_ssh_login.pyc
%exclude /ericsson/security/compliance/verify_ssh_login.pyo
%exclude /ericsson/security/compliance/cron_log_audit.pyc
%exclude /ericsson/security/compliance/cron_log_audit.pyo
%exclude /ericsson/security/compliance/verify_mask.pyc
%exclude /ericsson/security/compliance/verify_mask.pyo
%exclude /ericsson/security/compliance/verify_ssh_v2.pyc
%exclude /ericsson/security/compliance/verify_ssh_v2.pyo
%exclude /ericsson/security/compliance/NH_Compliance.pyc
%exclude /ericsson/security/compliance/NH_Compliance.pyo
%exclude /ericsson/security/compliance/verify_autologout.pyc
%exclude /ericsson/security/compliance/verify_autologout.pyo
%exclude /ericsson/security/compliance/verify_static_ip.pyc
%exclude /ericsson/security/compliance/verify_static_ip.pyo
%exclude /ericsson/security/compliance/verify_cipher.pyc
%exclude /ericsson/security/compliance/verify_cipher.pyo
%exclude /ericsson/security/compliance/verify_password_age.pyc
%exclude /ericsson/security/compliance/verify_password_age.pyo
%exclude /ericsson/security/compliance/verify_suid.pyc
%exclude /ericsson/security/compliance/verify_suid.pyo
%exclude /ericsson/security/compliance/restrict_at_audit.pyc
%exclude /ericsson/security/compliance/restrict_at_audit.pyo
%exclude /ericsson/security/compliance/verify_firewall.pyc
%exclude /ericsson/security/compliance/verify_firewall.pyo
%exclude /ericsson/security/compliance/verify_password_policy.pyc
%exclude /ericsson/security/compliance/verify_password_policy.pyo
%exclude /ericsson/security/compliance/verify_tcp_wrappers.pyc
%exclude /ericsson/security/compliance/verify_tcp_wrappers.pyo
%exclude /ericsson/security/compliance/restrict_cron_audit.pyc
%exclude /ericsson/security/compliance/restrict_cron_audit.pyo
%exclude /ericsson/security/compliance/verify_icmp_config.pyc
%exclude /ericsson/security/compliance/verify_icmp_config.pyo
%exclude /ericsson/security/compliance/verify_pf_logs.pyc
%exclude /ericsson/security/compliance/verify_pf_logs.pyo
%exclude /ericsson/security/compliance/verify_umask.pyc
%exclude /ericsson/security/compliance/verify_umask.pyo
%exclude /ericsson/security/compliance/verify_icmp.pyc
%exclude /ericsson/security/compliance/verify_icmp.pyo
%exclude /ericsson/security/compliance/verify_motd_banner.pyc
%exclude /ericsson/security/compliance/verify_motd_banner.pyo
%exclude /ericsson/security/compliance/verify_reverse_fwd.pyc
%exclude /ericsson/security/compliance/verify_reverse_fwd.pyo
%exclude /ericsson/security/compliance/verify_SR.pyc
%exclude /ericsson/security/compliance/verify_SR.pyo
%exclude /ericsson/security/compliance/verify_sshd_banner.pyc
%exclude /ericsson/security/compliance/verify_sshd_banner.pyo
%exclude /ericsson/security/compliance/verify_sticky_bit.pyc
%exclude /ericsson/security/compliance/verify_sticky_bit.pyo
%exclude /ericsson/security/compliance/verify_agent_fwdng.pyc
%exclude /ericsson/security/compliance/verify_agent_fwdng.pyo
%exclude /ericsson/security/compliance/NH_post_patch.pyc
%exclude /ericsson/security/compliance/NH_post_patch.pyo
%exclude /ericsson/security/compliance/verify_AllowTCPForwording.pyc
%exclude /ericsson/security/compliance/verify_AllowTCPForwording.pyo
%exclude /ericsson/security/compliance/verify_X11Forwarding.pyc
%exclude /ericsson/security/compliance/verify_X11Forwarding.pyo
%exclude /ericsson/security/compliance/verify_sshHostKeyVerification.pyc
%exclude /ericsson/security/compliance/verify_sshHostKeyVerification.pyo
%exclude /ericsson/security/compliance/verify_Ipv6_autoconf.pyc
%exclude /ericsson/security/compliance/verify_Ipv6_autoconf.pyo
%exclude /ericsson/security/compliance/verify_GatewayPorts.pyc
%exclude /ericsson/security/compliance/verify_GatewayPorts.pyo
%exclude /ericsson/security/compliance/verify_file_permissions.pyc
%exclude /ericsson/security/compliance/verify_file_permissions.pyo
%exclude /ericsson/security/compliance/verify_icmp_responses.pyc
%exclude /ericsson/security/compliance/verify_icmp_responses.pyo
%exclude /ericsson/security/compliance/verify_ipv6_advertisements.pyc
%exclude /ericsson/security/compliance/verify_ipv6_advertisements.pyo
%exclude /ericsson/security/compliance/verify_secure_icmp.pyc
%exclude /ericsson/security/compliance/verify_secure_icmp.pyo
%exclude /ericsson/security/compliance/verify_reverse_path_filter.pyc
%exclude /ericsson/security/compliance/verify_reverse_path_filter.pyo
%exclude /ericsson/security/compliance/verify_suspicious_packets.pyc
%exclude /ericsson/security/compliance/verify_suspicious_packets.pyo
%exclude /ericsson/security/compliance/verify_tcp_syncookies.pyc
%exclude /ericsson/security/compliance/verify_tcp_syncookies.pyo
%exclude /ericsson/security/compliance/verify_inactive.pyc
%exclude /ericsson/security/compliance/verify_inactive.pyo
%exclude /ericsson/security/compliance/verify_keyexchng_algorithm.pyc
%exclude /ericsson/security/compliance/verify_keyexchng_algorithm.pyo
%exclude /ericsson/security/compliance/verify_path_integrity.pyc
%exclude /ericsson/security/compliance/verify_path_integrity.pyo
%exclude /ericsson/security/compliance/verify_set_maxauth.pyc
%exclude /ericsson/security/compliance/verify_set_maxauth.pyo
%exclude /ericsson/security/compliance/verify_ssh_timeout.pyc
%exclude /ericsson/security/compliance/verify_ssh_timeout.pyo
%exclude /ericsson/security/compliance/verify_su_restriction.pyc
%exclude /ericsson/security/compliance/verify_su_restriction.pyo
%exclude /ericsson/security/compliance/verify_set_maxstart.pyc
%exclude /ericsson/security/compliance/verify_set_maxstart.pyo
%exclude /ericsson/security/compliance/verify_hostbasedAuthentication.pyc
%exclude /ericsson/security/compliance/verify_hostbasedAuthentication.pyo
%exclude /ericsson/security/compliance/verify_ignoreRhosts.pyc
%exclude /ericsson/security/compliance/verify_ignoreRhosts.pyo
%exclude /ericsson/security/compliance/verify_ssh_emptypasswords.pyc
%exclude /ericsson/security/compliance/verify_ssh_emptypasswords.pyo
%exclude /ericsson/security/compliance/verify_ssh_userenvironment.pyc
%exclude /ericsson/security/compliance/verify_ssh_userenvironment.pyo
%exclude /ericsson/security/compliance/verify_date_time_info.pyc
%exclude /ericsson/security/compliance/verify_date_time_info.pyo
%exclude /ericsson/security/compliance/verify_file_deletion.pyc
%exclude /ericsson/security/compliance/verify_file_deletion.pyo
%exclude /ericsson/security/compliance/verify_system_access.pyc
%exclude /ericsson/security/compliance/verify_system_access.pyo
%exclude /ericsson/security/compliance/verify_system_network.pyc
%exclude /ericsson/security/compliance/verify_system_network.pyo
%exclude /ericsson/security/compliance/verify_discec_access.pyc
%exclude /ericsson/security/compliance/verify_discec_access.pyo
%exclude /ericsson/security/compliance/verify_file_auth.pyc
%exclude /ericsson/security/compliance/verify_file_auth.pyo
%exclude /ericsson/security/compliance/verify_sys_admin_cmd.pyc
%exclude /ericsson/security/compliance/verify_sys_admin_cmd.pyo
%exclude /ericsson/security/compliance/verify_system_mount.pyc
%exclude /ericsson/security/compliance/verify_system_mount.pyo
%exclude /ericsson/security/compliance/verify_kernel_module.pyc
%exclude /ericsson/security/compliance/verify_kernel_module.pyo
%exclude /ericsson/security/compliance/verify_auditconf_immutable.pyc
%exclude /ericsson/security/compliance/verify_auditconf_immutable.pyo
%exclude /ericsson/security/compliance/verify_user_priviliged_cmd.pyc
%exclude /ericsson/security/compliance/verify_user_priviliged_cmd.pyo
%exclude /ericsson/security/compliance/verify_user_group_info.pyc
%exclude /ericsson/security/compliance/verify_user_group_info.pyo
%exclude /ericsson/security/compliance/verify_sys_admin_scope.pyc
%exclude /ericsson/security/compliance/verify_sys_admin_scope.pyo
%exclude /ericsson/security/compliance/verify_sudologs_rotate.pyc
%exclude /ericsson/security/compliance/verify_sudologs_rotate.pyo
%exclude /ericsson/security/compliance/verify_disable_root_switch.pyc
%exclude /ericsson/security/compliance/verify_disable_root_switch.pyo
%exclude /ericsson/security/compliance/verify_audit_automate_cron.pyc
%exclude /ericsson/security/compliance/verify_audit_automate_cron.pyo
%exclude /ericsson/security/compliance/nh_summary_generate.pyc
%exclude /ericsson/security/compliance/nh_summary_generate.pyo
/ericsson/security/compliance/verify_login_logout_events.pyc
/ericsson/security/compliance/verify_login_logout_events.pyo
/ericsson/security/compliance/verify_session_info.pyc
/ericsson/security/compliance/verify_session_info.pyo

#### audit file list
/ericsson/security/audit/NH_audit.py
/ericsson/security/audit/audit_config.py
/ericsson/security/audit/config.txt
/ericsson/security/audit/audit_automate_cron.py
/ericsson/security/audit/auditlog_rotate.py
/ericsson/security/audit/disable_audit_rules.py
/ericsson/security/audit/rollback_disable_audit_rules.py
/ericsson/security/audit/security_logcollector.py
%exclude /ericsson/security/audit/NH_audit.pyc
%exclude /ericsson/security/audit/NH_audit.pyo
%exclude /ericsson/security/audit/audit_config.pyc
%exclude /ericsson/security/audit/audit_config.pyo
%exclude /ericsson/security/audit/audit_automate_cron.pyc
%exclude /ericsson/security/audit/audit_automate_cron.pyo
%exclude /ericsson/security/audit/auditlog_rotate.pyc
%exclude /ericsson/security/audit/auditlog_rotate.pyo
%exclude /ericsson/security/audit/disable_audit_rules.pyc
%exclude /ericsson/security/audit/disable_audit_rules.pyo
%exclude /ericsson/security/audit/rollback_disable_audit_rules.pyo
%exclude /ericsson/security/audit/rollback_disable_audit_rules.pyc
%exclude /ericsson/security/audit/security_logcollector.pyc
%exclude /ericsson/security/audit/security_logcollector.pyo

%changelog
* Fri Dec 21 2018 XNAVVIJ
- Intial RPM Build
