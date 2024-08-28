#!bin/bash
set -e
usage ()
{
        echo ""
        echo  "Usage: $cmd [-thx] -r Rstate -m Module
        er -S sms_signum" 1>&2
        echo ""
        printf "  -r Rstate of Module"
        printf "  -m Module name"
        echo ""
        exit 1
}


while getopts r:m: opt;do
        case $opt in
            r) Rstate=$OPTARG
               ;;
            m) Module=$OPTARG
               ;;
        esac
done
shift `expr $OPTIND - 1`
[ "$Rstate" != "" ] || usage
[ "${Module}" != "" ] || usage

chmod 777 eniq_security_tools/bin/build_rpm
if [ "$Module" == "security" ]	
then
		perl eniq_security_tools/bin/build_rpm -r $Rstate -m ERICnodehardening
		mkdir rpm_file
		cp -r eniq_security_delivery/ERICnodehardening/RPMS/ERICnodehardening-$Rstate.rpm rpm_file/
		cd om_linux/security
		rm -rf *.rpm
		sed -i "s/Rev/$Rstate/g" cxp_info
		cp -r ../../eniq_security_delivery/ERICnodehardening/RPMS/ERICnodehardening-$Rstate.rpm .
		tar -cvf security_$Rstate.tar ../security
		gzip security_$Rstate.tar
		mkdir -p /home/lciadm100/jenkins/workspace/ENIQ_Security_Build/tar_file
		cp -r security_$Rstate.tar.gz /home/lciadm100/jenkins/workspace/ENIQ_Security_Build/tar_file
		
else
		echo "Invalid Module Name Provided....!!!!!!!!!!!!!"
		false

fi	
