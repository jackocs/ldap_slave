#!/bin/bash

if [ $# -eq 0 ]; then
        echo "fail: Your command line contains no arguments Domain & Password"
        exit
fi

if [ "$1" == "" ]; then
        echo "fail: Unknow Base Domain"
        exit
fi

if [ "$2" == "" ]; then
        echo "fail: Unknow password"
        exit
fi
LDAP_PASSWORD=$2

for i in $(echo $1 | tr "." "\n")
do
        domain="$domain,dc=$i"
done

LDAP_BASE_DN=`echo $domain |cut -c 2-`

#sleep 2
for ((i=30; i>0; i--))
do
    ping_result=`ldapsearch 2>&1 | grep "Can.t contact LDAP server"`
    if [ -z "$ping_result" ]
    then
        break
    fi
    sleep 1
done
if [ $i -eq 0 ]
then
    echo "slapd did not start correctly"
    exit 1
fi

if (( $(ps -ef | grep -v grep | grep slapd | wc -l) > 0 ))
then
    #echo "SLAPD is running!!!"
    if [ ! -f /home/ldap_slave/init/setpasswd.ldif ]; then
	echo "Need ldif file"
	exit
    fi 

    container="ldap"
    docker_c="/home/ldap_slave/docker-compose.yml"

    # Update Password
    docker-compose -f $docker_c exec -d $container ldapadd -Y EXTERNAL -H ldapi:/// -f /home/init/setpasswd.ldif

    #Configure OpenLDAP Server
    docker-compose -f $docker_c exec -d $container ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/init/config.ldif

    #Add index uid
    docker-compose -f $docker_c exec -d $container ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/init/olcDbIndex.ldif

    #Create Base Domain
    ldapadd -x -h 127.0.0.1 -D "cn=Manager,$LDAP_BASE_DN" -w $LDAP_PASSWORD -f /home/ldap_slave/init/basedomain.ldif &>/dev/null
    ldapadd -x -h 127.0.0.1 -D "cn=Manager,$LDAP_BASE_DN" -w $LDAP_PASSWORD -f /home/ldap_slave/init/groups.ldif &>/dev/null

    #Config ACL
    docker-compose -f $docker_c exec -d $container ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/init/config_acl.ldif

    #Config olcLimits
    docker-compose -f $docker_c exec -d $container ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/init/config_olcLimits.ldif

    #Create ObjectClass datainfo.ldif
    ldapadd -x -h 127.0.0.1 -D "cn=config" -w $LDAP_PASSWORD -f /home/ldap_slave/init/schema/datainfo.ldif &>/dev/null

    #Password Policy overlay (ppolicy)
    ldapmodify -x -h 127.0.0.1 -D "cn=config" -w $LDAP_PASSWORD -a -f /home/ldap_slave/init/schema/ppolicy.ldif &>/dev/null

    #Password Policy overlay (mailrecipient)
    ldapmodify -x -h 127.0.0.1 -D "cn=config" -w $LDAP_PASSWORD -a -f /home/ldap_slave/init/schema/mailrecipient.ldif &>/dev/null

    #Load the module ppolicy
    ldapmodify -x -h 127.0.0.1 -D "cn=config" -w $LDAP_PASSWORD -a -f /home/ldap_slave/init/ppolicymodule.ldif &>/dev/null

    #Configure ppolicy overlay
    ldapmodify -x -h 127.0.0.1 -D "cn=config" -w $LDAP_PASSWORD -a -f /home/ldap_slave/init/ppolicyoverlay.ldif &>/dev/null

    #Definition of a password policy
    ldapadd -x -h 127.0.0.1 -D "cn=Manager,$LDAP_BASE_DN" -w $LDAP_PASSWORD -f /home/ldap_slave/init/definition_password_policy.ldif &>/dev/null

    #Enable Audit overlay
    ldapadd -x -h 127.0.0.1 -D "cn=config" -w $LDAP_PASSWORD -f /home/ldap_slave/init/audit.ldif &>/dev/null

    # Config TLS
    ldapconfigvol=`docker volume inspect --format '{{ .Mountpoint }}' ldap_slave_ldapconfigvol`
    if [ -d $ldapconfigvol ]; then
	ldapconfigvol+="/"
	ldapconfigvolcert=$ldapconfigvol"certs/"
	ldapconfigvolfile=$ldapconfigvol"ldap.conf"
	#mkdir /etc/openldap/certs
        /bin/cp /home/ldap_slave/init/certs/oldap1.pem $ldapconfigvolcert
        /bin/cp /home/ldap_slave/init/certs/oldap1.key $ldapconfigvolcert
        /bin/cp /home/ldap_slave/init/certs/ca_cert.pem $ldapconfigvolcert

	echo "TLS_CACERT /etc/openldap/certs/ca_cert.pem" >> $ldapconfigvolfile
	echo "TLS_REQCERT allow" >> $ldapconfigvolfile

	docker-compose -f $docker_c exec -d $container ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/init/mod_ssl.ldif
    fi

    # Add module syncprov.la
    #docker-compose -f $docker_c exec -d $container ldapadd -Y EXTERNAL -H ldapi:/// -f /home/init/mod_syncprov.ldif

    # config module syncprov
    #docker-compose -f $docker_c exec -d $container ldapadd -Y EXTERNAL -H ldapi:/// -f /home/init/syncprov.ldif

    # config module syncprov olcDbIndex
    docker-compose -f $docker_c exec -d $container ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/init/olcDbIndex.ldif

    # config LDAP Consumer
    docker-compose -f $docker_c exec -d $container ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/init/syncrepl.ldif

    # config LDAP schema extra
    #listschema=$(ls /home/ldap_slave/init/schema/extra)
    listschema=$(cat /home/ldap_slave/init/schema/extra/order.txt)
    for schema in $listschema
    do
	#fileschema="/home/ldap_slave/init/schema/extra/$schema"
	fileschema="/home/ldap_slave/init/schema/extra/$schema.ldif"
	if [ -f "$fileschema" ] ; then
    		ldapmodify -x -h 127.0.0.1 -D "cn=config" -w $LDAP_PASSWORD -a -f $fileschema &>/dev/null
	fi
    done

else
	echo "SLAPD is not running!!!"
fi

