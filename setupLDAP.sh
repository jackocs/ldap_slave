#!/bin/bash

if [ $# -eq 0 ]; then
        echo "fail: Your command line contains no arguments Domain & Password"
        exit
fi

if [ "$1" == "" ]; then
        echo "fail: Unknow Base Domain"
        exit
fi
LDAP_DOMAIN=$1

if [ "$2" == "" ]; then
        echo "fail: Unknow password"
        exit
fi
LDAP_PASSWORD=$2

if [ "$3" == "" ]; then
        echo "fail: Unknow ip master"
        exit
fi
ipMaster=$3

for i in $(echo $1 | tr "." "\n")
do
        domain="$domain,dc=$i"
done
firstDomain=`echo "$1" |cut -f1 -d"."`
basedn=`echo $domain |cut -c 2-`

# Generated Password slappasswd
adminPasswd=`slappasswd -s $LDAP_PASSWORD`
setpasswd="/home/ldap_slave/init/setpasswd.ldif"
echo "dn: olcDatabase={0}config,cn=config" > $setpasswd
echo "changetype: modify" >> $setpasswd
echo "add: olcRootPW" >> $setpasswd
echo "olcRootPW: $adminPasswd" >> $setpasswd
echo "" >> $setpasswd

#echo "======== Step 5 : Configure OpenLDAP Server ========" >> $logfile
config="/home/ldap_slave/init/config.ldif"
echo "dn: olcDatabase={1}monitor,cn=config" > $config
echo "changetype: modify" >> $config
echo "replace: olcAccess" >> $config
echo "olcAccess: {0}to *" >> $config
echo "  by dn.base=\"gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth\" read" >> $config
echo "  by dn.base=\"cn=Manager,$basedn\" read" >> $config
echo "  by * none" >> $config
echo "" >> $config
echo "dn: olcDatabase={2}hdb,cn=config" >> $config
echo "changetype: modify" >> $config
echo "replace: olcSuffix" >> $config
echo "olcSuffix: $basedn" >> $config
echo "" >> $config
echo "dn: olcDatabase={2}hdb,cn=config" >> $config
echo "changetype: modify" >> $config
echo "replace: olcRootDN" >> $config
echo "olcRootDN: cn=Manager,$basedn" >> $config
echo "" >> $config
echo "dn: olcDatabase={2}hdb,cn=config" >> $config
echo "changetype: modify" >> $config
echo "replace: olcRootPW" >> $config
echo "olcRootPW: $adminPasswd" >> $config
echo "" >> $config
echo "dn: olcDatabase={2}hdb,cn=config" >> $config
echo "add: olcAccess" >> $config
echo "olcAccess: {0}to attrs=userPassword" >> $config
echo "  by dn=\"cn=Manager,$basedn\" write" >> $config
echo "  by anonymous auth" >> $config
echo "  by self write" >> $config
echo "  by * none" >> $config
echo "olcAccess: {1}to dn.base=\"\"" >> $config
echo "  by * read" >> $config
echo "olcAccess: {2}to *" >> $config
echo "  by dn=\"cn=Manager,$basedn\" write" >> $config
echo "  by * read" >> $config

#olcDbIndex="/home/ldap_slave/ldap/init/olcDbIndex.ldif"
#echo "dn: olcDatabase={2}hdb,cn=config" > $olcDbIndex
#echo "changetype: modify" >> $olcDbIndex
#echo "add: olcDbIndex" >> $olcDbIndex
#echo "olcDbIndex: uid eq,pres,sub" >> $olcDbIndex
#echo "" >> $olcDbIndex

basedomain="/home/ldap_slave/init/basedomain.ldif"
echo "dn: $basedn" > $basedomain
echo "objectClass: top" >> $basedomain
echo "objectClass: dcObject" >> $basedomain
echo "objectclass: organization" >> $basedomain
echo "o: $firstDomain" >> $basedomain
echo "dc: $firstDomain" >> $basedomain
echo "" >> $basedomain
echo "dn: cn=Manager,$basedn" >> $basedomain
echo "objectClass: organizationalRole" >> $basedomain
echo "cn: Manager" >> $basedomain
echo "description: Directory Manager" >> $basedomain
echo "" >> $basedomain
echo "dn: ou=People,$basedn" >> $basedomain
echo "objectClass: organizationalUnit" >> $basedomain
echo "ou: People" >> $basedomain
echo "" >> $basedomain
echo "dn: ou=Group,$basedn" >> $basedomain
echo "objectClass: organizationalUnit" >> $basedomain
echo "ou: Group" >> $basedomain
echo "" >> $basedomain
echo "dn: uid=admin,ou=People,$basedn" >> $basedomain
echo "objectClass: top" >> $basedomain
echo "objectClass: person" >> $basedomain
echo "objectClass: organizationalPerson" >> $basedomain
echo "objectClass: inetOrgPerson" >> $basedomain
echo "uid: admin" >> $basedomain
echo "cn: Administrator Manager" >> $basedomain
echo "givenName: Administrator" >> $basedomain
echo "sn: Manager" >> $basedomain
echo "userPassword: $adminPasswd" >> $basedomain
echo "" >> $basedomain
echo "dn: uid=ReplicaUser,ou=People,$basedn" >> $basedomain
echo "objectClass: top" >> $basedomain
echo "objectClass: person" >> $basedomain
echo "objectClass: organizationalPerson" >> $basedomain
echo "objectClass: inetOrgPerson" >> $basedomain
echo "uid: ReplicaUser" >> $basedomain
echo "cn: ReplicaUser Manager" >> $basedomain
echo "givenName: ReplicaUser" >> $basedomain
echo "sn: Manager" >> $basedomain
echo "userPassword: $adminPasswd" >> $basedomain
echo "" >> $basedomain
echo "dn: uid=help,ou=People,$basedn" >> $basedomain
echo "objectClass: top" >> $basedomain
echo "objectClass: person" >> $basedomain
echo "objectClass: organizationalPerson" >> $basedomain
echo "objectClass: inetOrgPerson" >> $basedomain
echo "uid: help" >> $basedomain
echo "cn: Helpdesk Manager" >> $basedomain
echo "givenName: Helpdesk" >> $basedomain
echo "sn: Manager" >> $basedomain
echo "userPassword: $adminPasswd" >> $basedomain
echo "" >> $basedomain
echo "dn: uid=search,ou=People,$basedn" >> $basedomain
echo "objectClass: top" >> $basedomain
echo "objectClass: person" >> $basedomain
echo "objectClass: organizationalPerson" >> $basedomain
echo "objectClass: inetOrgPerson" >> $basedomain
echo "uid: search" >> $basedomain
echo "cn: Search Manager" >> $basedomain
echo "givenName: Search" >> $basedomain
echo "sn: Manager" >> $basedomain
echo "userPassword: $adminPasswd" >> $basedomain
echo "" >> $basedomain


groups="/home/ldap_slave/init/groups.ldif"
echo "dn: cn=Administrator,ou=Group,$basedn" > $groups
echo "objectClass: top" >> $groups
echo "objectClass: groupOfNames" >> $groups
echo "cn: Administrator" >> $groups
echo "member: uid=admin,ou=People,$basedn" >> $groups
echo "member: uid=ReplicaUser,ou=People,$basedn" >> $groups
echo "" >> $groups
echo "dn: cn=Helpdesk,ou=Group,$basedn" >> $groups
echo "objectClass: top" >> $groups
echo "objectClass: groupOfNames" >> $groups
echo "cn: Helpdesk" >> $groups
echo "member: uid=help,ou=People,$basedn" >> $groups
echo "" >> $groups
echo "dn: cn=Operators,ou=Group,$basedn" >> $groups
echo "objectClass: top" >> $groups
echo "objectClass: groupOfNames" >> $groups
echo "cn: Operators" >> $groups
echo "member: uid=search,ou=People,$basedn" >> $groups
echo "" >> $groups

#echo "======== Step 7.1 : Config ACL ========" >> $logfile
config_acl="/home/ldap_slave/init/config_acl.ldif"
echo "dn: olcDatabase={2}hdb,cn=config" > $config_acl
echo "replace: olcAccess" >> $config_acl
echo "olcAccess: {0}to attrs=userPassword,sambaNTPassword,shadowLastChange" >> $config_acl
echo "  by dn=\"cn=Manager,$basedn\" write" >> $config_acl
echo "  by group=\"cn=Administrator,ou=Group,$basedn\" write" >> $config_acl
echo "  by group=\"cn=Helpdesk,ou=Group,$basedn\" write" >> $config_acl
echo "  by anonymous auth" >> $config_acl
echo "  by self write" >> $config_acl
echo "  by * none" >> $config_acl
echo "olcAccess: {1}to *" >> $config_acl
echo "  by dn=\"cn=Manager,$basedn\" write" >> $config_acl
echo "  by group=\"cn=Administrator,ou=Group,$basedn\" write" >> $config_acl
echo "  by group=\"cn=Helpdesk,ou=Group,$basedn\" read" >> $config_acl
echo "  by group=\"cn=Operators,ou=Group,$basedn\" read" >> $config_acl
echo "  by self write" >> $config_acl
echo "  by peername.regex=127.0.0.1 anonymous read" >> $config_acl
echo "  by peername.ip=172.16.0.0%255.240.0.0 anonymous read" >> $config_acl
echo "  by peername.ip=192.168.0.0%255.255.0.0 anonymous read" >> $config_acl
echo "  by users search" >> $config_acl
echo "  by * none" >> $config_acl

config_olcLimits="/home/ldap_slave/init/config_olcLimits.ldif"
echo "dn: olcDatabase={2}hdb,cn=config" > $config_olcLimits
echo "replace: olcLimits" >> $config_olcLimits
echo "olcLimits: {0}group=\"cn=Administrator,ou=Group,$basedn\"" >> $config_olcLimits
echo "  size.soft=unlimited size.hard=unlimited time.soft=unlimited time.hard=unlimited" >> $config_olcLimits

addmodule="/home/ldap_slave/init/addmodule.ldif"
echo "dn: cn=module,cn=config" > $addmodule
echo "objectClass: olcModuleList" >> $addmodule
echo "cn: module" >> $addmodule
echo "olcModulePath: /usr/lib64/openldap" >> $addmodule
echo "olcModuleLoad: memberof" >> $addmodule

ppolicymodule="/home/ldap_slave/init/ppolicymodule.ldif"
echo "dn: cn=module,cn=config" > $ppolicymodule
echo "objectClass: olcModuleList" >> $ppolicymodule
echo "cn: module" >> $ppolicymodule
echo "olcModuleLoad: ppolicy.la" >> $ppolicymodule

ppolicyoverlay="/home/ldap_slave/init/ppolicyoverlay.ldif"
echo "dn: olcOverlay=ppolicy,olcDatabase={2}hdb,cn=config" > $ppolicyoverlay
echo "objectClass: olcOverlayConfig" >> $ppolicyoverlay
echo "objectClass: olcPPolicyConfig" >> $ppolicyoverlay
echo "olcOverlay: ppolicy" >> $ppolicyoverlay
echo "olcPPolicyDefault: cn=passwordDefault,ou=Policies,$basedn" >> $ppolicyoverlay
echo "olcPPolicyHashCleartext: FALSE" >> $ppolicyoverlay
echo "olcPPolicyUseLockout: FALSE" >> $ppolicyoverlay
echo "olcPPolicyForwardUpdates: FALSE" >> $ppolicyoverlay

definition_password_policy="/home/ldap_slave/init/definition_password_policy.ldif"
echo "dn: ou=Policies,$basedn" > $definition_password_policy
echo "ou: Policies" >> $definition_password_policy
echo "objectClass: organizationalUnit" >> $definition_password_policy
echo "" >> $definition_password_policy
echo "dn: cn=passwordDefault,ou=Policies,$basedn" >> $definition_password_policy
echo "objectClass: pwdPolicy" >> $definition_password_policy
echo "objectClass: person" >> $definition_password_policy
echo "objectClass: top" >> $definition_password_policy
echo "cn: passwordDefault" >> $definition_password_policy
echo "sn: passwordDefault" >> $definition_password_policy
echo "pwdAttribute: userPassword" >> $definition_password_policy
echo "pwdCheckQuality: 0" >> $definition_password_policy
echo "pwdMinAge: 0" >> $definition_password_policy
echo "pwdMaxAge: 0" >> $definition_password_policy
echo "pwdMinLength: 8" >> $definition_password_policy
echo "pwdInHistory: 3" >> $definition_password_policy
echo "pwdMaxFailure: 0" >> $definition_password_policy
echo "pwdFailureCountInterval: 0" >> $definition_password_policy
echo "pwdLockout: TRUE" >> $definition_password_policy
echo "pwdLockoutDuration: 0" >> $definition_password_policy
echo "pwdAllowUserChange: TRUE" >> $definition_password_policy
echo "pwdExpireWarning: 0" >> $definition_password_policy
echo "pwdGraceAuthNLimit: 0" >> $definition_password_policy
echo "pwdMustChange: FALSE" >> $definition_password_policy
echo "pwdSafeModify: FALSE" >> $definition_password_policy
echo "" >> $definition_password_policy

audit="/home/ldap_slave/init/audit.ldif"
echo "dn: cn=module{0},cn=config" > $audit
echo "changetype: modify" >> $audit
echo "add: olcModuleLoad" >> $audit
echo "olcModuleLoad: {1}auditlog" >> $audit
echo "" >> $audit
echo "dn: olcOverlay=auditlog,olcDatabase={2}hdb,cn=config" >> $audit
echo "changetype: add" >> $audit
echo "objectClass: olcOverlayConfig" >> $audit
echo "objectClass: olcAuditLogConfig" >> $audit
echo "olcOverlay: auditlog" >> $audit
echo "olcAuditlogFile: /var/log/slapd/slapd.log" >> $audit
echo "" >> $audit

/bin/mkdir -p /etc/openldap/certs/
/bin/mkdir -p /etc/ssl/private/
#/bin/certtool --generate-privkey > /etc/ssl/private/ca_key.pem
/bin/curl --silent http://$ipMaster:3000/api/v1/cert/read/$LDAP_DOMAIN/$LDAP_PASSWORD/cert/ > /etc/ssl/certs/ca_cert.pem
/bin/curl --silent http://$ipMaster:3000/api/v1/cert/read/$LDAP_DOMAIN/$LDAP_PASSWORD/key/ > /etc/ssl/private/ca_key.pem
/bin/certtool --generate-privkey > /etc/ssl/private/oldap1.key

#echo "cn = $LDAP_DOMAIN" > ca.info
#echo "ca" >> ca.info
#echo "cert_signing_key" >> ca.info
#echo "expiration_days = 3650" >> ca.info

#/bin/certtool --generate-self-signed --load-privkey /etc/ssl/private/ca_key.pem --template ca.info --outfile /etc/ssl/certs/ca_cert.pem
#/bin/rm -f ca.info

/bin/cp /etc/ssl/certs/ca_cert.pem /etc/openldap/certs/

if [ -f /etc/openldap/ldap.conf ]; then
        ck_tls_cacert=`grep TLS_REQCERT /etc/openldap/ldap.conf |wc -l`
        if [ $ck_tls_cacert -eq 0 ]; then
                echo "TLS_REQCERT allow" >> /etc/openldap/ldap.conf
        fi
else
        echo "TLS_CACERT /etc/openldap/certs/ca_cert.pem" >> /etc/openldap/ldap.conf
        echo "TLS_REQCERT allow" >> /etc/openldap/ldap.conf
fi

echo "organization = $LDAP_DOMAIN" > oldap1.info
echo "cn = oldap1.$LDAP_DOMAIN" >> oldap1.info
echo "tls_www_server" >> oldap1.info
echo "encryption_key" >> oldap1.info
echo "signing_key" >> oldap1.info
echo "expiration_days = 3650" >> oldap1.info

# create the LDAP server's certificate:
/bin/certtool --generate-certificate --load-privkey /etc/ssl/private/oldap1.key --load-ca-certificate /etc/ssl/certs/ca_cert.pem --load-ca-privkey /etc/ssl/private/ca_key.pem --template oldap1.info --outfile /etc/ssl/certs/oldap1.pem

#/bin/mkdir -p /etc/openldap/certs
/bin/cp /etc/ssl/certs/oldap1.pem /home/ldap_slave/init/certs/oldap1.pem
/bin/cp /etc/ssl/private/oldap1.key /home/ldap_slave/init/certs/oldap1.key
/bin/cp /etc/ssl/certs/ca_cert.pem /home/ldap_slave/init/certs/ca_cert.pem
/bin/rm -f oldap1.info

mod_ssl="/home/ldap_slave/init/mod_ssl.ldif"
echo "dn: cn=config" > $mod_ssl
echo "changetype: modify" >> $mod_ssl
echo "add: olcTLSCACertificateFile" >> $mod_ssl
echo "olcTLSCACertificateFile: /etc/openldap/certs/ca_cert.pem" >> $mod_ssl
echo "-" >> $mod_ssl
echo "replace: olcTLSCertificateFile" >> $mod_ssl
echo "olcTLSCertificateFile: /etc/openldap/certs/oldap1.pem" >> $mod_ssl
echo "-" >> $mod_ssl
echo "replace: olcTLSCertificateKeyFile" >> $mod_ssl
echo "olcTLSCertificateKeyFile: /etc/openldap/certs/oldap1.key" >> $mod_ssl
echo "-" >> $mod_ssl
echo "replace: olcTLSCipherSuite" >> $mod_ssl
echo "olcTLSCipherSuite: TLSv1+RSA:!NULL" >> $mod_ssl
echo "-" >> $mod_ssl
echo "replace: olcTLSVerifyClient" >> $mod_ssl
echo "olcTLSVerifyClient: never" >> $mod_ssl

# Add module syncprov.la
mod_syncprov="/home/ldap_slave/init/mod_syncprov.ldif"
echo "dn: cn=module,cn=config" > $mod_syncprov 
echo "objectClass: olcModuleList" >> $mod_syncprov
echo "cn: module" >> $mod_syncprov
echo "olcModulePath: /usr/lib64/openldap" >> $mod_syncprov
echo "olcModuleLoad: syncprov.la" >> $mod_syncprov

# config module syncprov
syncprov="/home/ldap_slave/init/syncprov.ldif"
echo "dn: olcOverlay=syncprov,olcDatabase={2}hdb,cn=config" > $syncprov
echo "objectClass: olcOverlayConfig" >> $syncprov
echo "objectClass: olcSyncProvConfig" >> $syncprov
echo "olcOverlay: syncprov" >> $syncprov
echo "olcSpSessionLog: 100" >> $syncprov

# config module syncprov olcDbIndex
olcDbIndex="/home/ldap_slave/init/olcDbIndex.ldif"
echo "dn: olcDatabase={2}hdb,cn=config" > $olcDbIndex
echo "changetype: modify" >> $olcDbIndex
echo "add: olcDbIndex" >> $olcDbIndex
echo "olcDbIndex: uid eq,pres,sub" >> $olcDbIndex
echo "-" >> $olcDbIndex
echo "add: olcDbIndex" >> $olcDbIndex
echo "olcDbIndex: entryUUID,entryCSN eq" >> $olcDbIndex
echo "-" >> $olcDbIndex
echo "add: olcDbIndex" >> $olcDbIndex
echo "olcDbIndex: idcardno eq" >> $olcDbIndex
echo "" >> $olcDbIndex

# Config LDAP Consumer
syncrepl="/home/ldap_slave/init/syncrepl.ldif"
echo "dn: olcDatabase={2}hdb,cn=config" > $syncrepl
echo "changetype: modify" >> $syncrepl
echo "add: olcSyncRepl" >> $syncrepl
echo "olcSyncRepl: rid=001" >> $syncrepl
echo "  provider=ldaps://$ipMaster" >> $syncrepl
echo "  bindmethod=simple" >> $syncrepl
echo "  binddn=\"uid=ReplicaUser,ou=People,$basedn\"" >> $syncrepl
echo "  credentials=$LDAP_PASSWORD" >> $syncrepl
echo "  searchbase=\"$basedn\"" >> $syncrepl
echo "  scope=sub" >> $syncrepl
echo "  schemachecking=on" >> $syncrepl
echo "  type=refreshAndPersist" >> $syncrepl
echo "  retry=\"30 5 300 3\"" >> $syncrepl
echo "  interval=00:00:05:00" >> $syncrepl
echo "  tls_reqcert=allow" >> $syncrepl
echo "  tls_cacert=/etc/openldap/certs/ca_cert.pem" >> $syncrepl

# Build Image identityldap
#docker build -t identityldap .

# start docker container docker compose
#docker-compose up -d

#sleep 2

# Setup Config LDAP
#/home/ldap_slave/ldap/config-ldap.sh $LDAP_DOMAIN $LDAP_PASSWORD

#sleep 2
# start docker container docker compose
#docker-compose stop identity
#docker exec -it ldap /usr/local/bin/run-ldap-stop.sh

