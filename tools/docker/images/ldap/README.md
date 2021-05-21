Test port in powershell:  Test-NetConnection -ComputerName "localhost" -Port 10389    

.\SharpHound.exe --domain "ldap.formsys.com" --ldappassword "password" --ldapusername "uid=tesla,dc=example,dc=com”

# get ip address from test-openldap
hostname -I | awk '{print $1}'

# sanity check
ldapsearch -W -h ldap.forumsys.com -D "uid=tesla,dc=example,dc=com" -b "dc=example,dc=com"

# external linux search from shell
ldapsearch in linux: ldapsearch -x -h 172.17.0.2 -p 10389 -D "cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com" -w "professor" -b "dc=planetexpress,dc=com" -s sub '(objectClass=*)' givenName

# internal test search from shell
ldapsearch in linux: ldapsearch -x -h 127.0.0.1 -p 10389 -D "cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com" -w "professor" -b "dc=planetexpress,dc=com" -s sub '(objectClass=*)' givenName


docker run --rm --network=host -p 10389:10389 -p 10636:10636 rroemhild/test-openldap


docker run --rm -p 10389:10389 -p 10636:10636 rroemhild/test-openldap