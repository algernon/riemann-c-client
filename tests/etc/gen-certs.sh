#! /bin/sh

openssl req -nodes -x509 -newkey rsa:2048 -keyout cacert.key -out cacert.pem \
        -subj "/C=HU/L=Budapest/O=The MadHouse Project/CN=`hostname -f`"

openssl req -nodes -newkey rsa:2048 -keyout server.pkcs8 -out server.csr \
        -subj "/C=HU/L=Budapest/O=The MadHouse Project/CN=`hostname -f`"

openssl x509 -req -in server.csr -CA cacert.pem -CAkey cacert.key \
        -CAcreateserial -out server.crt

openssl req -nodes -newkey rsa:2048 -keyout client.key -out client.csr \
        -subj "/C=HU/L=Budapest/O=The MadHouse Project/CN=`hostname -f`"

openssl x509 -req -in client.csr -CA cacert.pem -CAkey cacert.key \
        -CAserial cacert.srl -out client.crt
