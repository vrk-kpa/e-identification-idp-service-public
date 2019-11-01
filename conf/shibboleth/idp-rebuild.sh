#!/bin/sh

rm -fr $1/usr/share/tomcat/webapps/idp
cd $1/opt/shibboleth-idp/bin
./build.sh -Didp.target.dir=$1/opt/shibboleth-idp
