#!/bin/bash
#
#
cd "$(dirname "$0")"  
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-arm64
java -Dlog4j.configurationFile=log4j2.xml -jar ./ice-server-1.0.jar -config server-koxnan.json
exit
