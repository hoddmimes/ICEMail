#!/bin/bash
#
#
cd "$(dirname "$0")"
#export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-arm64
java -Djava.net.preferIPv4Stack=true -Dlog4j.configurationFile=log4j2.xml \
     -cp "ice-bridge-1.0.jar:lib/*" \
     com.hoddmimes.icemail.bridge.MailBridge ./ice-bridge.json
exit
