#!/bin/bash
##
# Start Mailbridge standalone server with configuration files
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "$SCRIPT_DIR"
CONF_FILE="$SCRIPT_DIR/mailbridge-$(hostname).json"

sudo java -Djava.net.preferIPv4Stack=true -Dlog4j2.configurationFile="$SCRIPT_DIR/custom-log4j2.xml" -Dgreenmail.config.file="$SCRIPT_DIR/log4j2.xml" \
     -cp $SCRIPT_DIR/build/distributions/mailbridge-1.0-SNAPSHOT-all.jar com.hoddmimes.icemail.bridge.MailBridge $CONF_FILE
