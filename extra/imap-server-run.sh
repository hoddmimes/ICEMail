#!/bin/bash
#
# Starts the Minimal IMAP Server (James)
#

BASE_DIR="/usr/local/imap-james"
JAR="$BASE_DIR/james-server-imap-app.jar"
OPENJPA_JAR="$BASE_DIR/james-server-imap-app.lib/openjpa-3.2.0.jar"
CONFIG_FILE="$BASE_DIR/imap-server-$(hostname).json"
LOGBACK_FILE="$BASE_DIR/logback.xml"
WORKING_DIR="$BASE_DIR"

if [ ! -f "$JAR" ]; then
    echo "ERROR: $JAR not found."
    exit 1
fi

sudo java \
    -Dworking.directory="$WORKING_DIR" \
    -Dlogback.configurationFile="$LOGBACK_FILE" \
    -javaagent:"$OPENJPA_JAR" \
    -jar "$JAR" \
    "$CONFIG_FILE"
