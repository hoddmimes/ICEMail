#!/bin/bash
#
# Build the ICEMail server/bridge
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Building ICEMail server..."

export JAVA_HOME=/usr/lib/jvm/jdk-25
$SCRIPT_DIR/../../gradle-9.2.1/bin/gradle build

echo "Done."
