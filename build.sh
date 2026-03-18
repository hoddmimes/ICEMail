#!/bin/bash
#
# Build the ICEMail server/bridge
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TASK="${1:-build}"

if [ "$TASK" != "build" ] && [ "$TASK" != "clean" ]; then
    echo "Usage: $0 [build|clean]"
    exit 1
fi

echo "Running ICEMail $TASK..."

export JAVA_HOME=/usr/lib/jvm/jdk-25
$SCRIPT_DIR/../../gradle-9.2.1/bin/gradle "$TASK"

echo "Done."
