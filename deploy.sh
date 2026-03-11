#!/bin/bash
cd "$(dirname "$0")"
export JAVA_HOME=/usr/lib/jvm/java-21

SERVER_DIR=/usr/local/ice-server
BRIDGE_DIR=/usr/local/ice-bridge
TARGET=vraket

# Build uber jars
echo "Building uber jars..."
./gradlew ICE-Server:shadowJar ICE-Mailbridge:shadowJar || exit 1

# Generate build info (deployed as a static file inside WebContent)
BUILD_TIME=$(date '+%Y-%m-%d %H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
cat > ICE-Server/WebContent/build-info.json <<EOF
{
  "deployedAt": "$BUILD_TIME",
  "gitCommit": "$GIT_COMMIT",
  "gitBranch": "$GIT_BRANCH"
}
EOF
echo "Build info: $BUILD_TIME  commit=$GIT_COMMIT  branch=$GIT_BRANCH"

# Deploy server
echo "Deploying server to $TARGET:$SERVER_DIR..."
scp build-release/release/server/ice-server-*.jar "$TARGET:$SERVER_DIR/"
scp -r ICE-Server/WebContent "$TARGET:$SERVER_DIR/"

# Deploy bridge
echo "Deploying bridge to $TARGET:$BRIDGE_DIR..."
scp build-release/release/bridge/ice-bridge-*.jar "$TARGET:$BRIDGE_DIR/"

echo "Deploy complete."
