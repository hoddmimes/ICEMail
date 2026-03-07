#!/bin/bash
cd "$(dirname "$0")"
export JAVA_HOME=/usr/lib/jvm/java-21

SERVER_DIR=/usr/local/ICEMail/server
BRIDGE_DIR=/usr/local/ICEMail/bridge
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
echo "Deploying server..."
scp ICE-Server/build/distributions/ice-server-1.0.jar "$TARGET:$SERVER_DIR/"
scp ICE-Server/server-*.json "$TARGET:$SERVER_DIR/"
#scp ICE-Server/cert.pem ICE-Server/key.pem "$TARGET:$SERVER_DIR/"
scp ICE-Server/log4j2.xml "$TARGET:$SERVER_DIR/"
scp ICE-Server/create_user.sh ICE-Server/delete_user.sh "$TARGET:$SERVER_DIR/"
scp -r ICE-Server/WebContent "$TARGET:$SERVER_DIR/"

# Deploy bridge to remote
echo "Deploying bridge to $TARGET..."
scp ICE-Mailbridge/build/distributions/ice-mailbridge-1.0.jar "$TARGET:$BRIDGE_DIR/"
#scp ICE-Mailbridge/cert.pem ICE-Mailbridge/key.pem "$TARGET:$BRIDGE_DIR/"
scp ICE-Mailbridge/mailbridge-*.json "$TARGET:$BRIDGE_DIR/"
scp ICE-Mailbridge/log4j2.xml "$TARGET:$BRIDGE_DIR/"

echo "Deploy complete."
