#!/bin/bash

# Check if a username parameter is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <username>"
    exit 1
fi

# Assign the first parameter to USERNAME
USERNAME="$1"

# Check if the user already exists
if id "$USERNAME" &>/dev/null; then
    echo "User '$USERNAME' already exists."
else
    # Create the user with a nologin shell
    sudo useradd -s /usr/sbin/nologin "$USERNAME"

    if [ $? -eq 0 ]; then
        echo "User '$USERNAME' created with nologin shell."
    else
        echo "Failed to create user '$USERNAME'."
    fi
fi