#!/bin/bash

# Check if a username parameter is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <username>"
    exit 1
fi

# Assign the first parameter to USERNAME
USERNAME="$1"

# Check if the user exists
if id "$USERNAME" &>/dev/null; then
    # Delete the user and their home directory
    sudo userdel -r "$USERNAME"

    if [ $? -eq 0 ]; then
        echo "User '$USERNAME' and all their data have been deleted."
    else
        echo "Failed to delete user '$USERNAME'."
    fi
else
    echo "User '$USERNAME' does not exist."
fi