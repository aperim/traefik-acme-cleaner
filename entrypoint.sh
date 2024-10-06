#!/bin/sh
#
# Entrypoint script for the ACME Certificate Cleanup Docker container.
#
# This script initializes the environment, adjusts the UID and GID of the existing 'cleanup' user and group
# according to PUID and PGID environment variables, and runs the acme_cleanup.py application or any provided command.
#
# Author:
#     Troy Kelly <troy@aperim.com>
#
# Code History:
#     - 2024-10-06: Initial creation.

set -e
set -u
set -o pipefail

# Function to handle termination signals.
handle_signal() {
    echo "Termination signal received. Exiting gracefully."
    exit 0
}

# Trap SIGTERM and SIGINT signals.
trap 'handle_signal' SIGTERM SIGINT

# Main function to execute the acme_cleanup.py script or override with user command.
main() {
    # Set default PUID and PGID if not provided.
    PUID="${PUID:-1000}"
    PGID="${PGID:-1000}"

    # Get the current UID and GID of the 'cleanup' user and group.
    CURRENT_UID=$(id -u cleanup)
    CURRENT_GID=$(id -g cleanup)

    # If the current UID does not match PUID, update it.
    if [ "$CURRENT_UID" -ne "$PUID" ]; then
        echo "Updating UID of 'cleanup' from $CURRENT_UID to $PUID"
        usermod -u "$PUID" cleanup
    fi

    # If the current GID does not match PGID, update it.
    if [ "$CURRENT_GID" -ne "$PGID" ]; then
        echo "Updating GID of 'cleanup' from $CURRENT_GID to $PGID"
        groupmod -g "$PGID" cleanup
    fi

    # If no arguments are provided or the first argument starts with '-', default to running acme_cleanup.py.
    if [ "$#" -eq 0 ] || [ "$(printf '%s' "$1" | cut -c1)" = "-" ]; then
        # Ensure required environment variables are set.
        if [ -z "${TRAEFIK_DASHBOARD_URL:-}" ]; then
            echo "Error: TRAEFIK_DASHBOARD_URL environment variable is not set."
            exit 1
        fi

        # Prepend the Python command and script name.
        set -- /usr/bin/env python3 /app/acme_cleanup.py "$@"
    fi

    # Change to the application directory.
    cd /app

    # Execute the command as the 'cleanup' user.
    exec su-exec cleanup "$@"
}

# Invoke the main function with all script arguments.
main "$@"