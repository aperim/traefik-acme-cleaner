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
#     - 2023-10-06: Initial creation.
#     - 2023-10-06: Modified to honor PUID=1 and PGID=1 to run as root.

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

    # If PUID and PGID are 1, we assume the intent is to run as root.
    if [ "$PUID" -eq 1 ] && [ "$PGID" -eq 1 ]; then
        echo "PUID and PGID are set to 1. Running as root."

        # Change to the application directory.
        cd /app

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

        # Execute the command as root.
        exec "$@"
    else
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

        # Ensure 'cleanup' owns its home directory and application directory.
        chown -R cleanup:cleanup /home/cleanup /app

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
    fi
}

# Invoke the main function with all script arguments.
main "$@"