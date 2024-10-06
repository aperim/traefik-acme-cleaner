#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ACME Certificate Cleanup Script.

This script performs cleanup operations on the Traefik acme.json file by
removing expired, invalid, and optionally unused certificates.

Author:
    Troy Kelly <troy@aperim.com>

Code History:
    - 2024-10-06: Initial creation.

"""

import argparse
import json
import logging
import os
import shutil
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import requests
from OpenSSL import crypto

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def signal_handler(sig: int, frame: Any) -> None:
    """Handle termination signals."""
    logging.info('Termination signal received. Exiting gracefully.')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


class AcmeCleaner:
    """Class to handle the ACME certificate cleanup process."""

    def __init__(self, args: argparse.Namespace) -> None:
        """Initialize the AcmeCleaner with command-line arguments."""
        self.acme_file_path = Path(os.environ.get('TRAEFIK_ACME_FILE', 'acme.json'))
        self.dashboard_url = os.environ.get('TRAEFIK_DASHBOARD_URL')
        self.dashboard_username = os.environ.get('TRAEFIK_DASHBOARD_USERNAME')
        self.dashboard_password = os.environ.get('TRAEFIK_DASHBOARD_PASSWORD')
        self.include_unused = args.include_unused or self.str_to_bool(os.environ.get('ACME_CLEANUP_UNUSED', 'false'))
        self.doit = args.doit or self.str_to_bool(os.environ.get('ACME_CLEANUP_DOIT', 'false'))
        self.acme_data: Dict[str, Any] = {}
        self.valid_certs: List[Dict[str, Any]] = []
        self.invalid_certs: List[Dict[str, Any]] = []
        self.expired_certs: List[Dict[str, Any]] = []
        self.unused_certs: List[Dict[str, Any]] = []
        self.used_certs: List[Dict[str, Any]] = []
        self.certs_to_remove: List[Dict[str, Any]] = []

    @staticmethod
    def str_to_bool(value: str) -> bool:
        """Convert a string to a boolean."""
        return value.lower() in ('yes', 'true', 't', '1')

    def check_acme_file(self) -> None:
        """Ensure that the acme.json file exists and is readable and writable."""
        logging.info(f'Checking if acme.json file exists at {self.acme_file_path}')
        if not self.acme_file_path.exists():
            logging.error(f'ACME file not found: {self.acme_file_path}')
            sys.exit(1)
        if not os.access(self.acme_file_path, os.R_OK | os.W_OK):
            logging.error(f'ACME file is not readable and writable: {self.acme_file_path}')
            sys.exit(1)

    def check_dashboard_access(self) -> None:
        """Ensure that the Traefik dashboard is accessible."""
        logging.info('Checking Traefik dashboard accessibility')
        if not self.dashboard_url:
            logging.error('TRAEFIK_DASHBOARD_URL environment variable not set')
            sys.exit(1)
        try:
            response = requests.get(
                self.dashboard_url,
                auth=(self.dashboard_username, self.dashboard_password),
                timeout=10
            )
            if response.status_code != 200:
                logging.error(f'Failed to access Traefik dashboard, status code: {response.status_code}')
                sys.exit(1)
        except requests.RequestException as e:
            logging.error(f'Error accessing Traefik dashboard: {e}')
            sys.exit(1)

    def load_acme_file(self) -> None:
        """Load and parse the acme.json file."""
        logging.info(f'Loading acme.json file from {self.acme_file_path}')
        try:
            with self.acme_file_path.open('r', encoding='utf-8') as file:
                self.acme_data = json.load(file)
        except json.JSONDecodeError as e:
            logging.error(f'Invalid JSON in acme.json file: {e}')
            sys.exit(1)
        except Exception as e:
            logging.error(f'Error reading acme.json file: {e}')
            sys.exit(1)

    def analyse_certificates(self) -> None:
        """Analyse certificates in the acme.json file."""
        logging.info('Analysing certificates in acme.json')
        for resolver in self.acme_data.values():
            certificates = resolver.get('Certificates', [])
            for cert_entry in certificates:
                cert_pem = cert_entry.get('certificate')
                domain_info = cert_entry.get('domain', {})
                main_domain = domain_info.get('main')
                try:
                    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
                    not_after = datetime.strptime(
                        x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    if not_after < datetime.utcnow():
                        logging.info(f'Certificate expired: {main_domain}')
                        self.expired_certs.append(cert_entry)
                    else:
                        self.valid_certs.append(cert_entry)
                except crypto.Error as e:
                    logging.error(f'Invalid certificate for domain {main_domain}: {e}')
                    self.invalid_certs.append(cert_entry)

    def prepare_removal_list(self) -> None:
        """Prepare the list of certificates to be removed."""
        logging.info('Preparing list of certificates for removal')
        self.certs_to_remove = self.invalid_certs + self.expired_certs
        if self.include_unused:
            # Placeholder for unused certificates logic
            self.certs_to_remove += self.unused_certs
        logging.info(f'Certificates marked for removal: {len(self.certs_to_remove)}')

    def perform_cleanup(self) -> None:
        """Perform the cleanup by removing the certificates."""
        if not self.doit:
            logging.info('Simulation mode; no changes will be made')
            return
        logging.info('Performing cleanup')
        backup_path = self.acme_file_path.with_suffix('.backup')
        shutil.copy2(self.acme_file_path, backup_path)
        logging.info(f'Backup of acme.json created at {backup_path}')
        # Remove certificates from the acme_data
        for resolver in self.acme_data.values():
            certificates = resolver.get('Certificates', [])
            resolver['Certificates'] = [
                cert for cert in certificates if cert not in self.certs_to_remove
            ]
        # Write the updated acme.json
        temp_path = self.acme_file_path.with_suffix('.tmp')
        try:
            with temp_path.open('w', encoding='utf-8') as file:
                json.dump(self.acme_data, file, indent=2)
            temp_path.replace(self.acme_file_path)
            logging.info(f'acme.json file updated successfully at {self.acme_file_path}')
        except Exception as e:
            logging.error(f'Failed to update acme.json file: {e}')
            sys.exit(1)

    def run(self) -> None:
        """Run the ACME certificate cleanup process."""
        self.check_acme_file()
        self.check_dashboard_access()
        self.load_acme_file()
        self.analyse_certificates()
        self.prepare_removal_list()
        self.perform_cleanup()


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='ACME Certificate Cleanup Script')
    parser.add_argument('--include-unused', action='store_true',
                        help='Include unused certificates in the removal')
    parser.add_argument('--doit', action='store_true',
                        help='Perform the cleanup; otherwise, simulate only')
    return parser.parse_args()


def main() -> None:
    """Main function to execute the script."""
    args = parse_arguments()
    cleaner = AcmeCleaner(args)
    cleaner.run()


if __name__ == '__main__':
    main()
