#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ACME Certificate Cleanup Script.

This script performs cleanup operations on the Traefik acme.json file by
removing expired, invalid, and optionally unused certificates. It also generates
a markdown report summarizing the analysis.

Author:
    Troy Kelly <troy@aperim.com>

Code History:
    - 2024-10-06: Initial creation.
    - 2024-10-06: Fixed certificate decoding issue.
    - 2024-10-06: Resolved DeprecationWarning for datetime.utcnow().
    - 2024-10-06: Added markdown report generation functionality.

"""

import argparse
import base64
import json
import logging
import os
import shutil
import signal
import sys
from datetime import datetime, timezone
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
        """Initialise the AcmeCleaner with command-line arguments."""
        self.acme_file_path = Path(os.environ.get('TRAEFIK_ACME_FILE', 'acme.json'))
        self.dashboard_url = os.environ.get('TRAEFIK_DASHBOARD_URL')
        self.dashboard_username = os.environ.get('TRAEFIK_DASHBOARD_USERNAME')
        self.dashboard_password = os.environ.get('TRAEFIK_DASHBOARD_PASSWORD')
        self.include_unused = args.include_unused or self.str_to_bool(
            os.environ.get('ACME_CLEANUP_UNUSED', 'false'))
        self.doit = args.doit or self.str_to_bool(
            os.environ.get('ACME_CLEANUP_DOIT', 'false'))
        report_env = os.environ.get('CLEANUP_REPORT')
        self.report_path = Path(args.report or report_env or './REPORT.md')
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
        now = datetime.now(timezone.utc)
        for resolver_name, resolver in self.acme_data.items():
            certificates = resolver.get('Certificates', [])
            for cert_entry in certificates:
                cert_entry['resolver_name'] = resolver_name
                cert_pem_encoded = cert_entry.get('certificate')
                domain_info = cert_entry.get('domain', {})
                main_domain = domain_info.get('main', 'Unknown')
                sans = domain_info.get('sans', [])
                try:
                    # Base64-decode the certificate
                    cert_pem_bytes = base64.b64decode(cert_pem_encoded)
                    # Decode to string
                    cert_pem = cert_pem_bytes.decode('utf-8')
                    # Load the certificate
                    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
                    not_after = datetime.strptime(
                        x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'
                    ).replace(tzinfo=timezone.utc)
                    days_until_expiry = (not_after - now).days
                    cert_entry['not_after'] = not_after
                    cert_entry['days_until_expiry'] = days_until_expiry
                    if not_after < now:
                        logging.info(f'Certificate expired: {main_domain}')
                        cert_entry['status'] = 'expired'
                        self.expired_certs.append(cert_entry)
                    else:
                        cert_entry['status'] = 'valid'
                        self.valid_certs.append(cert_entry)
                except (crypto.Error, ValueError, UnicodeDecodeError) as e:
                    logging.error(f'Invalid certificate for domain {main_domain}: {e}')
                    cert_entry['status'] = 'invalid'
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
        if not self.certs_to_remove:
            logging.info('No certificates to remove')
            return
        logging.info('Performing cleanup')
        backup_path = self.acme_file_path.with_name(f'{self.acme_file_path.name}.backup')
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

    def generate_report(self) -> None:
        """Generate a markdown report of the certificate analysis."""
        logging.info(f'Generating markdown report at {self.report_path}')
        report_lines = []
        report_lines.append('# ACME Certificate Cleanup Report\n')
        report_lines.append(f'Generated on {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")}\n')
        total_certs = len(self.valid_certs) + len(self.invalid_certs) + len(self.expired_certs)
        total_domains = sum(
            len(cert.get('domain', {}).get('sans', [])) + 1
            for cert in self.valid_certs + self.invalid_certs + self.expired_certs
        )
        report_lines.append('## Summary\n')
        report_lines.append(f'- **Total Certificates**: {total_certs}')
        report_lines.append(f'- **Total Domains**: {total_domains}')
        report_lines.append(f'- **Valid Certificates**: {len(self.valid_certs)}')
        report_lines.append(f'- **Invalid Certificates**: {len(self.invalid_certs)}')
        report_lines.append(f'- **Expired Certificates**: {len(self.expired_certs)}')
        report_lines.append(f'- **Unused Certificates**: {len(self.unused_certs)}\n')
        # Group certificates by resolver
        resolvers: Dict[str, List[Dict[str, Any]]] = {}
        for cert_list in [self.valid_certs, self.invalid_certs, self.expired_certs]:
            for cert in cert_list:
                resolver_name = cert.get('resolver_name', 'Unknown')
                resolvers.setdefault(resolver_name, []).append(cert)
        for resolver_name, certs in resolvers.items():
            report_lines.append(f'## Resolver: {resolver_name}\n')
            report_lines.append('| Primary Domain | Additional Domains | Expiry Date | Days Until Expiry | In Use | Deleted |')
            report_lines.append('|----------------|--------------------|-------------|-------------------|--------|---------|')
            for cert in certs:
                domain_info = cert.get('domain', {})
                main_domain = domain_info.get('main', 'Unknown')
                sans = domain_info.get('sans', [])
                status = cert.get('status', '')
                not_after = cert.get('not_after', None)
                days_until_expiry = cert.get('days_until_expiry', '')
                if not_after:
                    expiry_date = not_after.strftime('%Y-%m-%d')
                else:
                    expiry_date = 'N/A'
                if status == 'expired':
                    days_until_expiry_display = 'Expired'
                elif status == 'invalid':
                    days_until_expiry_display = 'Invalid'
                else:
                    days_until_expiry_display = str(days_until_expiry)
                deleted = 'Yes' if cert in self.certs_to_remove else ''
                in_use = ''  # Placeholder for future implementation
                report_lines.append(
                    f'| {main_domain} | {", ".join(sans)} | {expiry_date} | '
                    f'{days_until_expiry_display} | {in_use} | {deleted} |'
                )
        # Write the report to file
        try:
            with self.report_path.open('w', encoding='utf-8') as report_file:
                report_file.write('\n'.join(report_lines))
            logging.info(f'Report generated successfully at {self.report_path}')
        except Exception as e:
            logging.error(f'Failed to write report file: {e}')
            sys.exit(1)

    def run(self) -> None:
        """Run the ACME certificate cleanup process."""
        self.check_acme_file()
        self.check_dashboard_access()
        self.load_acme_file()
        self.analyse_certificates()
        self.prepare_removal_list()
        self.perform_cleanup()
        self.generate_report()


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='ACME Certificate Cleanup Script')
    parser.add_argument('--include-unused', action='store_true',
                        help='Include unused certificates in the removal')
    parser.add_argument('--doit', action='store_true',
                        help='Perform the cleanup; otherwise, simulate only')
    parser.add_argument('--report', type=str, default=None,
                        help='Path to the markdown report file')
    return parser.parse_args()


def main() -> None:
    """Main function to execute the script."""
    args = parse_arguments()
    cleaner = AcmeCleaner(args)
    cleaner.run()


if __name__ == '__main__':
    main()