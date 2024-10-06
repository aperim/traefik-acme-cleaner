# -*- coding: utf-8 -*-
"""Traefik API Interaction Module.

This module provides functionality to interact with the Traefik API to
fetch routers and extract domains for in-use certificate determination.

Author:
    Troy Kelly <troy@aperim.com>

Code History:
    - 2023-10-06: Initial creation.
    - 2023-10-06: Added pagination handling and improved domain extraction.
    - 2023-10-06: Updated pagination to handle Traefik's non-standard implementation.
    - 2023-10-06: Modified get_tls_domains to map domains to router info.
    - 2023-10-06: Added get_tls_domain_sets method.

"""

import logging
import re
from typing import Any, Dict, List, Set

import requests


class TraefikAPI:
    """Class to interact with the Traefik API."""

    def __init__(self, base_url: str, username: str, password: str) -> None:
        """Initialise the Traefik API client."""
        self.base_url = base_url.rstrip('/')
        self.auth = (username, password)
        self.session = requests.Session()
        self.session.auth = self.auth

    def get_routers(self) -> List[Dict[str, Any]]:
        """Fetch the list of routers from the Traefik API with pagination support."""
        routers = []
        page = 1
        per_page = 100  # Maximum number of results per page
        while True:
            params = {'page': page, 'per_page': per_page}
            url = f'{self.base_url}/api/http/routers'
            logging.info(f'Fetching routers from {url} with params {params}')
            try:
                response = self.session.get(url, params=params, timeout=10)
                response.raise_for_status()
                page_data = response.json()
                # Check if data is empty
                if not page_data:
                    break
                routers.extend(page_data)
                # Traefik's pagination may not provide Next-Page header
                if len(page_data) < per_page:
                    break
                page += 1
            except requests.RequestException as e:
                logging.error(f'Error fetching routers from Traefik API: {e}')
                break
        return routers

    def get_tls_domain_sets(self) -> List[Set[str]]:
        """Get sets of domains from routers that have TLS configured.

        Returns:
            A list of sets, each containing the domains used in a router's rule.
        """
        routers = self.get_routers()
        domain_sets = []
        for router in routers:
            if 'tls' in router:
                rule = router.get('rule', '')
                domains = self.extract_domains_from_rule(rule)
                if domains:
                    domain_sets.append(set(domains))
        return domain_sets

    @staticmethod
    def extract_domains_from_rule(rule: str) -> List[str]:
        """Extract domains from a Traefik router rule.

        Args:
            rule: The routing rule from a Traefik router.

        Returns:
            A list of domain names extracted from the rule.
        """
        domains = []
        # Remove any negations and path prefixes/suffixes
        rule = re.sub(r'!\s*PathPrefix\([^\)]*\)', '', rule)
        # Find all Host(`domain`), HostSNI(`domain`), and HostRegexp(`domain`) patterns
        host_pattern = re.compile(
            r'(Host|HostSNI|HostRegexp)\((`[^`]+`(?:,\s*`[^`]+`)*)\)')
        matches = host_pattern.findall(rule)
        for _, match in matches:
            # Extract multiple hosts if present
            hosts = re.findall(r'`([^`]+)`', match)
            domains.extend(hosts)
        return domains
