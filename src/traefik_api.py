#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Traefik API Interaction Module.

This module provides functionality to interact with the Traefik API to
fetch routers and extract domains for in-use certificate determination.

Author:
    Troy Kelly <troy@aperim.com>

Code History:
    - 2024-10-06: Initial creation.
    - 2024-10-06: Added pagination handling and improved domain extraction.

"""

import logging
import re
from typing import Any, Dict, List, Optional

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
        url = f'{self.base_url}/api/http/routers'
        while url:
            logging.info(f'Fetching routers from {url}')
            try:
                response = self.session.get(url, timeout=10)
                response.raise_for_status()
                routers.extend(response.json())
                url = response.headers.get('X-Next-Page')
            except requests.RequestException as e:
                logging.error(f'Error fetching routers from Traefik API: {e}')
                break
        return routers

    def get_tls_domains(self) -> List[str]:
        """Get domains from routers that have TLS configured."""
        routers = self.get_routers()
        domains = set()
        for router in routers:
            if 'tls' in router:
                rule = router.get('rule', '')
                # Parse rule to extract domains
                extracted_domains = self.extract_domains_from_rule(rule)
                domains.update(extracted_domains)
        return list(domains)

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
        # Find all Host(`domain`) patterns
        host_matches = re.findall(r'Host\((`[^`]+`(?:,\s*`[^`]+`)*)\)', rule)
        for match in host_matches:
            # Extract multiple hosts if present
            hosts = re.findall(r'`([^`]+)`', match)
            domains.extend(hosts)
        return domains
