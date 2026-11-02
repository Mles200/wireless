"""Tenable Report Studio connector.

Pulls vulnerability and compliance results from Tenable Security Center (REST API, port 443)
or Nessus / Nessus Manager (port 8834), writes them as CSV exports with the column layout of
the Security Center "Vulnerability Detail List" export, keeps every pull in a dated store and
serves the Studio (the single-file browser tool) with a "Tenable" panel that loads a pull
straight into it.
"""

__version__ = "0.1.0"
