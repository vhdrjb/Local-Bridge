"""
LocalBridge - Selective MITM Proxy with SOCKS5

A local proxy solution that accepts SOCKS5 connections and intelligently
handles certificate-pinned applications by NOT performing MITM on them,
while still allowing modification of non-pinned traffic.

Key Innovation: Selective MITM - tunnel pinned connections, intercept only non-pinned.
"""

__version__ = "0.1.0"
__author__ = "LocalBridge Contributors"
