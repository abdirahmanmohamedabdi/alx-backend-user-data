#!/usr/bin/env python3
"""
Auth class defined here
"""
import base64
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """BasicAuth class
    """

    def extract_base64_authorization_header(
         self, authorization_header: str) -> str:
        """Extract base64 authorization header method
        """
        if not authorization_header:
            return None
        if type(authorization_header) != str:
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
         self, base64_authorization_header: str) -> str:
        """Decode base64 authorization header method
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decode_bytes = base64.b64decode(base64_authorization_header)
            return decode_bytes.decode('utf-8')
        except (base64binascii.Error, UnicodeDecodeError):
            return None
