#!/usr/bin/env python3
"""
Auth class defined here
"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """BasicAuth class
    """
    
    def extract_base64_authorization_header(
        self,authorization_header: str) -> str:
        """Extract base64 authorization header method
        """
        if not authorization_header:
            return None
        if type(authorization_header) != str:
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]