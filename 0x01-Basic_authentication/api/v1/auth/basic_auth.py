#!/usr/bin/env python3
"""
Auth class defined here
"""
import base64
from api.v1.auth.auth import Auth
from typing import TypeVar, Optional
from models.user import User

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
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
         self, decoded_base64_authorization_header: str) -> (str, str):
        """Extract user credentials method
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        email, password = decoded_base64_authorization_header.split(':', 1)
        return email, password

    def user_object_from_credentials(
         self, user_email: str, user_pwd: str) -> Optional[UserType]:
        """User object from credentials method
        """
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None
        if user_email is None or user_pwd is None:
            return None

        # Returns a list of users based on email
        users = User.search(user_email)
        if not users:
            return None

        for users in users:
            if users.is_valid_password(user_pwd):
                return users
        return None
