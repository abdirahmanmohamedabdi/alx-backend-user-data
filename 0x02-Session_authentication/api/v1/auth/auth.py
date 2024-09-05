#!/usr/bin/env python3
"""
Auth class defined here
"""
from flask import request
from typing import List, TypeVar
import re


class Auth:
    """Auth class
    """

    def require_auth(
        self, path: str, excluded_paths: List[str]
    ) -> bool:
        """Require auth method
        """
        if path is None or not excluded_paths:
            return True

        if path[-1] != '/':
            path += '/'
        for pth in excluded_paths:
            if pth[-1] == '*':
                pth = pth[:-1] + '.*'
            if re.fullmatch(pth, path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Authorization header method
        """
        if request is None:
            return None

        auth_header = request.headers.get('Authorization')
        if auth_header:
            return auth_header
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user method
        """
        return None

    def session_cookie(self, request=None):
        """Session cookie method
        """
        if request is None:
            return None

        session_name = request.cookies.get('SESSION_NAME')
        return request.cookies.get(session_name)