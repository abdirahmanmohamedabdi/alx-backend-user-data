#!/usr/bin/env python3
""" Module of session auth
"""
from api.v1.auth.auth import Auth
import uuid


class SessionAuth(Auth):
    """ SessionAuth class
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """ Creates a session id """
        if user_id is None or not isinstance(user_id, str):
            return None

        # Generate a session ID
        session_id = str(uuid.uuid4())

        # Store the session ID in the dictionary
        self.user_id_by_session_id[session_id] = user_id

        return session_id
