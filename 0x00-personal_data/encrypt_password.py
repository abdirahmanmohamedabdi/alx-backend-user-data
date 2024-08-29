#!/usr/bin/env python3
"""
Definition a hashed_password function
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    returns a hashed password, which is a byte string
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    checks whether a password is valid
    """
    return bcrypt.checkpw(password.encode(), hashed_password)