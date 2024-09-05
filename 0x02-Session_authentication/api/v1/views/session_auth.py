#!/usr/bin/env python3
""" Module for session Authentication views
"""
from flask import jsonify, request
from models.user import User
from api.v1.app import auth

@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def handle_login() -> str:
    """ POST /auth_session/login
    JSON body:
      - email
      - password
    Return:
      - User object JSON represented
      - 400 if email or password is missing
      - 401 if email or password is wrong
    """
    email = request.form.get('email')
    passwd = request.form.get('password')
    user = None

    if not email:
        return jsonify({
            "error": "email missing"
        }), 400
    if not passwd:
        return jsonify({
            "error": "password missing"
        }), 400

    users = User.search({
        'email': email
    })

    if users:
        user = users[0]

    if user.is_valid_password(passwd) is False:
        session_id = auth.create_session(user.id)
        cookie_name = os.getenv('SESSION_NAME')
        resp = jsonify(user.to_json())
        resp.set_cookie(cookie_name, session_id)
        return resp