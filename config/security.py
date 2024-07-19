from datetime import datetime
from functools import wraps
import jwt
from flask import current_app
from flask import request, jsonify
from sqlalchemy import and_
from models.models import db, User, UserToken


def fetch_user(token) -> None | User:
    try:
        decoded_token = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['sub']['id']
        user = User.query.filter(and_(User.user_id == user_id, User.deleted != 1)).first()
        return user
    except jwt.ExpiredSignatureError:
        return jsonify(message='Unauthorized. Token has expired.'), 401
    except jwt.InvalidTokenError:
        return jsonify(message='Unauthorized. Invalid token.'), 401


def permission():
    def decorate(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify(error="Authorization header is missing!"), 401

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return jsonify(error="Invalid Authorization header format!"), 401

            token = parts[1]
            if not token:
                return jsonify(error="Token is missing!"), 401

            token_record = UserToken.query.filter_by(access_token=token, active=True).first()

            if token_record and token_record.active:
                current_datetime = datetime.now()
                if current_datetime < token_record.expiry_datetime:
                    user_id = token_record.user_id
                    user = User.query.filter_by(user_id=user_id, deleted=False).first()
                    if user:
                        # Update last login time
                        user.last_login_time = current_datetime
                        db.session.commit()
                    else:
                        return jsonify({"error": "User Not Found!"}), 400
                else:
                    return jsonify({"error": "Token has expired."}), 401
            else:
                return jsonify(error="Unrecognized Token, Login again!"), 401

            user = fetch_user(token)
            if not user:
                return jsonify(error="User Not Found!"), 400

            user.last_login_time = datetime.now()
            db.session.commit()

            return f(token, *args, **kwargs)

        return decorated

    return decorate
