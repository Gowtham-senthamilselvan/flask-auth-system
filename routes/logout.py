from datetime import datetime
from flask import Blueprint, jsonify, request
from models.models import UserToken, db, User

logout_blueprint = Blueprint('logout', __name__)


@logout_blueprint.route('/logout', methods=['POST'])
def logout():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify(message='Authorization header is missing.'), 401

        token = auth_header.split(' ')[1]

        # Check if the token corresponds to a user
        token_record = UserToken.query.filter_by(access_token=token).first()
        if token_record:
            if token_record.active:
                current_datetime = datetime.now()
                if current_datetime < token_record.expiry_datetime:
                    user_id = token_record.user_id
                    user = User.query.get(user_id)
                    user.last_login_time = current_datetime
                    db.session.commit()
                db.session.delete(token_record)
                db.session.commit()
                return jsonify(message='Logged out successfully.'), 200
            else:
                return jsonify(message='Token is already inactive.'), 401

    except Exception as e:
        # Log the exception for debugging
        print(f"An error occurred during logout: {str(e)}")
        return jsonify(message='An unexpected error occurred.'), 500
