import random
import string
import uuid
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, make_response
from flask import current_app
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity, create_refresh_token, jwt_required
)
from config.security import permission
from models.models import User, UserToken, db, Role
from utils.helpers import send_otp_email

login_blueprint = Blueprint('login', __name__)

bcrypt = Bcrypt()


@login_blueprint.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        user_name = data.get('user_name')
        password = data.get('password')

        if user_name and password:
            # Check if the login attempt corresponds to a user
            user = User.query.filter_by(user_email=user_name, deleted=False).first()
            if user:
                role = Role.query.filter_by(role_id=user.role_id).first()

                # Verify user's password
                if bcrypt.check_password_hash(user.user_password, password):
                    access_token = create_access_token(
                        identity={
                            'id': user.user_id,
                            'email': user.user_email,
                            'role': role.role_name
                        }
                    )
                    refresh_token = create_refresh_token(identity=user.user_id)

                    expiry_datetime = datetime.now() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
                    new_user_token = UserToken(user_token_id=str(uuid.uuid4()), user_id=user.user_id,
                                               access_token=access_token, refresh_token=refresh_token,
                                               expiry_datetime=expiry_datetime, active=True)
                    db.session.add(new_user_token)
                    db.session.commit()

                    response = make_response(jsonify({
                        "user_id": user.user_id,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "role": role.role_name
                    }))
                    return response, 200
                else:
                    return jsonify(message='Invalid username or password.'), 400
        else:
            return jsonify(message='Invalid username or password.'), 400
    except Exception as e:
        # Log the exception for debugging
        print(f"An error occurred during login: {str(e)}")
        return jsonify(message='An unexpected error occurred.'), 500


@login_blueprint.route('/refresh_token', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()

        # Check if the current user is a regular user or an applicant
        if User.query.get(current_user_id):
            # Query the database for the user's refresh token
            user_token = UserToken.query.filter_by(user_id=current_user_id, active=True).first()

            if not user_token:
                return jsonify({'message': 'Invalid refresh token'}), 401

            # Delete the existing user token record
            db.session.delete(user_token)

            # Create a new access token and refresh token
            new_access_token = create_access_token(identity=current_user_id)
            new_refresh_token = create_refresh_token(identity=current_user_id)

            # Create a new user token record with the refreshed tokens
            expiry_datetime = datetime.now() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']

            new_user_token = UserToken(user_token_id=str(uuid.uuid4()), user_id=current_user_id,
                                       access_token=new_access_token, refresh_token=new_refresh_token,
                                       expiry_datetime=expiry_datetime, active=True)
            db.session.add(new_user_token)
            db.session.commit()

            return jsonify({'access_token': new_access_token, 'refresh_token': new_refresh_token}), 200
        else:
            return jsonify({'message': 'Invalid user or applicant'}), 400
    except Exception as e:
        # Log the exception for debugging
        print(f"An error occurred during token refresh: {str(e)}")
        return jsonify({'message': 'An unexpected error occurred.'}), 500


@login_blueprint.route('/forgot_password', methods=['POST'])
def forgot_password():
    try:
        data = request.json
        email = data.get('email')

        # Check if the email corresponds to a user
        user = User.query.filter_by(user_email=email, deleted=False).first()
        if user:
            # Generate a random 6-digit OTP
            otp = ''.join(random.choice(string.digits) for _ in range(6))

            # Save the OTP and its expiration time in the database for the user
            user.otp = otp
            user.otp_expiry = datetime.now() + timedelta(minutes=5)  # OTP expires in 5 minutes
            db.session.commit()

            # Send OTP to the user's email
            send_otp_email(user.user_email, otp)

            return jsonify(message='OTP has been sent to your email.'), 200

        return jsonify(message='No user found with that email.'), 404

    except Exception as e:
        # Log the exception for debugging
        print(f"An error occurred during forgot password: {str(e)}")
        return jsonify(message='An unexpected error occurred.'), 500


@login_blueprint.route('/verify_otp', methods=['POST'])
def verify_otp():
    try:
        data = request.json
        email = data.get('email')
        otp_entered = data.get('otp')

        # Check if the OTP corresponds to a user
        user = User.query.filter_by(user_email=email, otp=otp_entered, deleted=False).first()
        if user:
            # Check if OTP is still valid
            if user.otp_expiry and user.otp_expiry >= datetime.now():
                # OTP is valid, proceed to password reset
                user.otp = None  # Clear the OTP
                user.otp_verified = True
                db.session.commit()
                return jsonify({
                    "message": 'OTP verified successfully. You can now reset your password.',
                    "user_id": user.user_id}), 200
            else:
                return jsonify(message='OTP has expired. Please request a new OTP.'), 400
        else:
            return jsonify(message='Invalid OTP'), 404
    except Exception as e:
        # Log the exception for debugging
        print(f"An error occurred during OTP verification: {str(e)}")
        return jsonify(message='An unexpected error occurred.'), 500


@login_blueprint.route('/update_password', methods=['POST'])
def update_password():
    try:
        data = request.json
        user_id = data.get('user_id')
        new_password = data.get('new_password')

        # Check if the email corresponds to a user
        user = User.query.filter_by(user_id=user_id, otp_verified=True, deleted=False).first()
        if user:
            # Update the user's password with the new password after hashing
            user.user_password = bcrypt.generate_password_hash(new_password)  # Hash the new password
            user.otp_verified = False  # Reset OTP verification status
            db.session.commit()
            return jsonify(message='Password has been successfully updated.'), 200

    except Exception as e:
        # Log the exception for debugging
        print(f"An error occurred during password update: {str(e)}")
        return jsonify(message='An unexpected error occurred.'), 500


@login_blueprint.route('/change_password', methods=['POST'])
@permission()
def change_users_password(token):
    try:
        data = request.json
        user_id = data.get('user_id')
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not user_id or not current_password or not new_password:
            return jsonify(message='Missing mandatory fields.'), 400

        # Check if the user exists in the User table
        user = User.query.filter_by(user_id=user_id, deleted=False).first()
        if user:
            if bcrypt.check_password_hash(user.user_password, current_password):
                # Update the user's password
                user.user_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.session.commit()
                return jsonify(message='Password has been successfully updated.'), 200
            else:
                return jsonify(message='Please check your current password.'), 401

        return jsonify(message='Invalid user.'), 401

    except Exception as e:
        # Log the exception for debugging
        print(f"An error occurred during password change: {str(e)}")
        return jsonify(message='An unexpected error occurred.'), 500