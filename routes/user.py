import random
import string
import uuid
from flask import Blueprint, request, jsonify
from config.security import permission
from models.models import db, User, Role
from flask_bcrypt import Bcrypt
from datetime import datetime, timezone
from utils.helpers import (validate_email, validate_mandatory_fields, save_file_to_aws_users, generate_s3_url_users,
                           AdminMail)

users_blueprint = Blueprint('users', __name__)

bcrypt = Bcrypt()


@users_blueprint.route('/users', methods=['POST'])
@permission()
def add_user(token):
    try:
        data = request.form

        mandatory_fields = ['user_name', 'user_email', 'user_password', 'role_id']

        if not validate_mandatory_fields(data, mandatory_fields):
            return jsonify({'message': 'Missing or invalid mandatory fields'}), 400

        user_password = data['user_password']

        hashed_password = bcrypt.generate_password_hash(user_password)

        user_mobile = data['user_mobile']

        user_email = data['user_email']
        if user_email and user_email.strip():
            email_validation = validate_email(user_email)
            if email_validation:
                existing_user = User.query.filter_by(user_email=user_email, deleted=False).first()
                if existing_user:
                    return jsonify({'message': 'User with this email address already exists'}), 400
            else:
                return jsonify({'message': 'Invalid email address format'}), 400

        photo = request.files.get('photo')

        referral = ''.join(random.choices(string.digits, k=6))

        # Create User
        new_user = User(
            user_id=str(uuid.uuid4()),
            user_name=data['user_name'],
            user_email=user_email,
            user_mobile=user_mobile,
            user_password=hashed_password,
            role_id=data['role_id'],
            referral=referral,
            user_add_time=datetime.now(timezone.utc),
            user_update_time=datetime.now(timezone.utc)
        )
        db.session.add(new_user)
        db.session.flush()

        if photo:
            new_user.photo = save_file_to_aws_users(photo,
                                                    f"{new_user.user_id}_photo",
                                                    new_user.user_id)
        db.session.commit()

        role = Role.query.filter_by(role_id=new_user.role_id, deleted=False).first()

        return jsonify({
            "message": "User added successfully",
            "user_id": new_user.user_id,
            "role": role.role_name
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@users_blueprint.route('/users', methods=['GET'])
@permission()
def get_all_users(token):
    try:
        page = request.args.get('page', type=int, default=1)
        per_page = request.args.get('per_page', type=int, default=12)
        search_term = request.args.get('search', type=str)

        users_query = db.session.query(User, Role.role_name).outerjoin(Role, User.role_id == Role.role_id).filter(
            User.user_email != AdminMail, User.deleted == False)

        # Apply search filter if search term is provided
        if search_term:
            search_pattern = f"%{search_term}%"
            users_query = users_query.filter(
                (User.user_name.ilike(search_pattern)) |
                (User.user_email.ilike(search_pattern)) |
                (User.user_mobile.ilike(search_pattern)) |
                (Role.role_name.ilike(search_pattern))
            )

        paginated_users = users_query.paginate(page=page, per_page=per_page, error_out=False)

        response_data = {
            "users": [{
                "user_id": user.user_id,
                "user_name": user.user_name,
                "user_email": user.user_email,
                "role_name": role_name,
                "last_login": user.last_login_time.strftime('%Y-%m-%d %H:%M:%S') if user.last_login_time else None,
                "created_date": user.user_add_time.strftime('%Y-%m-%d'),
                "photo": generate_s3_url_users(user.user_id, user.photo),
                "referral_code": user.referral
            } for user, role_name in paginated_users.items],
            "page": paginated_users.page,
            "per_page": paginated_users.per_page,
            "total_pages": paginated_users.pages,
            "total_count": paginated_users.total
        }

        return jsonify(response_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@users_blueprint.route('/users/<path:user_id>', methods=['GET'])
@permission()
def get_user_by_id(token, user_id):
    try:
        # Query to get the user by ID and join with the Role table
        user_query = db.session.query(User, Role.role_name).outerjoin(Role, User.role_id == Role.role_id).filter(
            User.user_id == user_id,
            User.deleted == False
        ).first()

        if not user_query:
            return jsonify({"message": "User not found"}), 404

        user, role_name = user_query

        response_data = {
            "user_id": user.user_id,
            "user_name": user.user_name,
            "role_name": role_name,
            "user_email": user.user_email,
            "user_mobile": user.user_mobile,
            "last_login": user.last_login_time.strftime('%Y-%m-%d %H:%M:%S') if user.last_login_time else None,
            "created_date": user.user_add_time.strftime('%Y-%m-%d'),
            "photo": generate_s3_url_users(user.user_id, user.photo),
            "referral_code": user.referral
        }

        return jsonify(response_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@users_blueprint.route('/users/<path:user_id>', methods=['PUT'])
@permission()
def update_user_by_id(token, user_id):
    try:
        user = User.query.get(user_id)

        if user and not user.deleted:
            data = request.form

            photo = request.files.get('photo')

            # Check for existing email conflict
            if 'user_email' in data:
                existing_user = User.query.filter_by(user_email=data['user_email'], deleted=False).first()
                if existing_user and existing_user.user_id != user_id:
                    return jsonify({'message': 'Another user with this email address already exists'}), 400

            # Update fields based on the provided data
            user.user_name = data.get('user_name', user.user_name)
            user.user_email = data.get('user_email', user.user_email)
            user.user_mobile = data.get('user_mobile', user.user_mobile)

            user.role_id = data.get('role_id', user.role_id)

            if photo:
                user.photo = save_file_to_aws_users(photo,
                                                    f"{user.user_id}_photo",
                                                    user.user_id)

            user.user_update_time = datetime.now(timezone.utc)

            db.session.commit()

            return jsonify({"message": "User updated successfully"}), 200
        else:
            return jsonify({"message": "User not found or deleted"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@users_blueprint.route('/delete_users', methods=['POST'])
@permission()
def delete_multiple_users(token):
    try:
        data = request.json

        if not data:
            return jsonify({'message': 'Request body is missing or not in JSON format'}), 400

        user_ids = data.get('user_ids')

        deleted_user_ids = []
        for user_id in user_ids:
            user = User.query.filter_by(user_id=user_id, deleted=False).first()
            if user:
                user.soft_delete()
            else:
                return jsonify({'message': f'User with ID {user_id} not found or already deleted'}), 400

        db.session.commit()

        return jsonify({
            "message": "Users deleted successfully",
            "deleted_user_ids": deleted_user_ids
        }), 200

    except Exception as e:
        return jsonify({'message': 'An error occurred while processing the request', 'error': str(e)}), 500
