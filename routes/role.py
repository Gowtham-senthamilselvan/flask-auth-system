import uuid
from flask import Blueprint, request, jsonify
from config.security import permission
from models.models import db, Role

roles_blueprint = Blueprint('roles', __name__)


@roles_blueprint.route('/roles', methods=['POST'])
@permission()
def add_role(token):
    try:
        data = request.json

        role_name = data.get('role_name')

        new_role = Role(
            role_id=str(uuid.uuid4()),
            role_name=role_name
        )

        db.session.add(new_role)
        db.session.commit()

        return jsonify({"message": "Role added successfully", "role_id": new_role.role_id}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@roles_blueprint.route('/roles', methods=['GET'])
@permission()
def get_roles(token):
    try:
        page = request.args.get('page', type=int, default=1)
        per_page = request.args.get('per_page', type=int, default=12)
        search_term = request.args.get('search', type=str)

        query = Role.query.filter(Role.role_name != "admin", Role.role_name != "applicant",
                                  Role.role_name != "employee", Role.deleted == False)

        if search_term:
            query = query.filter(Role.role_name.ilike(f"%{search_term}%"))

        roles = query.paginate(page=page, per_page=per_page, error_out=False)

        result = []
        for role in roles.items:
            result.append({
                "role_id": role.role_id,
                "role_name": role.role_name
            })

        return jsonify({
            "roles": result,
            "total_roles": roles.total,
            "current_page": roles.page,
            "per_page": roles.per_page
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@roles_blueprint.route('/roles/<path:role_id>', methods=['GET'])
@permission()
def get_role_by_id(token, role_id):
    try:

        role = Role.query.filter_by(role_id=role_id).first()

        if role:
            role_data = {
                "role_id": role.role_id,
                "role_name": role.role_name
            }

            return jsonify(role_data), 200
        else:
            return jsonify({"message": "Role not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@roles_blueprint.route('/roles/<path:role_id>', methods=['PUT'])
@permission()
def update_role(token, role_id):
    try:
        data = request.json

        if not data or 'role_name' not in data:
            return jsonify({"error": "Missing or invalid data"}), 400

        role = Role.query.filter_by(role_id=role_id).first()

        if role:
            role.role_name = data['role_name']
            db.session.commit()

            role_data = {
                "role_id": role.role_id,
                "role_name": role.role_name
            }

            return jsonify(role_data), 200
        else:
            return jsonify({"message": "Role not found"}), 404

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@roles_blueprint.route('/delete_roles', methods=['POST'])
@permission()
def delete_role(token):
    try:
        data = request.json

        role_ids = data.get('role_ids')

        if not role_ids or not isinstance(role_ids, list):
            return jsonify({'message': 'No valid role IDs provided'}), 400

        # Soft delete each application by its ID
        deleted_role_ids = []
        for role_id in role_ids:
            role = Role.query.get(role_id)
            if role:
                role.soft_delete()
                deleted_role_ids.append(role_id)
            else:
                return jsonify({'message': f"Role not found with the given ID: {role_id}"}), 404

        # Commit the changes to the database
        db.session.commit()

        return jsonify({
            "message": "Roles deleted successfully",
            "deleted_role_ids": deleted_role_ids
        }), 200


    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500