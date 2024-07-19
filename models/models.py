from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.dialects.mysql import VARCHAR, DATETIME, BOOLEAN
import uuid

db = SQLAlchemy()

uuid = str(uuid.uuid4())


class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(VARCHAR(50), primary_key=True, default=uuid)
    role_name = db.Column(VARCHAR(100), nullable=False)
    role_add_time = db.Column(DATETIME, default=datetime.now(timezone.utc))
    role_update_time = db.Column(DATETIME, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    deleted = db.Column(BOOLEAN, default=False)
    deleted_time = db.Column(DATETIME)

    def soft_delete(self):
        self.deleted = True
        self.deleted_time = datetime.now(timezone.utc)
        db.session.commit()


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(VARCHAR(50), primary_key=True, default=uuid)
    user_name = db.Column(VARCHAR(100))
    user_email = db.Column(VARCHAR(100))
    user_mobile = db.Column(VARCHAR(15))
    user_password = db.Column(VARCHAR(100))
    role_id = db.Column(VARCHAR(50),
                        ForeignKey(ondelete="SET NULL", column='roles.role_id'))
    photo = db.Column(VARCHAR(1000))
    otp = db.Column(VARCHAR(10))
    otp_expiry = db.Column(DATETIME)
    otp_verified = db.Column(BOOLEAN)
    referral = db.Column(VARCHAR(10))
    user_add_time = db.Column(DATETIME, default=datetime.now(timezone.utc))
    user_update_time = db.Column(DATETIME, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    last_login_time = db.Column(DATETIME)
    deleted = db.Column(BOOLEAN, default=False)
    deleted_time = db.Column(DATETIME)

    def soft_delete(self):
        self.deleted = True
        self.deleted_time = datetime.now(timezone.utc)
        db.session.commit()


class UserToken(db.Model):
    __tablename__ = 'user_token'
    user_token_id = db.Column(VARCHAR(50), primary_key=True, default=uuid)
    user_id = db.Column(VARCHAR(50), ForeignKey(ondelete="SET NULL", column='users.user_id'))
    refresh_token = db.Column(VARCHAR(1000))
    access_token = db.Column(VARCHAR(1000))
    expiry_datetime = db.Column(DATETIME)
    active = db.Column(BOOLEAN)