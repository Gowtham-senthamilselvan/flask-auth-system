import logging
import os
import re
import uuid
from flask_bcrypt import Bcrypt
from flask_mail import Message, Mail
from models.models import Role, User
from flask import current_app
import boto3
from botocore.exceptions import ClientError

bcrypt = Bcrypt()
mail = Mail()

logging.basicConfig(
    format="| APP-LOG |: %(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("hrms.log"),
              logging.StreamHandler()],
    datefmt="%d-%b-%y %H:%M:%S",
    level=logging.INFO,
)

LOGGER = logging.getLogger()

AdminMail = "admin@gmail.com"


def seed_custom_roles_and_users(db, app):
    with app.app_context():

        admin_role = Role.query.filter_by(role_name='admin').first()

        if not admin_role:
            admin_role = Role(role_id=str(uuid.uuid4()), role_name='admin')
            db.session.add(admin_role)

        hr_role = Role.query.filter_by(role_name='hr').first()

        if not hr_role:
            hr_role = Role(role_id=str(uuid.uuid4()), role_name='hr')
            db.session.add(hr_role)

        db.session.commit()

        admin_user = User.query.filter_by(user_email=AdminMail).first()

        password = 'admin123'
        hashed_password = bcrypt.generate_password_hash(password)

        if not admin_user:
            admin_user = User(user_id=str(uuid.uuid4()), user_name='admin', user_email=AdminMail,
                              user_mobile='1234', user_password=hashed_password,
                              role_id=admin_role.role_id,
                              otp=None, otp_expiry=None, otp_verified=None)
            db.session.add(admin_user)
        db.session.commit()


def validate_mandatory_fields(data, fields):
    for field in fields:
        value = data.get(field)
        if not value or (isinstance(value, str) and not value.strip()):
            return False
    return True


def validate_email(input_data):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if re.match(email_pattern, input_data):
        return True
    else:
        return None


def send_otp_email(to_email, otp):
    subject = "OTP for Password Reset"
    html_body = f"""
    <html>
    <body>
        <p>Dear User,</p>
        <p>You have requested to reset your password. Your One-Time Password (OTP) for password reset is: <strong>{otp}</strong>.</p>
        <p>Please use this OTP to proceed with the password reset process.</p>
        <p>Thank you,<br>IT Support</p>
    </body>
    </html>
    """

    msg = Message(subject, recipients=[to_email], html=html_body)
    mail.send(msg)


# S3 Bucket Connection Credentials
access_key_id = ''
secret_access_key = ''

s3 = boto3.client('s3',
                  aws_access_key_id=access_key_id,
                  aws_secret_access_key=secret_access_key)


def create_folder(bucket_name, folder_name):
    # Construct the S3 key for the folder
    folder_key = f"{folder_name}/"

    # Check if the folder already exists
    try:
        s3.head_object(Bucket=bucket_name, Key=folder_key)
    except:
        # If the folder doesn't exist, create it
        s3.put_object(Bucket=bucket_name, Key=folder_key, Body='')


def list_files_in_folder(bucket_name, folder_name):
    try:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=folder_name)
        if 'Contents' in response:
            return [obj['Key'] for obj in response['Contents']]
        return []
    except Exception as e:
        print(f"Error listing files in folder: {e}")
        return []


def delete_file_from_s3(bucket_name, key):
    try:
        s3.delete_object(Bucket=bucket_name, Key=key)
        return True
    except Exception as e:
        print(f"Error deleting file from S3: {e}")
        return False


def save_file_to_aws_users(file, filename_prefix, container_name):
    if file:
        _, ext = os.path.splitext(file.filename)

        filename = f"{filename_prefix}{ext}"

        # Specify the bucket name
        bucket_name = current_app.config['S3_BUCKET_NAME']

        # Specify the folder name within the bucket
        parent_folder_name = current_app.config['UPLOAD_FOLDER']

        new_folder_name = container_name

        # Create the new folder within the user folder
        create_folder(bucket_name, f"{parent_folder_name}/{new_folder_name}")

        # Construct the S3 key including the new folder
        key = f"{parent_folder_name}/{new_folder_name}/{filename}"

        # List all files in the target folder
        folder_path = f"{parent_folder_name}/{new_folder_name}/"
        files_in_folder = list_files_in_folder(bucket_name, folder_path)

        # Extract the file name without the extension
        file_name_without_extn = filename_prefix

        # Check if any file matches the prefix (ignoring the extension)
        for existing_file_key in files_in_folder:
            existing_filename = os.path.basename(existing_file_key)
            existing_prefix, _ = os.path.splitext(existing_filename)
            if existing_prefix == file_name_without_extn:
                delete_file_from_s3(bucket_name, existing_file_key)

        # Upload the file to AWS S3 Bucket
        try:
            s3.upload_fileobj(file, bucket_name, key, ExtraArgs={'ContentType': file.content_type})
            # If successful, return the filename
            return filename
        except Exception as e:
            print(f"Error uploading file to S3: {e}")
            return None


def generate_s3_url_users(user_id, filename):
    if not filename:
        return None  # If filename is None or empty, return None

    # Assuming your S3 bucket name is stored in your app configuration
    s3_bucket_name = current_app.config['S3_BUCKET_NAME']
    # Assuming the files are stored in a folder named 'uploads' under 'users' directory
    s3_base_url = f"https://{s3_bucket_name}.s3.ap-south-1.amazonaws.com/users/{user_id}/"

    # Construct the full key
    s3_key = f"users/{user_id}/{filename}"

    try:
        # Check if the file exists in the S3 bucket
        s3.head_object(Bucket=s3_bucket_name, Key=s3_key)
    except ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            return None  # File not found in S3
        else:
            raise e  # Re-raise the exception if it's not a 404

    # Combine the base URL and the filename to generate the complete S3 URL
    return s3_base_url + filename
