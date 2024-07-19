from datetime import timedelta
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_swagger_ui import get_swaggerui_blueprint
from models.models import db
from utils.helpers import seed_custom_roles_and_users, mail
from routes.login import login_blueprint
from routes.logout import logout_blueprint
from routes.role import roles_blueprint
from routes.user import users_blueprint

app = Flask(__name__)

api_version = "v1"


@app.route('/api/v1', methods=['GET'])
def home_page():
    return f'API Version: {api_version}'


app.config['SECRET_KEY'] = 'your secret key'

# S3 Bucket Configuration
app.config['S3_BUCKET_NAME'] = ''

# JWT Token Configuration
app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_TOKEN_LOCATION'] = ["headers"]
app.config['JWT_HEADER_NAME'] = "Authorization"
app.config['JWT_HEADER_TYPE'] = ""

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://username:password@localhost/db_name'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask Mail Configuration
app.config['MAIL_SERVER'] = ''
app.config['MAIL_PORT'] = ''
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = ''

app.config['UPLOAD_FOLDER'] = 'users'

# Cors Header Configuration
CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

mail.init_app(app)
jwt = JWTManager(app)

# Register blueprints for routes
apiPrefixV1 = '/api/v1/'

app.register_blueprint(login_blueprint, url_prefix=apiPrefixV1)
app.register_blueprint(logout_blueprint, url_prefix=apiPrefixV1)
app.register_blueprint(roles_blueprint, url_prefix=apiPrefixV1)
app.register_blueprint(users_blueprint, url_prefix=apiPrefixV1)

# Register the Swagger UI blueprint
SWAGGER_URL = '/swagger'
API_URL = '/static/auth-system-swagger.json'
swagger_ui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Flask Authentication System"
    }
)
app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL, name="flask_auth_system_swagger")

db.init_app(app)

with app.app_context():
    migrate = Migrate(app, db)
    db.create_all()
    seed_custom_roles_and_users(db, app)
