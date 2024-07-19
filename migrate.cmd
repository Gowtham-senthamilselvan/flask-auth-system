SET FLASK_APP=app.py
SET FLASK_ENV=development
flask db init
flask db stamp head
flask db migrate -m "Initial migration."
flask db upgrade
SET FLASK_RUN_HOST=0.0.0.0
SET FLASK_RUN_PORT=5000
flask run