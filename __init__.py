from flask import Flask # Imports the Flask class to create the Flask application.
from flask_sqlalchemy import SQLAlchemy  # Imports SQLAlchemy for database operations.
from os import path    # Imports the path module from os for working with file paths.
from flask_login import LoginManager  # Imports LoginManager from Flask-Login for managing user sessions and authentication.


db = SQLAlchemy()  # Initializes an SQLAlchemy object to be used later in the Flask application.
DB_NAME = "database.db"  #


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'QWERTYUIOPasdfghjkl1234'   #  Sets a secret key for session management and security features like CSRF protection
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}' #Configures the SQLAlchemy database URI to use SQLite with the defined database name.
    db.init_app(app) #Initializes the SQLAlchemy instance with the Flask application.

    from .views import views # : Imports a module that defines routes and views for the application.
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')  # Registers the views blueprint with the Flask application
    app.register_blueprint(auth, url_prefix='/')

#User Authentication Setup
    from .models import User
    with app.app_context():
        create_database()
         # for handling user sessions and authentication.
        login_manager = LoginManager()
        login_manager.login_view = 'auth.log_in'
        login_manager.init_app(app)


     # A decorator that specifies a function to load a user by their ID from the database when restoring a session.
        @login_manager.user_loader
        def load_user(id):
            return User.query.get(int(id))

    return app


def create_database():
    try:
        if not path.exists('website/' + DB_NAME):
            db.create_all()   #Creates all defined tables in the database if they don't already exist
            print('database created')
    except Exception as e:
        print(f"Error creating database: {str(e)}")
