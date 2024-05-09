from flask import Blueprint, render_template, request, flash, redirect, url_for, session, Flask, abort
from google.auth.transport import requests
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
import os
import google.auth.transport.requests
from google.auth.transport import requests  # Correct import statement
import pathlib
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

auth = Blueprint('auth', __name__)  #Initializes a Flask blueprint named 'auth', used to organize routes related to authentication.
app = Flask(__name__)

# Login Requirement
def login_is_required(function): #checks if a user is logged in (based on the presence of "google_id"
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            #The wrapper function used by the decorator. It checks for "google_id" in the session and either
            # aborts with a 401 error or calls the wrapped function.
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" #Allows OAuth to work over HTTP instead of HTTPS

GOOGLE_CLIENT_ID = ".apps.googleusercontent.com"

# the path to the client_secret.json file, which contains the configuration details
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

    #OAuth Flow Configuration
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# Defines the route for logging out. It clears the user session and redirects to the login page
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('auth.log_in'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)


@auth.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@auth.route('/log_in', methods=['GET', 'POST'])
def log_in():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


#Define the Callback Route
@auth.route("/callback")
def callback():
    ## (1)Fetch the OAuth token using the authorization response
    flow.fetch_token(authorization_response=request.url)
 # (2)Validate OAuth State
    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials  # (3)Retrieve OAuth Credentials
    # (4)Set Up Cached Session
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)
# (5)Verify the ID Token
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
#(6)tore User Information in Session
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")#Redirect to a Protected Area


@auth.route("/")
def index():
    #return render_template('home.html', user=current_user)
    return "Hello World <a href='/login'><button>Login</button></a>"

@auth.route("/protected_area")
@login_is_required
def protected_area():
    #return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"
    return render_template('home.html', user=current_user)