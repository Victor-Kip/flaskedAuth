from flask import Flask, render_template,request,redirect,session,url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeSerializer
from flask_mail import Mail,Message
from api_key import *

app = Flask(__name__)
app.secret_key = 'mon_secret_key'

#configure SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] ="sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]= False
db = SQLAlchemy(app)

#configure oauth
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id = CLIENT_ID,
    client_secret = CLIENT_SECRET,
    access_token_url="https://oauth2.googleapis.com/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    api_base_url="https://www.googleapis.com/oauth2/v1/",
    userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    client_kwargs={"scope": "openid profile email"}
)

#database model (a single row in database)
class User(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    username = db.Column(db.String(25),unique = True,nullable = False)
    password_hash = db.Column(db.String(150),nullable =  True)

    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
    def check_password(self,password):
        return check_password_hash(self.password_hash,password)

#configure mail_trap
app.config['MAIL_SERVER']='live.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'api'
app.config['MAIL_PASSWORD'] = MAIL_API_KEY
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

#setup mail
mail = Mail(app)
serializer = URLSafeSerializer(app.secret_key)
def generate_confirmation_token(email):
    return serializer.dumps(email,salt = "email-confirm")
def confirm_token(token,salt):
    try:
        email = serializer.loads(token,salt = salt,max_age = 3600)
        return email
    except:
        return False
#routes
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

#login
@app.route("/login",methods = ["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    user = User.query.filter_by(username = username).first()
    if user and user.check_password(password):
        session["username"] = username
        return redirect(url_for("dashboard"))

    else:
        return render_template("index.html")
#register
@app.route("/register",methods = ["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    user = User.query.filter_by(username = username).first()
    if user:
        return render_template("index.html",error = "User already exists")
    else:
        new_user = User(username = username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        token = generate_confirmation_token(username)
        confirm_url = url_for("confirm_email",token = token, _external = True)
        msg = Message("Confirm Your Email",recipients = [username])
        msg.html = f"""Click <a href="{confirm_url}">here</a> to confirm your email"""
        mail.send(msg)
        return render_template("index.html",message = "Please check your email for confirmation")
#confirm email
@app.route("/confirm_email/<token>")
def confirm_email(token):
    email = confirm_token(token,salt = "email-confirm")
    if email:
        user = User.query.filter_by(username = email).first()
        if user:
            session["username"] = email
            return redirect(url_for("dashboard"))
    return render_template("index.html",error = "Invalid or expired token")
#dashboard
@app.route("/dashboard")
def dashboard():
    if "username" in session:
        return render_template("dashboard.html",username = session["username"])
    return redirect (url_for("home"))

#log out
@app.route("/logout")
def logout():
    session.pop("username")
    return redirect(url_for("home"))

#login with google
@app.route("/login/google")
def googlelogin():
    try:
        redirect_uri = url_for('authorize_google',_external = True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        app.logger.error(f"An error during login:{str(e)}" )
        return "Error during login",500

#google authorization
@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    userinfo_endpoint = google.server_metadata["userinfo_endpoint"]
    resp = google.get(userinfo_endpoint)
    user_info = resp.json()
    username = user_info["email"]

    user = User.query.filter_by(username = username).first()
    if not user:
        user = User(username = username)
        db.session.add(user)
        db.session.commit()
    session["username"] = username
    session["oauth_token"] = token
    return redirect(url_for("dashboard"))
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)