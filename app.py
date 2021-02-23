from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import Length, Email, InputRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///aplicatie.db"
app.config['SECRET_KEY'] = 'Cheie_Secreta'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
Bootstrap(app)


# ------------------------------------Models-----------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    email = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(80))
    isAdmin = db.Column(db.Boolean)


class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(70))
    text = db.Column(db.String())


# --------------------------------Authentichation--------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------------------Forms-Login/SignUp-------------------------------------------------
class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message="Invalid Email"), Length(min=6, max=30)])
    username = StringField('Nume Utilizator', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Parola', validators=[InputRequired(), Length(min=5, max=80)])


class LoginForm(FlaskForm):
    username = StringField('Nume Utilizator', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Parola', validators=[InputRequired(), Length(min=5, max=80)])
    remember = BooleanField('TIne-ma minte', default=False)


# --------------------------------Routes---------------------------------------------
@app.route('/')
def index():
    news = News.query.all()
    return render_template('index.html', news=news)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:

            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        password_hash = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=password_hash, email=form.email.data, isAdmin=False)
        db.session.add(new_user)
        db.session.commit()
        return "User created"
    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
