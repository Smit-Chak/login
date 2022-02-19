from email import message
from enum import unique
from wsgiref import validate
from wsgiref.validate import validator
from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField , PasswordField, SubmitField 
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, EqualTo, Regexp
from flask_bcrypt import Bcrypt

app = Flask(__name__)


#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:smit1303@localhost/auth'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://bogvuqqqhdtvde:8cba747a9cf2ea6209fdcbb3159fa601dbacd4f9af693c1f443f762894b88f74@ec2-34-253-29-48.eu-west-1.compute.amazonaws.com:5432/ddq5q15kpm4c9f'
app.config['SECRET_KEY'] = '12345'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'auth'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)
    quotes = db.Column(db.String(100))

class RegisterForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(min = 5, max = 20)], render_kw = {"placeholder" : "Username"})
    password = PasswordField(validators = [InputRequired(), Length(min = 5, max = 80), Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$',
     message = "*Password should contain alteast 1 uppercase, lowercase, special symbol")],
      render_kw = {"placeholder" : "Password"})
    confirm_password = PasswordField(validators = [DataRequired(message='*Required'), EqualTo('password' , message = "*Password doesn't match")], render_kw = {'placeholder' : 'Confirm Password'})
    submit = SubmitField("Register")
    def validate_username(self, username):
        existing_username = User.query.filter_by(username = username.data).first()
        if existing_username :
            raise ValidationError(
                f"Username already Exists."
            )

class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(min = 4, max = 20)], render_kw = {"placeholder" : "Username"})
    password = PasswordField(validators = [InputRequired(), Length(min = 4, max = 80)], render_kw = {"placeholder" : "Password"})
    submit = SubmitField("Login")


@app.route('/')
def home():
    result = User.query.all()
    return render_template('home.html')

@app.route('/quote', methods=['GET', 'POST'])
def quote():
    result = User.query.all()
    return render_template('quote.html', result = result)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/process', methods=['GET', 'POST'])
def process():
        quotes = request.form['quotes']
        row_changed = User.query.filter_by(username = current_user.username).update(dict(quotes = quotes))
        #print(current_user.username)
        db.session.commit()
        return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user :
            if bcrypt.check_password_hash(user.password , form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else :
                return render_template('login.html',form = form ,  msg = '*Incorrect Password')
    return render_template('login.html', form = form, msg = '')




@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_pass = bcrypt.generate_password_hash(form.password.data)
        hashed_pass = hashed_pass.decode("utf-8", "ignore")
        new_user = User(username = form.username.data , password = hashed_pass)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form = form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

