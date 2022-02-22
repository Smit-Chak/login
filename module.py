
from email import message
from enum import unique
from wsgiref import validate
from wsgiref.validate import validator
from flask import Flask, render_template, url_for, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey
from wtforms import StringField , PasswordField, SubmitField , BooleanField
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
    quotes = db.relationship('Quote', backref = 'auth')

class Quote(db.Model):
    __tablename__ = 'quote'
    id = db.Column(db.Integer, primary_key = True)
    quotes = db.Column(db.String(100))
    complete = db.Column(db.Boolean , default = False)
    user_id = db.Column(db.Integer, db.ForeignKey('auth.id'))

#class isComplete(FlaskForm):
#    check = BooleanField()

class RegisterForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(min = 5, max = 20)], render_kw = {"placeholder" : "Username"})
    password = PasswordField(validators = [InputRequired(), Length(min = 5, max = 80), Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&+=]).*$',
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
    return render_template('home.html')

@app.route('/quote', methods=['GET', 'POST'])
def quote():
    user = session['user']
    u_quote = Quote.query.filter_by(auth = current_user)
    return render_template('quote.html', quote = u_quote, user = user)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = session['user']
    return render_template('dashboard.html', user = user)

@app.route('/process', methods=['GET', 'POST'])
def process():
        quotes = request.form['quotes']
        user_quotes = Quote(quotes = quotes , auth = current_user)
        db.session.add(user_quotes)
        db.session.commit()
        user = session['user']
        return render_template('dashboard.html', user = user)

@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user :
            if bcrypt.check_password_hash(user.password , form.password.data):
                login_user(user)
                session['user'] = user.username
                #print(user.username)
                return redirect(url_for('dashboard'))
            else :
                return render_template('login.html',form = form ,  msg = '*Incorrect Password')
        else :
                return render_template('login.html', form = form, msg = "*Username doesn't exist")
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

@app.route('/update', methods=['POST'])
def update():
    ck_id = request.form
    for i in ck_id:
        if(ck_id[i] == 'on'):
            Quote.query.filter_by(id = i,auth = current_user).update(dict(complete = True))
            db.session.commit()
    return redirect('/quote')