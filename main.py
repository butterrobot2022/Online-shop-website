from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
import stripe


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

stripe.api_key = 'sk_test_51M5ZpQIaSaqxrAVPWfIfVv2ReotvSBosfRCcJ7r0QpCcAFkcaNlr3A6z8vJJH0Szgbi0e575YNtkzrIzTPJStqnb00bFNmuy2g '

domain = 'http://127.0.0.1:5000'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign me up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let me in!")

# with app.app_context():
#     db.create_all()


@app.route('/')
def homepage():
    return render_template('home.html')


@app.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        new_user = User(
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('homepage'))
    return render_template('register.html')


@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user by email entered.
        user = User.query.filter_by(email=email).first()

        # Check stored password hash against entered password hashed.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
            # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
            # Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for('homepage'))
    return render_template("login.html")


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/checkout-session', methods=['GET', 'POST'])
def checkout():
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    'price': 'price_1M5aE7IaSaqxrAVP4YHmaBh7',
                    'quantity': 1
                }
            ],
            mode='subscription',
            success_url=domain + '/success.html',
            cancel_url=domain + '/cancel.html'
        )
    except Exception as e:
        return str(e)

    return redirect(url_for('checkout'), code=303)


if __name__ == '__main__':
    app.run(debug=True)

