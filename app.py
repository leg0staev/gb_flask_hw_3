from flask import Flask, abort, render_template, request, url_for, session, redirect
from models import db, User
from forms import RegisterForm, LoginForm
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = secrets.token_hex()
csrf = CSRFProtect(app)
db.init_app(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.cli.command('init-db')
def init_db():
    db.create_all()
    print('OK')


@app.route('/registration/', methods=['GET', 'POST'])
def registration():
    form = RegisterForm()
    if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        password = generate_password_hash(form.password.data)
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        return render_template('reg_success.html', username=username)
    return render_template('registration.html', form=form)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        password_hash = user.password
        if check_password_hash(password_hash, password):
            session['email'] = form.email.data
            session['username'] = user.username
            return redirect(url_for('hello_func'))
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/hello/')
def hello_func():
    if session.get('email', False):
        context = {
            'title': 'Привет',
            'username': session['username'],
        }
        return render_template('hello.html', **context)
    abort(403)


@app.route('/logout/')
def logout_func():
    session.pop('email', None)
    return redirect(url_for('index'))


@app.errorhandler(403)
def err_403(e):
    print(e)
    return render_template('err_403.html', title='ошибка входа')


if __name__ == '__main__':
    app.run()
