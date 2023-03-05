from flask import Flask, Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db


from flask_login import login_user, login_required, logout_user, current_user

import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = "password"

DB_HOST = "localhost"
DB_NAME = "lib_sys_db"
DB_USER = "postgres"
DB_PASS = "password"

conn = psycopg2.connect (
                            dbname=DB_NAME, 
                            user=DB_USER,
                            password=DB_PASS, 
                            host=DB_HOST
                        )

auth = Blueprint('auth', __name__)


@auth.route('/abk', methods = ['GET','POST'])
def abk():
    if request.method == 'POST':
        book_name = request.form.get('book_name')
        book_subject = request.form.get('book_subject')
        book_year_level = request.form.get('book_year_level')
        book_section = request.form.get('book_section')
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("INSERT INTO books(book_name, book_subject, book_year_level, book_section) VALUES (%s, %s, %s, %s)",(book_name, book_subject, book_year_level, book_section))
        conn.commit()

        if len("book_name") < 2:
            flash('Enter appropriate Book Name', category='error')
        elif len("book_subject") <2:
           flash('Enter appropriate Book Subject', category='error')
        elif len("book_year_level") == 0:
           flash('Enter appropriate Year level', category='error')
        elif len("book_section") < 2:
           flash('Enter Appropriate Section', category='error')
        else:
            flash('Book Added from List', category='success')

    
    return render_template ("addbook.html", user=current_user)



@auth.route('/login', methods=['GET', 'POST'])
def login():
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


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/emp-sign', methods=['GET', 'POST'])
def empsign():
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
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("empsign-up.html", user=current_user)
