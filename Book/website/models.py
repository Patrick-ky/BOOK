
from flask import Flask, Blueprint, render_template,request,flash
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

@app.route('/')
def home():
    return render_template('base.html')

@auth.route('/add-book',methods=['GET','POST'])
def add_book():
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

    return render_template("add_book.html")