from flask import Flask, request, redirect, url_for, render_template, session, flash
import psycopg2
from psycopg2 import sql
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key' 

DATABASE = {
    'host': 'localhost',
    'database': 'postgres',
    'user': 'postgres',
    'password': '2006'
}

def get_db_connection():
    conn = psycopg2.connect(
        host=DATABASE['host'],
        database=DATABASE['database'],
        user=DATABASE['user'],
        password=DATABASE['password']
    )
    return conn

@app.route('/', methods=['GET'])
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    phone = request.form['phone']
    password = request.form['password']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(sql.SQL("SELECT id, password FROM users WHERE phone = %s"), [phone])
        user = cursor.fetchone()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('profile'))
        else:
            flash("Неверный номер телефона или пароль", "error")
            return redirect(url_for('index'))
    except Exception as e:
        print(f"Error: {e}")
        flash("Произошла ошибка, попробуйте снова", "error")
        return redirect(url_for('index'))
    finally:
        cursor.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        phone = request.form['phone']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(sql.SQL("INSERT INTO users (phone, password) VALUES (%s, %s)"), [phone, hashed_password.decode('utf-8')])
            conn.commit()
            return redirect(url_for('index'))
        except Exception as e:
            print(f"Error: {e}")
            return "An error occurred", 500
        finally:
            cursor.close()
            conn.close()
    
    return render_template('register.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(sql.SQL("SELECT phone FROM users WHERE id = %s"), [user_id])
    user = cursor.fetchone()
    
    if user:
        return render_template('profile.html', phone=user[0])
    else:
        return "User not found", 404

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/edit_profile')
def edit_profile():
    return render_template('edit_profile.html')


if __name__ == '__main__':
    app.run(debug=True)
