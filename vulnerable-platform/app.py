#!/usr/bin/env python3
"""
Vulnerable Web Platform for Learning Exploitation
WARNING: This application contains INTENTIONAL security vulnerabilities.
DO NOT deploy this in a production environment!

This platform demonstrates:
1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Command Injection
4. File Upload vulnerabilities
5. Authentication bypass
6. Path Traversal
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import sqlite3
import os
import subprocess
import hashlib
import pickle
import base64

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_12345'  # Intentionally weak secret

DATABASE = 'vulnerable.db'
UPLOAD_FOLDER = 'uploads'

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with sample data"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample users
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        users = [
            ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@vulnerable.local', 1),
            ('user', hashlib.md5('password'.encode()).hexdigest(), 'user@vulnerable.local', 0),
            ('guest', hashlib.md5('guest123'.encode()).hexdigest(), 'guest@vulnerable.local', 0),
        ]
        cursor.executemany('INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)', users)
        
        posts = [
            ('Welcome to the Platform!', 'This is a vulnerable web platform for learning. Flag 1: FLAG{sql_injection_master}', 'admin'),
            ('Getting Started', 'Start by exploring the login page. Try some common SQL injection payloads!', 'admin'),
            ('User Post', 'This is my first post on the platform.', 'user'),
        ]
        cursor.executemany('INSERT INTO posts (title, content, author) VALUES (?, ?, ?)', posts)
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    VULNERABILITY: SQL Injection
    This login form is vulnerable to SQL injection attacks
    Exploit: username: admin' OR '1'='1' -- 
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE: Direct string concatenation in SQL query
        password_hash = hashlib.md5(password.encode()).hexdigest()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                flash(f'Welcome back, {user["username"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials!', 'danger')
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
        finally:
            conn.close()
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        email = request.form.get('email', '')
        
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute('INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, 0)',
                         (username, password_hash, email))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM posts ORDER BY created_at DESC')
    posts = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', posts=posts)

@app.route('/search')
def search():
    """
    VULNERABILITY: SQL Injection in search
    Exploit: ?q=' UNION SELECT username, password, email, 1 FROM users--
    """
    search_term = request.args.get('q', '')
    results = []
    
    if search_term:
        # VULNERABLE: SQL Injection in search
        query = f"SELECT * FROM posts WHERE title LIKE '%{search_term}%' OR content LIKE '%{search_term}%'"
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            results = cursor.fetchall()
        except Exception as e:
            flash(f'Search error: {str(e)}', 'danger')
        finally:
            conn.close()
    
    return render_template('search.html', results=results, search_term=search_term)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    """
    VULNERABILITY: Reflected XSS
    Exploit: /post/1?comment=<script>alert('XSS')</script>
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM posts WHERE id = ?', (post_id,))
    post = cursor.fetchone()
    
    cursor.execute('SELECT * FROM comments WHERE post_id = ? ORDER BY created_at DESC', (post_id,))
    comments = cursor.fetchall()
    conn.close()
    
    # VULNERABLE: Reflected XSS via comment parameter
    comment_preview = request.args.get('comment', '')
    
    return render_template('post.html', post=post, comments=comments, comment_preview=comment_preview)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    """
    VULNERABILITY: Stored XSS
    Comments are stored without sanitization
    """
    if 'user_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))
    
    content = request.form.get('content', '')
    author = session.get('username', 'Anonymous')
    
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE: Stored XSS - content not sanitized
    cursor.execute('INSERT INTO comments (post_id, author, content) VALUES (?, ?, ?)',
                 (post_id, author, content))
    conn.commit()
    conn.close()
    
    flash('Comment added!', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
    """
    VULNERABILITY: Broken Access Control
    Only checks session variable which can be manipulated
    """
    # VULNERABLE: Only checks client-side session
    if session.get('is_admin') != 1:
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, is_admin FROM users')
    users = cursor.fetchall()
    conn.close()
    
    # Flag for admin access
    flag = "FLAG{admin_access_granted}"
    
    return render_template('admin.html', users=users, flag=flag)

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    """
    VULNERABILITY: Command Injection
    Exploit: 127.0.0.1; cat /etc/passwd
    Exploit: 127.0.0.1 && whoami
    """
    result = ''
    
    if request.method == 'POST':
        host = request.form.get('host', '')
        
        # VULNERABLE: Command Injection via shell=True
        try:
            command = f'ping -c 3 {host}'
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10)
            result = result.decode('utf-8', errors='ignore')
        except subprocess.TimeoutExpired:
            result = 'Command timeout!'
        except Exception as e:
            result = f'Error: {str(e)}'
    
    return render_template('ping.html', result=result)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """
    VULNERABILITY: Unrestricted File Upload
    No validation on file type, size, or content
    """
    if 'user_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected!', 'danger')
            return redirect(request.url)
        
        # VULNERABLE: No file validation
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        
        flash(f'File {file.filename} uploaded successfully! Flag: FLAG{unrestricted_upload_pwned}', 'success')
        return redirect(url_for('upload'))
    
    files = []
    if os.path.exists(UPLOAD_FOLDER):
        files = os.listdir(UPLOAD_FOLDER)
    
    return render_template('upload.html', files=files)

@app.route('/download')
def download():
    """
    VULNERABILITY: Path Traversal
    Exploit: ?file=../../../../etc/passwd
    """
    filename = request.args.get('file', '')
    
    if not filename:
        flash('No file specified!', 'danger')
        return redirect(url_for('upload'))
    
    # VULNERABLE: Path traversal - no validation
    try:
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        with open(filepath, 'r') as f:
            content = f.read()
        return f'<pre>{content}</pre>'
    except Exception as e:
        return f'Error reading file: {str(e)}'

@app.route('/serialize', methods=['GET', 'POST'])
def serialize():
    """
    VULNERABILITY: Insecure Deserialization
    Exploit with pickle payloads
    """
    result = ''
    
    if request.method == 'POST':
        data = request.form.get('data', '')
        
        try:
            # VULNERABLE: Insecure deserialization
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            result = f'Deserialized object: {obj}'
        except Exception as e:
            result = f'Error: {str(e)}'
    
    return render_template('serialize.html', result=result)

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_db()
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # Debug mode enabled for easier exploitation
    app.run(debug=True, host='0.0.0.0', port=5000)
