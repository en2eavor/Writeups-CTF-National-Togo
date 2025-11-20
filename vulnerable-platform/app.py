#!/usr/bin/env python3
"""
Simplified Vulnerable Web Platform
XSS to RCE Challenge with Docker Escape

WARNING: This application contains INTENTIONAL security vulnerabilities.
DO NOT deploy this in a production environment!
"""

from flask import Flask, render_template, request, redirect, url_for, flash
import subprocess
import os

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_12345'

# Store messages in memory (for XSS demonstration)
messages = []

@app.route('/')
def index():
    """Home page with message board"""
    return render_template('index.html', messages=messages)

@app.route('/post', methods=['POST'])
def post_message():
    """
    VULNERABILITY: Stored XSS
    User input is not sanitized and directly rendered in HTML
    """
    username = request.form.get('username', 'Anonymous')
    message = request.form.get('message', '')
    
    if message:
        # VULNERABLE: No sanitization - Stored XSS
        messages.append({
            'username': username,
            'message': message
        })
        flash('Message posted!', 'success')
    else:
        flash('Message cannot be empty!', 'danger')
    
    return redirect(url_for('index'))

@app.route('/execute', methods=['POST'])
def execute():
    """
    VULNERABILITY: RCE endpoint (reachable via XSS)
    This endpoint allows command execution
    Meant to be triggered via XSS payload
    """
    cmd = request.form.get('cmd', '')
    
    if not cmd:
        return 'No command specified', 400
    
    try:
        # VULNERABLE: Direct command execution
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return result.decode('utf-8', errors='ignore')
    except subprocess.TimeoutExpired:
        return 'Command timeout', 500
    except Exception as e:
        return f'Error: {str(e)}', 500

@app.route('/clear', methods=['POST'])
def clear_messages():
    """Clear all messages"""
    global messages
    messages = []
    flash('All messages cleared!', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    print("=" * 60)
    print("Vulnerable Platform - XSS to RCE Challenge")
    print("=" * 60)
    print("\n[!] WARNING: This app contains intentional vulnerabilities!")
    print("[+] Challenge: Exploit XSS to achieve RCE")
    print("[+] Then: Escape the Docker container")
    print("[+] Goal: Become root on the host and capture the flag\n")
    print("=" * 60)
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
