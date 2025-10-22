#!/usr/bin/env python3
"""
Intentionally Vulnerable Web Application for Testing WebFuzzingBrain

This application contains REAL SQL injection vulnerabilities for testing purposes.
DO NOT deploy this in production or on public networks.

Vulnerabilities included:
1. Error-based SQL injection
2. Boolean-based SQL injection
3. Union-based SQL injection
4. Time-based SQL injection
"""

from flask import Flask, request, jsonify
import sqlite3
import time
import os

app = Flask(__name__)

# Create in-memory database with sample data
def init_db():
    """Initialize the vulnerable database with sample data"""
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            api_key TEXT NOT NULL
        )
    ''')

    # Insert sample data including "secrets"
    cursor.execute('''
        INSERT INTO users (username, password, email, role, api_key) VALUES
        ('admin', 'SuperSecret123!', 'admin@company.com', 'administrator', 'sk-admin-key-abc123'),
        ('john_doe', 'password123', 'john@example.com', 'user', 'sk-user-key-def456'),
        ('jane_smith', 'qwerty', 'jane@example.com', 'user', 'sk-user-key-ghi789'),
        ('bob_johnson', 'letmein', 'bob@example.com', 'moderator', 'sk-mod-key-jkl012')
    ''')

    # Create products table
    cursor.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            category TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        INSERT INTO products (name, price, category) VALUES
        ('Laptop', 999.99, 'Electronics'),
        ('Mouse', 29.99, 'Electronics'),
        ('Keyboard', 79.99, 'Electronics'),
        ('Desk', 299.99, 'Furniture')
    ''')

    conn.commit()
    return conn

# Global database connection
db_conn = init_db()

@app.route('/')
def index():
    """Home page with links to vulnerable endpoints"""
    return """
    <html>
    <head><title>Vulnerable Test Application</title></head>
    <body>
        <h1>Vulnerable Web Application - Testing Only</h1>
        <p>This application contains intentional SQL injection vulnerabilities for testing.</p>

        <h2>Available Endpoints:</h2>
        <ul>
            <li><a href="/api/user?id=1">/api/user?id=1</a> - Error-based SQLi</li>
            <li><a href="/api/login?username=admin&password=test">/api/login?username=admin&password=test</a> - Boolean-based SQLi</li>
            <li><a href="/api/product?id=1">/api/product?id=1</a> - Union-based SQLi</li>
            <li><a href="/api/search?q=laptop">/api/search?q=laptop</a> - Time-based SQLi</li>
        </ul>

        <h2>Example Attacks:</h2>
        <ul>
            <li>Error-based: /api/user?id=1'</li>
            <li>Boolean-based: /api/login?username=admin' OR '1'='1&password=test</li>
            <li>Union-based: /api/product?id=1 UNION SELECT username,password,email,role FROM users--</li>
            <li>Time-based: /api/search?q=laptop' AND (SELECT CASE WHEN (1=1) THEN (SELECT load_extension(1)) ELSE 0 END)--</li>
        </ul>
    </body>
    </html>
    """

@app.route('/api/user')
def get_user():
    """
    VULNERABLE: Error-based SQL injection

    This endpoint directly concatenates user input into SQL query,
    causing database errors that leak information.
    """
    user_id = request.args.get('id', '1')

    # VULNERABLE: Direct string concatenation
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"

    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            return jsonify({
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3]
            })
        else:
            return jsonify({'error': 'User not found'}), 404

    except sqlite3.Error as e:
        # VULNERABLE: Exposing database errors
        return jsonify({
            'error': 'Database error',
            'details': str(e),
            'query': query  # Exposing the query for demonstration
        }), 500

@app.route('/api/login', methods=['GET', 'POST'])
def login():
    """
    VULNERABLE: Boolean-based SQL injection

    This endpoint allows authentication bypass through SQL injection
    that changes query logic.
    """
    username = request.args.get('username', '')
    password = request.args.get('password', '')

    # VULNERABLE: String concatenation in WHERE clause
    query = f"SELECT id, username, role, api_key FROM users WHERE username = '{username}' AND password = '{password}'"

    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': result[0],
                    'username': result[1],
                    'role': result[2],
                    'api_key': result[3]  # Sensitive data
                }
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid credentials'
            }), 401

    except sqlite3.Error as e:
        return jsonify({
            'error': 'Database error',
            'details': str(e)
        }), 500

@app.route('/api/product')
def get_product():
    """
    VULNERABLE: Union-based SQL injection

    This endpoint allows UNION attacks to extract data from other tables.
    """
    product_id = request.args.get('id', '1')

    # VULNERABLE: Direct concatenation allowing UNION attacks
    query = f"SELECT id, name, price, category FROM products WHERE id = {product_id}"

    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()

        products = []
        for row in results:
            products.append({
                'id': row[0],
                'name': row[1],
                'price': row[2],
                'category': row[3]
            })

        return jsonify({'products': products})

    except sqlite3.Error as e:
        return jsonify({
            'error': 'Database error',
            'details': str(e),
            'query': query
        }), 500

@app.route('/api/search')
def search_products():
    """
    VULNERABLE: Time-based SQL injection

    This endpoint allows blind SQL injection through time delays.
    """
    search_term = request.args.get('q', '')

    # VULNERABLE: String concatenation in LIKE clause
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{search_term}%' OR category LIKE '%{search_term}%'"

    try:
        start_time = time.time()
        cursor = db_conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        elapsed = time.time() - start_time

        products = []
        for row in results:
            products.append({
                'id': row[0],
                'name': row[1],
                'price': row[2]
            })

        return jsonify({
            'results': products,
            'count': len(products),
            'query_time': f"{elapsed:.4f}s"
        })

    except sqlite3.Error as e:
        return jsonify({
            'error': 'Database error',
            'details': str(e)
        }), 500

@app.route('/api/stats')
def get_stats():
    """Safe endpoint for statistics"""
    cursor = db_conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM products")
    product_count = cursor.fetchone()[0]

    return jsonify({
        'users': user_count,
        'products': product_count,
        'endpoints': [
            '/api/user',
            '/api/login',
            '/api/product',
            '/api/search'
        ]
    })

if __name__ == '__main__':
    print("=" * 70)
    print("VULNERABLE WEB APPLICATION FOR TESTING ONLY")
    print("=" * 70)
    print("This application contains INTENTIONAL SQL injection vulnerabilities.")
    print("DO NOT use in production or expose to public networks.")
    print()
    print("Server starting on http://localhost:5001")
    print("=" * 70)
    print()

    app.run(host='0.0.0.0', port=5001, debug=False)
