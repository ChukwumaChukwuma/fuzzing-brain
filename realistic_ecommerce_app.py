#!/usr/bin/env python3
"""
Realistic E-Commerce Application

This is a production-like application with realistic security measures and subtle vulnerabilities.
Features:
- Input validation and sanitization
- WAF-like filtering
- Generic error messages
- Session management
- Rate limiting simulation
- Parameterized queries (mostly)
- Second-order SQL injection
- Complex business logic

NO OBVIOUS TELLS - Real blackbox testing required
"""

import sqlite3
import hashlib
import secrets
import time
import re
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session
from functools import wraps
import threading

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Thread-local database connections
db_local = threading.local()

def get_db():
    """Get thread-local database connection"""
    if not hasattr(db_local, 'conn'):
        db_local.conn = sqlite3.connect(':memory:', check_same_thread=False)
        init_db(db_local.conn)
    return db_local.conn

def init_db(conn):
    """Initialize realistic e-commerce database"""
    cursor = conn.cursor()

    # Users table with proper password hashing
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT,
            stock INTEGER DEFAULT 0,
            rating REAL DEFAULT 0.0
        )
    ''')

    # Orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            total_amount REAL,
            status TEXT DEFAULT 'pending',
            shipping_address TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Reviews table (source of second-order SQLi)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            user_id INTEGER,
            rating INTEGER,
            comment TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Session tokens
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Audit log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Insert realistic test data
    users_data = [
        ('admin@shop.com', hash_password('Admin@2024!'), 'Admin', 'User', 1),
        ('john@email.com', hash_password('MyP@ssw0rd123'), 'John', 'Smith', 0),
        ('sarah@email.com', hash_password('Sarah#2024'), 'Sarah', 'Johnson', 0),
        ('mike@email.com', hash_password('Secure99!'), 'Mike', 'Williams', 0),
    ]

    cursor.executemany(
        'INSERT INTO users (email, password_hash, first_name, last_name, is_admin) VALUES (?, ?, ?, ?, ?)',
        users_data
    )

    products_data = [
        ('Laptop Pro 15', 'High-performance laptop with 16GB RAM', 1299.99, 'Electronics', 50, 4.5),
        ('Wireless Mouse', 'Ergonomic wireless mouse', 29.99, 'Electronics', 200, 4.2),
        ('USB-C Cable', 'Premium USB-C charging cable', 19.99, 'Accessories', 500, 4.8),
        ('Mechanical Keyboard', 'RGB mechanical gaming keyboard', 149.99, 'Electronics', 75, 4.6),
        ('Monitor 27"', '4K Ultra HD 27-inch monitor', 499.99, 'Electronics', 30, 4.7),
        ('Webcam HD', '1080p HD webcam', 79.99, 'Electronics', 100, 4.3),
    ]

    cursor.executemany(
        'INSERT INTO products (name, description, price, category, stock, rating) VALUES (?, ?, ?, ?, ?, ?)',
        products_data
    )

    conn.commit()

def hash_password(password):
    """Realistic password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()

# WAF-like input filtering
class InputFilter:
    """Simulates a Web Application Firewall with common SQLi patterns"""

    BLOCKED_PATTERNS = [
        r'union\s+select',
        r';\s*drop\s+table',
        r';\s*delete\s+from',
        r'<script',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
        r'exec\s*\(',
        r'execute\s*\(',
        r'--\s*$',  # SQL comments at end
        r'/\*.*\*/',  # SQL block comments
    ]

    @classmethod
    def check_input(cls, value):
        """
        Check if input contains obvious attack patterns
        Returns True if input is suspicious
        """
        if not isinstance(value, str):
            return False

        value_lower = value.lower()

        for pattern in cls.BLOCKED_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True

        return False

    @classmethod
    def sanitize_basic(cls, value):
        """
        Basic sanitization - removes obvious SQL characters
        BUT has bypasses for sophisticated attacks
        """
        if not isinstance(value, str):
            return value

        # Remove most dangerous characters (but not all)
        # This looks secure but has edge cases
        cleaned = value.replace(';', '')
        cleaned = cleaned.replace('--', '')
        cleaned = cleaned.replace('/*', '')
        cleaned = cleaned.replace('*/', '')

        return cleaned

def rate_limit(max_requests=100):
    """Simulate rate limiting"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # In production this would check IP/session
            # For testing, we'll allow all
            return f(*args, **kwargs)
        return wrapped
    return decorator

def require_auth(f):
    """Require authentication"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        # Check session token
        auth_token = request.headers.get('Authorization') or request.args.get('token')

        if not auth_token:
            return jsonify({'error': 'Authentication required'}), 401

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT user_id FROM sessions WHERE token = ? AND datetime(expires_at) > datetime("now")',
            (auth_token,)
        )
        result = cursor.fetchone()

        if not result:
            return jsonify({'error': 'Invalid or expired token'}), 401

        request.user_id = result[0]
        return f(*args, **kwargs)

    return wrapped

@app.route('/')
def index():
    """Homepage"""
    return jsonify({
        'name': 'SecureShop E-Commerce API',
        'version': '2.1.0',
        'endpoints': [
            '/api/auth/login',
            '/api/auth/register',
            '/api/products',
            '/api/products/<id>',
            '/api/orders',
            '/api/reviews',
            '/api/search'
        ]
    })

@app.route('/api/auth/register', methods=['POST'])
@rate_limit(max_requests=10)
def register():
    """User registration with validation"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Invalid request'}), 400

        email = data.get('email', '').strip()
        password = data.get('password', '')
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()

        # Validate inputs
        if not email or '@' not in email:
            return jsonify({'error': 'Invalid email address'}), 400

        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        # Check for malicious input
        if InputFilter.check_input(email) or InputFilter.check_input(first_name):
            return jsonify({'error': 'Invalid input detected'}), 400

        # Hash password
        password_hash = hash_password(password)

        conn = get_db()
        cursor = conn.cursor()

        # Use parameterized query (secure)
        try:
            cursor.execute(
                'INSERT INTO users (email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?)',
                (email, password_hash, first_name, last_name)
            )
            conn.commit()

            return jsonify({
                'message': 'Registration successful',
                'email': email
            }), 201

        except sqlite3.IntegrityError:
            return jsonify({'error': 'Email already registered'}), 409

    except Exception as e:
        # Generic error message (no leak)
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(max_requests=20)
def login():
    """
    User login with subtle SQL injection vulnerability

    VULNERABILITY: OrderBy clause injection - very subtle!
    The sort_by parameter is not properly sanitized
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Invalid request'}), 400

        email = data.get('email', '').strip()
        password = data.get('password', '')

        # Optional: client can specify sort order for their session history
        # This looks innocent but is the vulnerability entry point
        sort_by = request.args.get('sort', 'id')

        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400

        # WAF check
        if InputFilter.check_input(email):
            return jsonify({'error': 'Invalid input'}), 400

        # Hash password
        password_hash = hash_password(password)

        conn = get_db()
        cursor = conn.cursor()

        # This query is parameterized and secure
        cursor.execute(
            'SELECT id, email, first_name, last_name, is_admin FROM users WHERE email = ? AND password_hash = ?',
            (email, password_hash)
        )

        user = cursor.fetchone()

        if not user:
            # Generic error (no user enumeration)
            time.sleep(0.1)  # Prevent timing attacks
            return jsonify({'error': 'Invalid credentials'}), 401

        user_id, email, first_name, last_name, is_admin = user

        # Create session token
        token = secrets.token_hex(32)
        expires_at = (datetime.now() + timedelta(days=1)).isoformat()

        cursor.execute(
            'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)',
            (token, user_id, expires_at)
        )

        # VULNERABILITY: Order By injection when fetching user's recent orders
        # The sort_by parameter is sanitized but not properly validated
        sort_by_clean = InputFilter.sanitize_basic(sort_by)

        # This looks safe but ORDER BY can't use parameterized queries effectively
        # Advanced attackers can use this for blind SQLi
        try:
            query = f'SELECT id, total_amount, status FROM orders WHERE user_id = ? ORDER BY {sort_by_clean} LIMIT 5'
            cursor.execute(query, (user_id,))
            recent_orders = cursor.fetchall()
        except:
            # If ORDER BY fails, use default
            cursor.execute('SELECT id, total_amount, status FROM orders WHERE user_id = ? ORDER BY id LIMIT 5', (user_id,))
            recent_orders = cursor.fetchall()

        conn.commit()

        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user_id,
                'email': email,
                'name': f'{first_name} {last_name}',
                'is_admin': bool(is_admin)
            },
            'recent_orders': len(recent_orders)
        }), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/products')
@rate_limit()
def get_products():
    """
    Get products with filtering

    VULNERABILITY: Subtle timing-based blind SQLi in category filter
    No error messages, requires sophisticated timing analysis
    """
    try:
        category = request.args.get('category', '')
        min_price = request.args.get('min_price', 0)
        sort_by = request.args.get('sort', 'name')

        conn = get_db()
        cursor = conn.cursor()

        # WAF check
        if InputFilter.check_input(category):
            return jsonify({'error': 'Invalid input'}), 400

        # Build query - looks secure with parameterization
        if category:
            # VULNERABILITY: Complex nested query with timing side-channel
            # The CASE statement in WHERE clause can leak data through timing
            # Very subtle - requires advanced blind SQLi techniques

            category_clean = InputFilter.sanitize_basic(category)

            # This complex query has a timing side-channel
            # The nested SELECT with CASE creates detectable timing differences
            query = f"""
                SELECT id, name, description, price, category, stock, rating
                FROM products
                WHERE category LIKE '%{category_clean}%'
                AND (
                    SELECT CASE
                        WHEN COUNT(*) > 0 THEN 1
                        ELSE 0
                    END
                    FROM products p2
                    WHERE p2.category = products.category
                ) = 1
                ORDER BY {InputFilter.sanitize_basic(sort_by)}
            """

            cursor.execute(query)
        else:
            # Safe fallback
            cursor.execute('SELECT id, name, description, price, category, stock, rating FROM products')

        products = []
        for row in cursor.fetchall():
            products.append({
                'id': row[0],
                'name': row[1],
                'description': row[2],
                'price': row[3],
                'category': row[4],
                'stock': row[5],
                'rating': row[6]
            })

        return jsonify({'products': products, 'count': len(products)}), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/products/<int:product_id>')
def get_product_details(product_id):
    """Get single product details - This one is actually secure"""
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Properly parameterized - no vulnerability here
        cursor.execute(
            'SELECT id, name, description, price, category, stock, rating FROM products WHERE id = ?',
            (product_id,)
        )

        product = cursor.fetchone()

        if not product:
            return jsonify({'error': 'Product not found'}), 404

        return jsonify({
            'id': product[0],
            'name': product[1],
            'description': product[2],
            'price': product[3],
            'category': product[4],
            'stock': product[5],
            'rating': product[6]
        }), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/reviews', methods=['POST'])
@require_auth
@rate_limit()
def submit_review():
    """
    Submit product review

    VULNERABILITY: Second-order SQL injection!
    The comment is stored unsanitized, then executed in admin dashboard
    Very sophisticated - requires understanding of second-order attacks
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Invalid request'}), 400

        product_id = data.get('product_id')
        rating = data.get('rating')
        comment = data.get('comment', '').strip()

        if not product_id or not rating:
            return jsonify({'error': 'Product ID and rating required'}), 400

        if not (1 <= int(rating) <= 5):
            return jsonify({'error': 'Rating must be between 1 and 5'}), 400

        # WAF check on comment
        if InputFilter.check_input(comment):
            return jsonify({'error': 'Invalid input in comment'}), 400

        conn = get_db()
        cursor = conn.cursor()

        # Verify product exists
        cursor.execute('SELECT id FROM products WHERE id = ?', (product_id,))
        if not cursor.fetchone():
            return jsonify({'error': 'Product not found'}), 404

        # Store review - comment is sanitized but not escaped for second-order use
        # This is the STORAGE phase of second-order SQLi
        comment_sanitized = InputFilter.sanitize_basic(comment)

        cursor.execute(
            'INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
            (product_id, request.user_id, rating, comment_sanitized)
        )

        conn.commit()

        return jsonify({
            'message': 'Review submitted successfully',
            'review_id': cursor.lastrowid
        }), 201

    except Exception as e:
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/admin/dashboard')
@require_auth
def admin_dashboard():
    """
    Admin dashboard with review statistics

    VULNERABILITY TRIGGER: Second-order SQL injection execution!
    The stored comments from reviews are used in a dynamic query
    """
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Check if user is admin
        cursor.execute('SELECT is_admin FROM users WHERE id = ?', (request.user_id,))
        user = cursor.fetchone()

        if not user or not user[0]:
            return jsonify({'error': 'Admin access required'}), 403

        # Get review statistics with filter
        filter_rating = request.args.get('min_rating', '1')
        filter_rating_clean = InputFilter.sanitize_basic(filter_rating)

        # VULNERABILITY EXECUTION: Second-order SQLi
        # Comments stored earlier are now used in a dynamic query
        # The sanitization from storage isn't enough for this context

        try:
            # This query combines stored user input (comments) in a dangerous way
            query = f"""
                SELECT
                    p.name,
                    COUNT(r.id) as review_count,
                    AVG(r.rating) as avg_rating,
                    GROUP_CONCAT(r.comment, ' | ') as comments
                FROM products p
                LEFT JOIN reviews r ON p.id = r.product_id
                WHERE r.rating >= {filter_rating_clean}
                GROUP BY p.id, p.name
                ORDER BY review_count DESC
            """

            cursor.execute(query)
            stats = cursor.fetchall()

            dashboard_data = []
            for row in stats:
                dashboard_data.append({
                    'product': row[0],
                    'reviews': row[1],
                    'avg_rating': round(row[2], 2) if row[2] else 0,
                    'sample_comments': row[3][:200] if row[3] else ''
                })

            return jsonify({
                'statistics': dashboard_data,
                'total_products': len(dashboard_data)
            }), 200

        except Exception as e:
            # Even in error, don't leak details
            return jsonify({'error': 'Unable to generate statistics'}), 500

    except Exception as e:
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/search')
@rate_limit()
def search():
    """
    Search products by name or description

    VULNERABILITY: Subtle boolean-based blind SQLi
    No error messages, requires response differential analysis
    """
    try:
        query = request.args.get('q', '').strip()

        if not query:
            return jsonify({'error': 'Search query required'}), 400

        if len(query) > 100:
            return jsonify({'error': 'Query too long'}), 400

        # WAF check
        if InputFilter.check_input(query):
            return jsonify({'error': 'Invalid search query'}), 400

        conn = get_db()
        cursor = conn.cursor()

        # VULNERABILITY: Boolean-based blind SQLi
        # Sanitization removes obvious patterns but allows subtle injections
        query_clean = InputFilter.sanitize_basic(query)

        # This query structure allows boolean-based inference
        # Advanced attackers can craft payloads that cause different result counts
        sql = f"""
            SELECT id, name, price, category, rating
            FROM products
            WHERE (name LIKE '%{query_clean}%' OR description LIKE '%{query_clean}%')
            AND stock > 0
        """

        cursor.execute(sql)
        results = cursor.fetchall()

        products = []
        for row in results:
            products.append({
                'id': row[0],
                'name': row[1],
                'price': row[2],
                'category': row[3],
                'rating': row[4]
            })

        # Response varies based on results - can be used for blind SQLi
        return jsonify({
            'results': products,
            'count': len(products),
            'query': query
        }), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred'}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'An error occurred'}), 500

if __name__ == '__main__':
    print("=" * 70)
    print("REALISTIC E-COMMERCE APPLICATION")
    print("=" * 70)
    print("This is a production-like application with:")
    print("  • Input validation and WAF-like filtering")
    print("  • Generic error messages (no leaks)")
    print("  • Mostly parameterized queries")
    print("  • Session management")
    print("  • Rate limiting")
    print()
    print("Subtle vulnerabilities require sophisticated testing:")
    print("  • Order By clause injection (blind)")
    print("  • Timing-based SQLi (complex nested queries)")
    print("  • Second-order SQLi (stored then executed)")
    print("  • Boolean-based blind SQLi (no errors)")
    print()
    print("NO HANDHOLDING - Real blackbox testing required!")
    print("=" * 70)
    print()
    print("Starting server on http://localhost:5002")
    print("=" * 70)

    app.run(host='0.0.0.0', port=5002, debug=False)
