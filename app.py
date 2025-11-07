from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
from datetime import datetime, date, timedelta
import mysql.connector
from mysql.connector import Error
from flask_mail import Mail, Message
import plotly.graph_objs as go
import plotly.offline as pyo
import pandas as pd
import importlib
try:
    sarimax_mod = importlib.import_module('statsmodels.tsa.statespace.sarimax')
    SARIMAX = getattr(sarimax_mod, 'SARIMAX')
except Exception:
    class SARIMAX:
        def __init__(self, *args, **kwargs):
            raise ImportError("statsmodels.tsa.statespace.sarimax.SARIMAX is not available; install the 'statsmodels' package to enable forecasting.")
import os, time, requests, io, csv
from models.forecasting import SalesForecaster
from apscheduler.schedulers.background import BackgroundScheduler
import logging
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'static/proofs/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'), 
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'casadoragri_db')
        )
        print("Database connection successful")
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")

# Update app configuration
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'maytrixiem@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'sisp whwg gtoj txjq')

# Initialize Flask-Mail
mail = Mail(app)

API_KEY = 'AIzaSyCKoLuO0tW46lMavIXdnV3sBnvpvpAeyJg'
DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'casadoragri_db'
}

def geocode(address):
    url = 'https://maps.googleapis.com/maps/api/geocode/json'
    r = requests.get(url, params={'address': address, 'key': API_KEY})
    j = r.json()
    if j.get('status') == 'OK' and j.get('results'):
        loc = j['results'][0]['geometry']['location']
        return float(loc['lat']), float(loc['lng'])
    return None, None

def get_full_name(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT full_name FROM users WHERE user_id = %s", (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result['full_name'] if result else None

@app.route('/')
def home():
    products = ['Corn', 'Hog', 'Poultry', 'Cattle', 'Cat', 'Dog']
    current_year = datetime.now().year
    return render_template('home.html', products=products, current_year=current_year)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        agree = request.form.get('agree')

        if not all([full_name, username, email, password, role, agree]):
            flash('All fields including role and agreement must be filled.', 'error')
            return redirect(url_for('register'))

        try:
            # Hash the password before storing
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            
            conn = get_db_connection()
            cursor = conn.cursor()
            insert_query = """
                INSERT INTO users (full_name, email, password, role, status)
                VALUES (%s, %s, %s, %s, 'pending')
            """
            cursor.execute(insert_query, (full_name, email, hashed_password, role))
            conn.commit()
            conn.close()
            flash('Registration successful! Your account is pending admin approval.', 'success')
        except mysql.connector.Error as err:
            flash(f'Database error: {err}', 'error')

        return redirect(url_for('register'))

    return render_template('register.html', current_year=datetime.now().year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    current_year = datetime.now().year

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return redirect(url_for('login'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            stored_password = user[3]
            role = user[4]
            status = user[5]

            if status != 'approved':
                conn.close()
                flash('Your account is not yet approved.', 'error')
                return redirect(url_for('login'))

            # ✅ FIX: Check if password is hashed or plain text
            password_valid = False
            
            # Check if it's a hashed password (starts with pbkdf2:, scrypt:, or bcrypt:)
            if stored_password.startswith(('pbkdf2:', 'scrypt:', 'bcrypt:')):
                # It's hashed - use check_password_hash
                password_valid = check_password_hash(stored_password, password)
            else:
                # It's plain text (old password) - compare directly and then update it
                if stored_password == password:
                    password_valid = True
                    # ✅ IMPORTANT: Hash the password immediately
                    hashed = generate_password_hash(password, method='pbkdf2:sha256')
                    cursor.execute("UPDATE users SET password = %s WHERE user_id = %s", 
                                 (hashed, user[0]))
                    conn.commit()
                    print(f"⚠️ Migrated plain password for user {email}")

            if password_valid:
                session['user_id'] = user[0]
                session['role'] = role
                session['email'] = user[2]

                # Log login
                full_name = user[1]
                cursor.execute(
                    "INSERT INTO activity_log (full_name, action) VALUES (%s, %s)",
                    (full_name, f"{role} logged in")
                )
                conn.commit()
                conn.close()

                flash('Login successful!', 'success')

                if role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif role == 'warehouse_staff':
                    return redirect(url_for('warehouse_dashboard'))
                elif role == 'secretary':
                    return redirect(url_for('secretary_dashboard'))
                elif role == 'delivery_driver':
                    return redirect(url_for('delivery_dashboard'))
                else:
                    flash('Unknown role. Please contact admin.', 'error')
                    return redirect(url_for('login'))
            else:
                conn.close()
                flash('Incorrect password.', 'error')
        else:
            flash('Email not found.', 'error')

    return render_template('login.html', current_year=current_year)

@app.route('/admin/update-account', methods=['POST'])
def update_account():
    if 'user_id' not in session:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    new_email = request.form.get('email')
    new_password = request.form.get('password')

    # Hash the new password
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET email=%s, password=%s WHERE user_id=%s",
                   (new_email, hashed_password, session['user_id']))
    conn.commit()
    session['email'] = new_email

    admin_full_name = get_full_name(session.get('user_id'))
    cursor.execute(
        "INSERT INTO activity_log (full_name, action) VALUES (%s, %s)",
        (admin_full_name, "Updated admin account")
    )
    conn.commit()
    conn.close()

    flash("Account updated successfully!", "success")
    return redirect(url_for('admin_dashboard'))
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get monthly sales data
        cursor.execute("""
            SELECT 
                DATE_FORMAT(sale_date, '%Y-%m-01') AS sale_month,
                ROUND(SUM(total_amount), 2) AS total_sales
            FROM sales 
            GROUP BY DATE_FORMAT(sale_date, '%Y-%m-01')
            ORDER BY sale_month ASC
        """)
        monthly_sales = cursor.fetchall()
        
        chart_html = ""
        best_selling_forecast_html = ""
        
        if monthly_sales:
            try:
                forecaster = SalesForecaster()
                fitted_model, predictions = forecaster.train_model(monthly_sales)
                forecast_values, confidence_intervals = forecaster.generate_forecast(steps=1)
                
                fig = forecaster.plot_results(
                    monthly_sales, 
                    predictions,
                    title="Monthly Sales Forecast"
                )
                chart_html = fig.to_html(full_html=False, include_plotlyjs=True)
                
            except Exception as e:
                print(f"Forecasting error: {e}")
                flash("Error generating forecast", "error")

        # âœ… Get TOP 3 best selling products only
        cursor.execute("""
            SELECT 
                p.product_name,
                SUM(oi.quantity) AS total_sold
            FROM order_items oi
            JOIN products p ON oi.product_id = p.product_id
            JOIN orders o ON oi.order_id = o.order_id
            WHERE o.status IN ('delivered', 'completed', 'pending')
            GROUP BY p.product_id, p.product_name
            ORDER BY total_sold DESC
            LIMIT 3
        """)
        best_selling_products = cursor.fetchall()
        
        # Generate chart if data exists
        if best_selling_products:
            import plotly.graph_objs as go
            
            products = [row['product_name'] for row in best_selling_products]
            quantities = [row['total_sold'] for row in best_selling_products]
            
            # âœ… Color coding for top 3
            colors = ['#FFD700', '#C0C0C0', '#CD7F32']  # Gold, Silver, Bronze
            
            fig = go.Figure(data=[
                go.Bar(
                    x=products,
                    y=quantities,
                    marker=dict(
                        color=colors,
                        line=dict(color='#2E7D32', width=2)
                    ),
                    text=quantities,
                    textposition='auto',
                    textfont=dict(size=14, color='white', family='Arial Black')
                )
            ])
            
            fig.update_layout(
                title="ðŸ† Top 3 Best Selling Products",
                xaxis_title="Product Name",
                yaxis_title="Total Quantity Sold",
                template="plotly_white",
                height=500,
                font=dict(size=12)
            )
            
            best_selling_forecast_html = fig.to_html(full_html=False, include_plotlyjs=False)

        # Get today's total sales
        cursor.execute("""
            SELECT COALESCE(SUM(total_amount), 0) as total_sales 
            FROM sales 
            WHERE DATE(sale_date) = CURDATE()
        """)
        total_sales = cursor.fetchone()['total_sales']

        # Get pending users count
        cursor.execute("SELECT COUNT(*) as pending_users FROM users WHERE status='pending'")
        pending_users = cursor.fetchone()['pending_users']

        conn.close()

        return render_template(
            'admin/dashboard.html',
            total_sales=total_sales,
            pending_users=pending_users,
            chart_html=chart_html,
            best_selling_forecast_html=best_selling_forecast_html,
            current_year=date.today().year
        )
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash("Error connecting to database", "error")
        return redirect(url_for('login'))
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/admin/users')
def view_users():
    if 'role' not in session or session['role'] != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    # Only get pending users
    cursor.execute("SELECT user_id, full_name, email, role, status, date_registered FROM users WHERE status='pending' ORDER BY date_registered DESC")
    users = cursor.fetchall()
    conn.close()

    return render_template('admin/users.html', users=users, current_year=datetime.now().year)

@app.route('/admin/approve/<int:user_id>')
def approve_user(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status = 'approved' WHERE user_id = %s", (user_id,))
    conn.commit()
    conn.close()
    flash("User approved successfully!", "success")
    return redirect(url_for('view_users'))


@app.route('/admin/reject/<int:user_id>')
def reject_user(user_id):
    if 'role' not in session or session['role'] != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status = 'rejected' WHERE user_id = %s", (user_id,))
    conn.commit()
    conn.close()
    flash("User rejected.", "success")
    return redirect(url_for('view_users'))

@app.route('/admin/inventory', methods=['GET'])
def admin_inventory():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Kunin date filter
    selected_date = request.args.get('date', None)
    if not selected_date:
        cursor.execute("SELECT CURDATE() AS today")
        selected_date = cursor.fetchone()['today']

    # Query para kunin AM, PM (latest per day per product)
    query = """
        SELECT 
            p.category,
            p.product_id,
            p.product_name,
            p.price,
            p.kilo_per_unit,
            p.reorder_level,
            COALESCE(MAX(il.am), 0) AS am,
            COALESCE(MAX(il.pm), 0) AS pm
        FROM products p
        LEFT JOIN inventorylog il
            ON p.product_id = il.product_id
            AND DATE(il.date) = %s
        GROUP BY p.product_id, p.category, p.product_name, p.price, p.kilo_per_unit, p.reorder_level
        ORDER BY p.category, p.product_name
    """
    cursor.execute(query, (selected_date,))
    products = cursor.fetchall()

    # Add final_stock = pm
    for product in products:
        product['final_stock'] = product['pm']

    # Log activity: admin viewed inventory
    if 'user_id' in session:
        full_name = get_full_name(session.get('user_id'))
        log_cursor = conn.cursor()
        log_cursor.execute(
            "INSERT INTO activity_log (full_name, action, timestamp) VALUES (%s, %s, NOW())",
            (full_name, f"Viewed inventory for {selected_date}")
        )
        conn.commit()

    conn.close()

    # Group by category
    products_by_category = {}
    for product in products:
        cat = product['category']
        if cat not in products_by_category:
            products_by_category[cat] = []
        products_by_category[cat].append(product)

    return render_template(
        'admin/inventory.html',
        products_by_category=products_by_category,
        selected_date=selected_date,
        current_year=datetime.now().year
    )

@app.route('/admin/activity-logs')
def view_logs():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT log_id, full_name, action, timestamp
        FROM activity_log
        ORDER BY timestamp DESC
    """)
    logs = cursor.fetchall()
    conn.close()
    return render_template('admin/view_logs.html', logs=logs)

@app.route('/admin/admin_today_sales', methods=['GET'])
def admin_today_sales():
    from datetime import date
    selected_date = request.args.get('date', date.today().strftime('%Y-%m-%d'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT order_id, customer_name, date_created, total_price
        FROM orders
        WHERE DATE(date_created) = %s
        ORDER BY date_created DESC
    """, (selected_date,))
    sales = cursor.fetchall()
    conn.close()

    return render_template(
        'admin/dashboard.html',
        sales=sales,
        selected_date=selected_date,
        current_year=date.today().year
    )

@app.route('/warehouse_dashboard')
def warehouse_dashboard():
    now = datetime.now()
    is_am = now.hour < 17

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get optional filters from request args
    search_query = request.args.get('search', '').strip()
    category_filter = request.args.get('category', '').strip()
    date_filter = request.args.get('date', datetime.now().date().strftime('%Y-%m-%d'))

    # Determine which stock column to check based on time
    stock_column = 'am' if is_am else 'pm'

    # âœ… FIXED Restock count query
    cursor.execute(f"""
        SELECT COUNT(*) AS restock_count
        FROM products p
        LEFT JOIN (
            SELECT product_id, am, pm
            FROM inventorylog
            WHERE DATE(date) = %s
        ) il ON p.product_id = il.product_id
        WHERE p.reorder_level IS NOT NULL 
        AND COALESCE(il.{stock_column}, 0) <= p.reorder_level
    """, (date_filter,))
    restock_count = cursor.fetchone()['restock_count']

    # âœ… FIXED LOGS QUERY â€” removes duplicates
    query = """
        SELECT 
            p.product_name, 
            p.category, 
            DATE(il.date) AS log_date,
            MAX(il.am) AS am,
            MAX(il.pm) AS pm
        FROM inventorylog il
        JOIN products p ON il.product_id = p.product_id
        WHERE DATE(il.date) = %s
    """
    params = [date_filter]

    if search_query:
        query += " AND p.product_name LIKE %s"
        params.append(f"%{search_query}%")

    if category_filter:
        query += " AND p.category = %s"
        params.append(category_filter)

    query += " GROUP BY p.product_name, p.category, DATE(il.date) ORDER BY log_date DESC, p.product_name ASC"

    cursor.execute(query, tuple(params))
    logs = cursor.fetchall()

    conn.close()

    return render_template(
        'warehouse/dashboard.html',
        logs=logs,
        restock_count=restock_count,
        search_query=search_query,
        category_filter=category_filter,
        date_filter=date_filter,
        current_year=datetime.now().year
    )

@app.route('/warehouse/inventory', methods=['GET', 'POST'])
def warehouse_inventory():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    today = datetime.now().date()
    yesterday = today - timedelta(days=1)

    # Handle POST request for saving AM/PM values
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        
        if form_type == 'add_log':
            product_id = request.form.get('product_id')
            am = request.form.get('am', 0)
            pm = request.form.get('pm', 0)

            # Check if a log already exists for this product today
            cursor.execute("""
                SELECT log_id FROM inventorylog 
                WHERE product_id = %s AND DATE(date) = %s
            """, (product_id, today))
            existing_log = cursor.fetchone()

            if existing_log:
                # UPDATE existing record
                cursor.execute("""
                    UPDATE inventorylog 
                    SET am = %s, pm = %s
                    WHERE product_id = %s AND DATE(date) = %s
                """, (am, pm, product_id, today))
            else:
                # INSERT new record
                cursor.execute("""
                    INSERT INTO inventorylog (product_id, date, am, pm)
                    VALUES (%s, %s, %s, %s)
                """, (product_id, today, am, pm))
            
            conn.commit()

            # Log the activity
            full_name = get_full_name(session.get('user_id'))
            cursor.execute(
                "INSERT INTO activity_log (full_name, action) VALUES (%s, %s)",
                (full_name, f"Updated inventory for product ID {product_id}")
            )
            conn.commit()

            flash('Inventory updated successfully!', 'success')
            conn.close()
            return redirect(url_for('warehouse_inventory'))

    # UPDATED: Fetch products with auto-carry from yesterday PM
    cursor.execute("""
        SELECT 
            p.category, 
            p.product_id, 
            p.product_name, 
            p.price, 
            p.kilo_per_unit,
            COALESCE(
                (SELECT am FROM inventorylog WHERE product_id = p.product_id AND DATE(date) = %s LIMIT 1),
                (SELECT pm FROM inventorylog WHERE product_id = p.product_id AND DATE(date) = %s LIMIT 1),
                0
            ) AS am,
            COALESCE(
                (SELECT pm FROM inventorylog WHERE product_id = p.product_id AND DATE(date) = %s LIMIT 1),
                0
            ) AS pm
        FROM products p
        ORDER BY p.category, p.product_name
    """, (today, yesterday, today))
    products = cursor.fetchall()
    conn.close()

    # Group products by category
    products_by_category = {}
    for product in products:
        category = product['category']
        if category not in products_by_category:
            products_by_category[category] = []
        products_by_category[category].append(product)

    return render_template(
        'warehouse/manage_inventory.html',
        products_by_category=products_by_category,
        current_year=datetime.now().year
    )
# Add this route to replace your existing restock_alerts route in app.py

@app.route('/warehouse/restock_alerts')
def restock_alerts():
    today = datetime.now().date()
    yesterday = today - timedelta(days=1)
    now = datetime.now()
    is_am = now.hour < 17

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Enhanced query with expiry date tracking
    if is_am:
        cursor.execute("""
            SELECT 
                p.product_id, 
                p.product_name, 
                p.category, 
                p.reorder_level,
                p.expiry_date,
                p.expiry_months,
                COALESCE(today_il.am, yesterday_il.pm, 0) AS current_stock,
                COALESCE(today_il.last_restock_date, yesterday_il.last_restock_date) AS last_restock_date,
                DATEDIFF(p.expiry_date, CURDATE()) AS days_until_expiry
            FROM products p
            LEFT JOIN inventorylog today_il ON p.product_id = today_il.product_id AND DATE(today_il.date) = %s
            LEFT JOIN inventorylog yesterday_il ON p.product_id = yesterday_il.product_id AND DATE(yesterday_il.date) = %s
            WHERE p.reorder_level IS NOT NULL 
              AND p.reorder_level > 0
              AND COALESCE(today_il.am, yesterday_il.pm, 0) <= p.reorder_level
            ORDER BY current_stock ASC, days_until_expiry ASC
        """, (today, yesterday))
    else:
        cursor.execute("""
            SELECT 
                p.product_id, 
                p.product_name, 
                p.category, 
                p.reorder_level,
                p.expiry_date,
                p.expiry_months,
                COALESCE(il.pm, 0) AS current_stock,
                il.last_restock_date,
                DATEDIFF(p.expiry_date, CURDATE()) AS days_until_expiry
            FROM products p
            LEFT JOIN inventorylog il ON p.product_id = il.product_id AND DATE(il.date) = %s
            WHERE p.reorder_level IS NOT NULL 
              AND p.reorder_level > 0
              AND COALESCE(il.pm, 0) <= p.reorder_level
            ORDER BY current_stock ASC, days_until_expiry ASC
        """, (today,))
    
    restocks = cursor.fetchall()
    
    # Calculate expiry status for each product
    for product in restocks:
        if product['days_until_expiry'] is not None:
            if product['days_until_expiry'] < 0:
                product['expiry_status'] = 'expired'
                product['expiry_badge'] = 'danger'
            elif product['days_until_expiry'] <= 7:
                product['expiry_status'] = 'expiring_soon'
                product['expiry_badge'] = 'warning'
            elif product['days_until_expiry'] <= 30:
                product['expiry_status'] = 'attention'
                product['expiry_badge'] = 'info'
            else:
                product['expiry_status'] = 'good'
                product['expiry_badge'] = 'success'
        else:
            product['expiry_status'] = 'no_expiry'
            product['expiry_badge'] = 'secondary'
    
    conn.close()

    return render_template(
        'warehouse/restock.html',
        restocks=restocks,
        current_year=datetime.now().year
    )

# Add this new route to handle restocking with expiry date update
@app.route('/warehouse/restock_product', methods=['POST'])
def restock_product():
    product_id = request.form.get('product_id')
    quantity = request.form.get('quantity')
    expiry_months = request.form.get('expiry_months')
    
    if not product_id or not quantity:
        flash('Invalid input. Please provide all required fields.', 'danger')
        return redirect(url_for('restock_alerts'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        today = datetime.now().date()
        now = datetime.now()
        is_am = now.hour < 17
        stock_column = 'am' if is_am else 'pm'
        
        # Calculate new expiry date if expiry_months is provided
        new_expiry_date = None
        if expiry_months:
            from dateutil.relativedelta import relativedelta
            new_expiry_date = today + relativedelta(months=int(expiry_months))
        
        # Get current stock
        cursor.execute(f"""
            SELECT {stock_column} as current_stock
            FROM inventorylog
            WHERE product_id = %s AND DATE(date) = %s
        """, (product_id, today))
        result = cursor.fetchone()
        current_stock = result['current_stock'] if result else 0
        
        # Update inventory log with new stock and restock date
        new_stock = int(current_stock) + int(quantity)
        cursor.execute(f"""
            INSERT INTO inventorylog (product_id, date, {stock_column}, last_restock_date)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
                {stock_column} = %s,
                last_restock_date = %s
        """, (product_id, today, new_stock, today, new_stock, today))
        
        # Update product expiry date if provided
        if new_expiry_date:
            cursor.execute("""
                UPDATE products 
                SET expiry_date = %s, expiry_months = %s
                WHERE product_id = %s
            """, (new_expiry_date, expiry_months, product_id))
        
        conn.commit()
        
        # Log the activity
        cursor.execute("SELECT product_name FROM products WHERE product_id = %s", (product_id,))
        product = cursor.fetchone()
        product_name = product['product_name'] if product else f"ID {product_id}"
        
        full_name = get_full_name(session.get('user_id'))
        cursor.execute("""
            INSERT INTO activity_log (full_name, action, timestamp)
            VALUES (%s, %s, NOW())
        """, (full_name, f"Restocked {quantity} units of {product_name}"))
        conn.commit()
        
        flash(f'Product restocked successfully! New expiry date: {new_expiry_date if new_expiry_date else "Not updated"}', 'success')
    except Exception as e:
        flash(f'Error restocking product: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('restock_alerts'))

@app.route('/warehouse/add_product', methods=['POST'])
def add_product():
    category = request.form['category']
    product_name = request.form['product_name']
    price = request.form['price']
    kilo_per_unit = request.form['kilo_per_unit']
    try:
        quantity = int(request.form.get('quantity', 0))
    except (ValueError, TypeError):
        quantity = 0

    rl_raw = request.form.get('reorder_level')
    if rl_raw is None or rl_raw == '':
        reorder_level = None
    else:
        try:
            reorder_level = int(rl_raw)
        except (ValueError, TypeError):
            reorder_level = None

    # Calculate expiry date from months
    expiry_months = request.form.get('expiry_months')
    if expiry_months and expiry_months != '':
        from dateutil.relativedelta import relativedelta
        expiry_date = datetime.now().date() + relativedelta(months=int(expiry_months))
    else:
        expiry_date = None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO products (category, product_name, price, kilo_per_unit, quantity, reorder_level, expiry_date)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (category, product_name, price, kilo_per_unit, quantity, reorder_level, expiry_date))
    conn.commit()

    full_name = get_full_name(session.get('user_id'))
    log_cursor = conn.cursor()
    log_cursor.execute(
        "INSERT INTO activity_log (full_name, action) VALUES (%s, %s)",
        (full_name, f"Added product '{product_name}' in category '{category}'")
    )
    conn.commit()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect(url_for('warehouse_dashboard'))

@app.route('/update_warehouse_account', methods=['POST'])
def update_warehouse_account():
    email = request.form['email']
    password = request.form['password']
    
    # Hash the new password
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("UPDATE users SET email=%s, password=%s WHERE user_id=%s",
                   (email, hashed_password, session['user_id']))
    conn.commit()

    # Log the action
    full_name = get_full_name(session.get('user_id'))
    cursor.execute(
        "INSERT INTO activity_log (full_name, action) VALUES (%s, %s)",
        (full_name, "Updated warehouse account")
    )
    conn.commit()
    conn.close()

    flash("Account updated successfully!", "success")
    return redirect(url_for('warehouse_dashboard'))



@app.route('/warehouse/delete_product', methods=['POST'])
def delete_product():
    product_id = request.form.get('product_id')

    if not product_id:
        flash('Invalid product ID.', 'danger')
        return redirect(url_for('warehouse_inventory'))

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get product name for logging
        cursor.execute("SELECT product_name FROM products WHERE product_id = %s", (product_id,))
        product = cursor.fetchone()
        product_name = product['product_name'] if product else f"ID {product_id}"
        
        # Delete from inventory logs first (foreign key constraint)
        cursor.execute("DELETE FROM inventorylog WHERE product_id = %s", (product_id,))
        
        # Delete from order_items if exists
        cursor.execute("DELETE FROM order_items WHERE product_id = %s", (product_id,))
        
        # Delete the product itself
        cursor.execute("DELETE FROM products WHERE product_id = %s", (product_id,))
        
        conn.commit()
        
        # Log the activity
        full_name = get_full_name(session.get('user_id'))
        cursor.execute("""
            INSERT INTO activity_log (full_name, action, timestamp)
            VALUES (%s, %s, NOW())
        """, (full_name, f"Deleted product: {product_name}"))
        conn.commit()
        
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        if conn:
            conn.rollback()
        flash(f'Error deleting product: {e}', 'danger')
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return redirect(url_for('warehouse_inventory'))

@app.route('/secretary/dashboard')
def secretary_dashboard():
    if 'role' not in session or session['role'] != 'secretary':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    today = datetime.now().date()

    # Count pending deliveries
    cursor.execute("""
        SELECT COUNT(*) AS pending_count
        FROM orders
        WHERE status = 'pending'
    """)
    pending_deliveries = cursor.fetchone()['pending_count']

    # Count completed deliveries today
    cursor.execute("""
        SELECT COUNT(*) AS completed_today
        FROM orders
        WHERE status = 'completed' AND DATE(date_created) = CURDATE()
    """)
    completed_deliveries_today = cursor.fetchone()['completed_today']

    # Get today's deliveries with full details
    cursor.execute("""
        SELECT o.order_id, o.customer_name, o.address, o.date_created, 
               o.status, u.full_name AS delivery_staff
        FROM orders o
        LEFT JOIN users u ON o.assigned_driver = u.user_id
        WHERE DATE(o.date_created) = %s
        ORDER BY o.date_created DESC
    """, (today,))
    today_deliveries = cursor.fetchall()

    # Attach order items to each delivery
    for delivery in today_deliveries:
        cursor.execute("""
            SELECT oi.*, p.product_name, p.kilo_per_unit
            FROM order_items oi
            JOIN products p ON oi.product_id = p.product_id
            WHERE oi.order_id = %s
        """, (delivery['order_id'],))
        delivery['order_items'] = cursor.fetchall()

    conn.close()

    return render_template(
        'secretary/dashboard.html',
        pending_deliveries=pending_deliveries,
        completed_deliveries_today=completed_deliveries_today,
        today_deliveries=today_deliveries,
        current_year=datetime.now().year
    )
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/secretary/pending_deliveries')
def view_pending_deliveries():
    if 'role' not in session or session['role'] != 'secretary':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Fetch only pending deliveries with driver info
    cursor.execute("""
        SELECT o.*, u.full_name AS driver_full_name
        FROM orders o
        LEFT JOIN users u ON o.assigned_driver = u.user_id
        WHERE o.status = 'pending'
        ORDER BY o.date_created DESC
    """)
    deliveries = cursor.fetchall()

    # Attach order items to each delivery
    for delivery in deliveries:
        cursor.execute("""
            SELECT oi.*, p.product_name, p.kilo_per_unit
            FROM order_items oi
            JOIN products p ON oi.product_id = p.product_id
            WHERE oi.order_id = %s
        """, (delivery['order_id'],))
        order_items = cursor.fetchall()
        
        # Calculate kilos for each item
        for item in order_items:
            item['kilos'] = item['quantity'] * item.get('kilo_per_unit', 0)
        
        delivery['order_items'] = order_items

    conn.close()
    
    return render_template(
        'secretary/pending_deliveries.html',  # filename lang yung nandito
        deliveries=deliveries,
        current_year=datetime.now().year
    )

@app.route('/secretary/completed_deliveries')
def view_completed_deliveries():
    if 'role' not in session or session['role'] != 'secretary':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT d.*, u.full_name AS driver_full_name
        FROM deliveries d
        LEFT JOIN users u ON d.assigned_driver = u.user_id
        WHERE d.status = 'completed'
        ORDER BY d.completed_at DESC
    """)
    completed_deliveries = cursor.fetchall()

    # Attach proof photos and other details if needed
    for delivery in completed_deliveries:
        delivery['proof_photos'] = delivery.get('proof_photos', None)

    conn.close()

    return render_template(
        'secretary/completed_deliveries.html',
        completed_deliveries=completed_deliveries,
        current_year=datetime.now().year
    )

def get_completed_deliveries():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT d.*, u.full_name AS driver_full_name
        FROM deliveries d
        LEFT JOIN users u ON d.assigned_driver = u.user_id
        WHERE d.status = 'delivered'
        ORDER BY d.date_created DESC
    """)
    deliveries = cursor.fetchall()
    # Attach order items to each delivery (from orders/order_items)
    for delivery in deliveries:
        cursor.execute("""
            SELECT oi.*, p.product_name 
            FROM order_items oi 
            JOIN products p ON oi.product_id = p.product_id 
            WHERE oi.order_id = %s
        """, (delivery['order_id'],))
        delivery['order_items'] = cursor.fetchall()
    conn.close()
    return deliveries

def get_order_items(order_id):
    """
    Helper to fetch order items for a given order_id; returns a list of dicts
    with order item fields plus product_name.
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT oi.*, p.product_name
            FROM order_items oi
            JOIN products p ON oi.product_id = p.product_id
            WHERE oi.order_id = %s
            ORDER BY oi.order_item_id ASC
        """, (order_id,))
        items = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()
    return items

@app.route('/secretary/create_customer', methods=['GET', 'POST'])
def create_customer():
    if 'role' not in session or session['role'] != 'secretary':
        return redirect(url_for('login'))

    if request.method == 'POST':
        customer_name = request.form['customer_name']
        contact_number = request.form['contact_number']
        address = request.form['address']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert new customer
        cursor.execute("""
            INSERT INTO customers (customer_name, contact_number, address)
            VALUES (%s, %s, %s)
        """, (customer_name, contact_number, address))

        # Log the activity
        activity = f"Added new customer: {customer_name}"
        cursor.execute("""
            INSERT INTO activity_log (full_name, action, timestamp)
            VALUES (%s, %s, NOW())
        """, (get_full_name(session.get('user_id')), activity))

        conn.commit()
        conn.close()

        flash('Customer added successfully!', 'success')
        return redirect(url_for('secretary_dashboard'))

    return render_template('secretary/create_customer.html', current_year=datetime.now().year)

# Added route to satisfy templates that call url_for('manage_customers')
@app.route('/secretary/manage_customers')
def manage_customers():
    if 'role' not in session or session['role'] != 'secretary':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT customer_id, customer_name, contact_number, address, created_at FROM customers ORDER BY created_at DESC")
    customers = cursor.fetchall()
    conn.close()

    return render_template('secretary/manage_customers.html', customers=customers, current_year=datetime.now().year)

@app.route('/secretary/create_order', methods=['GET', 'POST'])
def create_order():
    if 'role' not in session or session['role'] != 'secretary':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        print("=" * 50)
        print("ðŸ”µ POST REQUEST RECEIVED")
        print("=" * 50)
        
        try:
            # Debug: Print all form data
            print("ðŸ“‹ Form Data:")
            for key, value in request.form.items():
                print(f"  {key}: {value}")
            
            # Get form data
            customer_name = request.form.get('customer_name')
            assigned_driver = request.form.get('assigned_driver')
            address = request.form.get('address')
            total_price = request.form.get('total_price')
            order_items_json = request.form.get('order_items')

            print(f"\nâœ… customer_name: {customer_name}")
            print(f"âœ… assigned_driver: {assigned_driver}")
            print(f"âœ… address: {address}")
            print(f"âœ… total_price: {total_price}")
            print(f"âœ… order_items_json: {order_items_json}")

            # Validation
            if not customer_name:
                print("âŒ Missing customer_name")
                flash('Customer name is required!', 'error')
                return redirect(url_for('create_order'))
            
            if not assigned_driver:
                print("âŒ Missing assigned_driver")
                flash('Assigned driver is required!', 'error')
                return redirect(url_for('create_order'))
            
            if not address:
                print("âŒ Missing address")
                flash('Address is required!', 'error')
                return redirect(url_for('create_order'))
            
            if not total_price:
                print("âŒ Missing total_price")
                flash('Total price is required!', 'error')
                return redirect(url_for('create_order'))
            
            if not order_items_json:
                print("âŒ Missing order_items")
                flash('Order items are required!', 'error')
                return redirect(url_for('create_order'))

            # Parse order items
            import json
            order_items = json.loads(order_items_json)
            print(f"\nðŸ“¦ Parsed {len(order_items)} order items:")
            for item in order_items:
                print(f"  - Product ID: {item['product_id']}, Quantity: {item['quantity']}")

            if not order_items:
                print("âŒ Empty order_items array")
                flash('Please add at least one product!', 'error')
                return redirect(url_for('create_order'))

            # Connect to database
            print("\nðŸ”Œ Connecting to database...")
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            print("âœ… Database connected")

            # Build product names string
            product_names = []
            for item in order_items:
                cursor.execute("SELECT product_name FROM products WHERE product_id = %s", (item['product_id'],))
                product = cursor.fetchone()
                if product:
                    product_names.append(product['product_name'])
                    print(f"  âœ… Found product: {product['product_name']}")

            product_names_str = ', '.join(product_names)
            created_at = datetime.now()

            print(f"\nðŸ“ Inserting order into database...")
            print(f"  Customer: {customer_name}")
            print(f"  Products: {product_names_str}")
            print(f"  Driver ID: {assigned_driver}")
            print(f"  Address: {address}")
            print(f"  Total: â‚±{total_price}")

            # Insert order
            cursor.execute("""
                INSERT INTO orders (customer_name, product_name, assigned_driver, address, date_created, total_price, status)
                VALUES (%s, %s, %s, %s, %s, %s, 'pending')
            """, (customer_name, product_names_str, assigned_driver, address, created_at, float(total_price)))
            order_id = cursor.lastrowid
            print(f"âœ… Order inserted! Order ID: {order_id}")

            # Insert order items and deduct stock
            stock_column = 'am' if datetime.now().hour < 17 else 'pm'
            print(f"\nðŸ“¦ Processing order items (Stock Column: {stock_column})...")
            
            for item in order_items:
                product_id = item['product_id']
                quantity = int(item['quantity'])

                # âœ… FIXED: Remove the price field from INSERT statement
                print(f"  ðŸ“ Inserting order_item: Product {product_id}, Qty {quantity}")
                cursor.execute("""
                    INSERT INTO order_items (order_id, product_id, quantity)
                    VALUES (%s, %s, %s)
                """, (order_id, product_id, quantity))

                # Deduct stock from inventorylog
                print(f"  ðŸ“‰ Deducting {quantity} from product {product_id} ({stock_column} stock)")
                cursor.execute(f"""
                    UPDATE inventorylog 
                    SET {stock_column} = {stock_column} - %s
                    WHERE product_id = %s AND DATE(date) = CURDATE()
                """, (quantity, product_id))

            # Insert into sales table
            print(f"\nðŸ’° Inserting into sales table...")
            cursor.execute("""
                INSERT INTO sales (order_id, sale_date, total_amount)
                VALUES (%s, %s, %s)
            """, (order_id, created_at, float(total_price)))
            print(f"âœ… Sale recorded")

            # Log activity
            full_name = get_full_name(session.get('user_id'))
            cursor.execute("""
                INSERT INTO activity_log (full_name, action, timestamp)
                VALUES (%s, %s, NOW())
            """, (full_name, f"Created order #{order_id} for {customer_name}"))
            print(f"âœ… Activity logged")

            print(f"\nðŸ’¾ Committing transaction...")
            conn.commit()
            print("âœ… TRANSACTION COMMITTED SUCCESSFULLY!")
            print("=" * 50)
            
            flash('Order created successfully!', 'success')
            return redirect(url_for('secretary_dashboard'))

        except Exception as e:
            if 'conn' in locals():
                conn.rollback()
                print(f"\nâŒ ROLLBACK EXECUTED")
            print(f"\nâŒâŒâŒ ERROR: {str(e)}")
            print(f"Error type: {type(e).__name__}")
            import traceback
            print(traceback.format_exc())
            flash(f'Error creating order: {str(e)}', 'error')
            return redirect(url_for('create_order'))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()
                print("ðŸ”Œ Database connection closed")

    # GET request - Show form
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM customers ORDER BY customer_name")
    customers = cursor.fetchall()

    cursor.execute("SELECT user_id, full_name FROM users WHERE role = 'delivery_driver' ORDER BY full_name")
    drivers = cursor.fetchall()

    current_hour = datetime.now().hour
    stock_column = 'am' if current_hour < 17 else 'pm'
    
    cursor.execute(f"""
        SELECT 
            p.product_id,
            p.product_name, 
            p.category,
            p.price,
            p.kilo_per_unit,
            COALESCE(MAX(il.{stock_column}), 0) as current_stock
        FROM products p
        LEFT JOIN inventorylog il ON p.product_id = il.product_id AND DATE(il.date) = CURDATE()
        GROUP BY p.product_id, p.product_name, p.category, p.price, p.kilo_per_unit
        HAVING current_stock > 0
        ORDER BY p.category, p.product_name
    """)
    products = cursor.fetchall()

    products_by_category = {}
    for product in products:
        category = product['category']
        if category not in products_by_category:
            products_by_category[category] = []
        products_by_category[category].append(product)

    categories = list(products_by_category.keys())
    conn.close()

    return render_template(
        'secretary/create_order.html',
        customers=customers,
        drivers=drivers,
        products_by_category=products_by_category,
        categories=categories,
        current_time=datetime.now().strftime('%Y-%m-%dT%H:%M'),
        current_year=datetime.now().year
    )
    
@app.route('/warehouse/edit_product_inventory', methods=['POST'])
def edit_product_inventory():
    product_id = request.form.get('product_id')
    am = request.form.get('am')
    pm = request.form.get('pm')

    if not product_id or am is None or pm is None:
        flash('Invalid input. Please provide all required fields.', 'danger')
        return redirect(url_for('warehouse_inventory'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE inventorylog
            SET am = %s, pm = %s
            WHERE product_id = %s AND DATE(date) = CURDATE()
        """, (am, pm, product_id))
        conn.commit()
        flash('Inventory updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating inventory: {e}', 'danger')
    finally:
        conn.close()
        # Log the activity
    activity = f"Edited inventory for product ID: {product_id}"
    cursor.execute("""
        INSERT INTO activity_log (full_name, action, timestamp)
        VALUES (%s, %s, NOW())
    """, (get_full_name(session.get('user_id')), activity))
    conn.commit()
    conn.close()

    return redirect(url_for('warehouse_inventory'))

@app.route('/api/deliveries')
def get_deliveries():
    if 'role' not in session or session['role'] != 'delivery_driver':
        return {'success': False, 'message': 'Unauthorized'}, 401

    user_id = session.get('user_id')
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get today's deliveries for the logged-in driver
        today = datetime.now().date()
        cursor.execute("""
            SELECT o.order_id, o.customer_name, o.address, o.status, o.date_created,
                   GROUP_CONCAT(CONCAT(oi.quantity, 'x ', p.product_name) SEPARATOR ', ') as products
            FROM orders o
            LEFT JOIN order_items oi ON o.order_id = oi.order_id
            LEFT JOIN products p ON oi.product_id = p.product_id
            WHERE o.assigned_driver = %s 
            AND DATE(o.date_created) = %s 
            GROUP BY o.order_id
            ORDER BY o.date_created ASC
        """, (user_id, today))
        deliveries = cursor.fetchall()
        
        # Add sample coordinates for demo
        # In real app, these would come from the database
        import random
        for delivery in deliveries:
            delivery['latitude'] = 14.1 + random.uniform(-0.1, 0.1)
            delivery['longitude'] = 121.4 + random.uniform(-0.1, 0.1)
        
        return {'success': True, 'deliveries': deliveries}
    except Exception as e:
        return {'success': False, 'message': str(e)}, 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/driver/stats')
def get_driver_stats():
    if 'role' not in session or session['role'] != 'delivery_driver':
        return {'success': False, 'message': 'Unauthorized'}, 401

    user_id = session.get('user_id')
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        today = datetime.now().date()

        # Get assigned deliveries count
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM orders 
            WHERE assigned_driver = %s AND DATE(date_created) = %s
        """, (user_id, today))
        assigned = cursor.fetchone()['count']

        # Get completed deliveries count
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM orders 
            WHERE assigned_driver = %s 
            AND DATE(date_created) = %s 
            AND status = 'delivered'
        """, (user_id, today))
        completed = cursor.fetchone()['count']

        # Sample distance and fuel calculations
        # In a real app, these would be calculated based on actual route data
        distance = completed * 5  # Assume 5km per delivery
        fuel_used = f"{distance * 0.1:.1f}L"  # Assume 0.1L per km

        stats = {
            'assigned': assigned,
            'completed': completed,
            'distance': distance,
            'fuel_used': fuel_used
        }
        
        return {'success': True, 'stats': stats}
    except Exception as e:
        return {'success': False, 'message': str(e)}, 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/delivery/dashboard')
def delivery_dashboard():
    if 'role' not in session or session['role'] != 'delivery_driver':
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    today = datetime.now().date()

    # Assigned deliveries (pending/processing)
    cursor.execute("""
        SELECT o.order_id, o.customer_name, o.address, o.status
        FROM orders o
        WHERE o.assigned_driver = %s AND DATE(o.date_created) = %s AND o.status IN ('pending', 'processing')
        ORDER BY o.date_created ASC
    """, (user_id, today))
    assigned_deliveries = cursor.fetchall()

    # Completed deliveries (from deliveries table)
    cursor.execute("""
        SELECT d.order_id, d.customer_name, d.address, d.status, d.completed_at
        FROM deliveries d
        WHERE d.assigned_driver = %s AND d.status = 'completed'
        ORDER BY d.completed_at DESC
    """, (user_id,))
    completed_deliveries = cursor.fetchall()

    conn.close()

    return render_template(
        'delivery/dashboard.html',
        assigned_deliveries=assigned_deliveries,
        completed_deliveries=completed_deliveries,
        google_maps_api_key=API_KEY,
        current_year=datetime.now().year
    )
@app.route('/delivery-route')
def delivery_route():
    return render_template('delivery/delivery_route.html')

@app.route('/delivery/assigned_deliveries')
def assigned_deliveries():
    if 'role' not in session or session['role'] != 'delivery_driver':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT full_name FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()
    driver_name = user['full_name'] if user else ''

    # JOIN to get full name for display
    cursor.execute("""
        SELECT o.*, u.full_name AS driver_full_name
        FROM orders o
        LEFT JOIN users u ON o.assigned_driver = u.user_id
        WHERE o.assigned_driver = %s AND o.status = 'pending'
        ORDER BY o.date_created DESC
    """, (user_id,))
    deliveries = cursor.fetchall()

    # Attach order items to each delivery
    for delivery in deliveries:
        cursor.execute("""
            SELECT oi.*, p.product_name 
            FROM order_items oi 
            JOIN products p ON oi.product_id = p.product_id 
            WHERE oi.order_id = %s
        """, (delivery['order_id'],))
        delivery['order_items'] = cursor.fetchall()

    today_date = date.today().strftime('%B %d, %Y')
    conn.close()

    return render_template(
        'delivery/assigned_delivery.html',
        deliveries=deliveries,
        driver_name=driver_name,
        today_date=today_date,
        current_year=date.today().year
    )

@app.route('/delivery/completed_deliveries')
def completed_deliveries():
    if 'role' not in session or session['role'] != 'delivery_driver':
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # âœ… FIXED: Added proof_photos explicitly + debug print
    cursor.execute("""
        SELECT 
            d.delivery_id,
            d.order_id,
            d.customer_name,
            d.address,
            d.status,
            d.completed_at,
            d.proof_photos,
            u.full_name AS driver_full_name
        FROM deliveries d
        LEFT JOIN users u ON d.assigned_driver = u.user_id
        WHERE d.assigned_driver = %s AND d.status = 'completed'
        ORDER BY d.completed_at DESC
    """, (user_id,))
    completed_deliveries = cursor.fetchall()
    
    # âœ… Debug: Check kung may laman ang proof_photos
    print("=" * 50)
    print("ðŸ” COMPLETED DELIVERIES DEBUG:")
    for delivery in completed_deliveries:
        print(f"Order {delivery['order_id']}: proof_photos = '{delivery.get('proof_photos')}'")
    print("=" * 50)
    
    conn.close()
    
    return render_template(
        'delivery/completed_delieveries.html',
        completed_deliveries=completed_deliveries,
        current_year=datetime.now().year
    )

# âœ… NOTICE THE BLANK LINE AND PROPER SPACING ABOVE!

@app.route('/delivery/update_status/<int:order_id>', methods=['POST'])
def update_delivery_status(order_id):
    new_status = request.form['status']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = %s WHERE order_id = %s", (new_status, order_id))
    conn.commit()
    flash('Delivery status updated!', 'success')
    # Log the activity
    activity = f"Updated delivery status for order ID: {order_id} to {new_status}"
    cursor.execute("""
        INSERT INTO activity_log (full_name, action, timestamp)
        VALUES (%s, %s, NOW())
    """, (get_full_name(session.get('user_id')), activity))
    conn.commit()
    conn.close()
    return redirect(url_for('assigned_deliveries'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()
        if user:
            from itsdangerous import URLSafeTimedSerializer
            s = URLSafeTimedSerializer(app.secret_key)
            token = s.dumps(email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)
            send_reset_email(email, reset_link)
            flash('Password reset link sent to your email!', 'success')
        else:
            flash('Email not found.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
    s = URLSafeTimedSerializer(app.secret_key)
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The reset link is invalid or expired.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        
        # Hash the new password
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        conn.commit()
        conn.close()
        flash('Password has been reset!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

def send_reset_email(to_email, reset_link):
    msg = Message('Password Reset Request',
                  sender='your_email@gmail.com',
                  recipients=[to_email])
    msg.body = f'Click the link to reset your password: {reset_link}'
    mail.send(msg)

@app.route('/migrate_passwords')
def migrate_passwords():
    """
    ONE-TIME USE: This route hashes all existing plain-text passwords.
    After running once, you should remove or comment out this route.
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get all users
    cursor.execute("SELECT user_id, password FROM users")
    users = cursor.fetchall()
    
    updated_count = 0
    for user in users:
        user_id = user['user_id']
        plain_password = user['password']
        
        # Check if password is already hashed (hashed passwords start with specific prefixes)
        if not plain_password.startswith(('pbkdf2:', 'scrypt:', 'bcrypt:')):
            # Hash the plain password
            hashed_password = generate_password_hash(plain_password, method='pbkdf2:sha256')
            
            # Update the database
            cursor.execute("UPDATE users SET password = %s WHERE user_id = %s", 
                          (hashed_password, user_id))
            updated_count += 1
    
    conn.commit()
    conn.close()
    
    return f"Password migration complete! {updated_count} passwords were hashed."


def send_reset_email(to_email, reset_link):
    msg = Message('Password Reset Request',
                  sender='your_email@gmail.com',
                  recipients=[to_email])
    msg.body = f'Click the link to reset your password: {reset_link}'
    mail.send(msg)

# Geocode deliveries without coordinates (run once or as needed)
# Requires: pip install mysql-connector-python requests
# Comment out or remove after initial run to prevent overwriting
"""
cnx = mysql.connector.connect(**DB_CONFIG)
cur = cnx.cursor(dictionary=True)

cur.execute("SELECT delivery_id, address FROM deliveries WHERE (latitude IS NULL OR longitude IS NULL) AND address IS NOT NULL")
rows = cur.fetchall()
for row in rows:
    delivery_id = row['delivery_id']
    addr = row['address']
    lat, lng = geocode(addr)
    if lat and lng:
        cur2 = cnx.cursor()
        cur2.execute("UPDATE deliveries SET latitude=%s, longitude=%s WHERE delivery_id=%s", (lat, lng, delivery_id))
        cnx.commit()
        cur2.close()
        print(f"Updated {delivery_id} -> {lat},{lng}")
    else:
        print(f"Geocode failed for {delivery_id}: {addr}")
    time.sleep(0.1)  # polite pacing to avoid quotas

cur.close()
cnx.close()
"""

today_date = date.today().strftime('%B %d, %Y')



@app.route('/api/complete_delivery/<int:order_id>', methods=['POST'])
def api_complete_delivery(order_id):
    data = request.get_json()
    delivery_notes = data.get('delivery_notes')
    proof_photos = data.get('proof_photos', [])

    # Save proof_photos (base64) and notes to DB or filesystem as needed
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE orders SET status = %s, delivery_notes = %s WHERE order_id = %s",
        ('delivered', delivery_notes, order_id)
    )
    # Example: Save proof_photos filenames to another table if needed
    # for photo in proof_photos:
    #     save_photo(photo, order_id)  # Implement this function

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Delivery marked as completed!'})

@app.route('/delivery/mark_completed/<int:order_id>', methods=['POST'])
def mark_completed(order_id):
    if 'role' not in session or session['role'] != 'delivery_driver':
        flash('Access denied.', 'error')
        return redirect(url_for('login'))

    confirm = request.form.get('confirm')
    if not confirm:
        flash('Please confirm delivery completion.', 'error')
        return redirect(url_for('delivery_dashboard'))

    if 'proof_photo' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('delivery_dashboard'))

    file = request.files['proof_photo']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('delivery_dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(f"proof_{order_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.jpg")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Fetch order details
            cursor.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
            order = cursor.fetchone()

            if order:
                # Insert into deliveries table
                cursor.execute("""
                    INSERT INTO deliveries (
                        order_id, customer_name, address, assigned_driver, 
                        status, date_created, completed_at, proof_photos
                    ) VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
                """, (
                    order['order_id'],
                    order['customer_name'],
                    order['address'],
                    order['assigned_driver'],
                    'completed',
                    order['date_created'],
                    filename
                ))

                # Update the order status to 'completed' instead of deleting it
                cursor.execute("UPDATE orders SET status = 'completed' WHERE order_id = %s", (order_id,))

                # Log activity
                full_name = get_full_name(session.get('user_id'))
                cursor.execute("""
                    INSERT INTO activity_log (full_name, action, timestamp)
                    VALUES (%s, %s, NOW())
                """, (full_name, f"Completed delivery for order #{order_id}"))

                conn.commit()
                flash('Delivery marked as completed with proof uploaded!', 'success')
            else:
                flash('Order not found.', 'error')
        except Exception as e:
            conn.rollback()
            flash(f'Error completing delivery: {e}', 'error')
        finally:
            cursor.close()
            conn.close()
    else:
        flash('Invalid file type. Please upload an image (JPG, PNG, JPEG)', 'error')

    return redirect(url_for('delivery_dashboard'))
# Sort and get top 3 products (only if a DataFrame 'df' exists)
chart_top3_html = ""
try:
    # Safely obtain df from globals or locals to avoid NameError
    df_obj = globals().get('df', locals().get('df', None))
    if df_obj is not None:
        import plotly.express as px
        # Ensure the expected columns exist before sorting/plotting
        cols = getattr(df_obj, 'columns', None)
        if cols is not None and {'quantity', 'product'}.issubset(set(cols)):
            top3 = df_obj.sort_values('quantity', ascending=False).head(3)
            fig = px.bar(top3, x='product', y='quantity')
            chart_top3_html = pyo.plot(fig, output_type='div', include_plotlyjs=False)
except Exception:
    # Fail silently and keep chart HTML empty if anything goes wrong
    chart_top3_html = ""

@app.route('/admin/upload_csv', methods=['POST'])
def upload_csv():
    # You can add your CSV processing logic here
    from flask import request, redirect, url_for, flash
    file = request.files.get('csv_file')
    if file and file.filename.endswith('.csv'):
        # Process the CSV file as needed
        flash('CSV file uploaded successfully!', 'success')
    else:
        flash('Please upload a valid CSV file.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/secretary/download_customers')
def download_customers():
    if 'role' not in session or session['role'] != 'secretary':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT customer_id, customer_name, contact_number, address, created_at FROM customers ORDER BY created_at DESC")
    customers = cursor.fetchall()
    conn.close()

    # Build CSV in memory
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Customer ID', 'Customer Name', 'Contact Number', 'Address', 'Created At'])
    for c in customers:
        created = c.get('created_at')
        if hasattr(created, 'strftime'):
            created = created.strftime('%Y-%m-%d %H:%M:%S')
        writer.writerow([c.get('customer_id'), c.get('customer_name'), c.get('contact_number'), c.get('address'), created])

    output = si.getvalue()
    si.close()

    from flask import make_response
    response = make_response(output)
    response.headers['Content-Disposition'] = 'attachment; filename=customers.csv'
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    return response

@app.route('/update_stock', methods=['POST'])
def update_stock():
    product_id = request.form['product_id']
    stock_type = 'am' if datetime.now().hour < 17 else 'pm'  # Determine AM or PM
    quantity = int(request.form['quantity'])
    today = datetime.now().date()

    conn = get_db_connection()
    cursor = conn.cursor()

    # Update the correct stock column
    cursor.execute(f"""
        INSERT INTO inventorylog (product_id, date, {stock_type})
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE {stock_type} = {stock_type} + VALUES({stock_type})
    """, (product_id, today, quantity))

    conn.commit()
    cursor.close()
    conn.close()

    flash('Stock updated successfully!', 'success')
    return redirect(url_for('restock_alerts'))

def shift_pm_to_am():
    logging.info("Running shift_pm_to_am function...")
    conn = get_db_connection()
    cursor = conn.cursor()

    yesterday = (datetime.now() - timedelta(days=1)).date()
    today = datetime.now().date()
    cursor.execute("""
        INSERT INTO inventorylog (product_id, date, am)
        SELECT product_id, %s, pm
        FROM inventorylog
        WHERE date = %s
    """, (today, yesterday))

    conn.commit()
    cursor.close()
    conn.close()
    logging.info("PM stock shifted to AM stock successfully.")

@app.route('/secretary/edit_customer/<int:customer_id>', methods=['POST'])
def edit_customer(customer_id):
    if 'role' not in session or session['role'] != 'secretary':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    customer_name = request.form.get('customer_name')
    contact_number = request.form.get('contact_number')
    address = request.form.get('address')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE customers 
        SET customer_name = %s, contact_number = %s, address = %s 
        WHERE customer_id = %s
    """, (customer_name, contact_number, address, customer_id))
    conn.commit()
    conn.close()

    flash('Customer details updated successfully!', 'success')
    return redirect(url_for('manage_customers'))


@app.route('/secretary/delete_customer/<int:customer_id>', methods=['POST'])
def delete_customer(customer_id):
    if 'role' not in session or session['role'] != 'secretary':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM customers WHERE customer_id = %s", (customer_id,))
    conn.commit()
    conn.close()

    flash('Customer deleted successfully!', 'success')
    return redirect(url_for('manage_customers'))

@app.route('/secretary/download_completed_deliveries')
def download_completed_deliveries():
    # Example logic to generate a CSV file for completed deliveries
    completed_deliveries = get_completed_deliveries()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Order ID', 'Customer', 'Address', 'Date Completed', 'Driver', 'Total Price'])
    for delivery in completed_deliveries:
        writer.writerow([
            delivery['order_id'],
            delivery['customer_name'],
            delivery['address'],
            delivery['date_created'],
            delivery.get('driver_full_name', 'N/A'),
            delivery['total_price']
        ])
    output = si.getvalue()
    si.close()

    from flask import make_response
    response = make_response(output)
    response.headers['Content-Disposition'] = 'attachment; filename=completed_deliveries.csv'
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    return response

# New function to update filenames in the database
import mysql.connector

DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'casadoragri_db'
}

def update_filenames():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT delivery_id, proof_photos FROM deliveries WHERE proof_photos IS NOT NULL")
    rows = cursor.fetchall()

    for delivery_id, proof_photos in rows:
        updated_photos = ','.join([photo + '.jpg' if '.' not in photo else photo for photo in proof_photos.split(',')])
        cursor.execute("UPDATE deliveries SET proof_photos = %s WHERE delivery_id = %s", (updated_photos, delivery_id))
        conn.commit()

    cursor.close()
    conn.close()

update_filenames()

# Initialize the scheduler
scheduler = BackgroundScheduler()

# Schedule the shift_pm_to_am function to run daily at midnight
scheduler.add_job(shift_pm_to_am, 'cron', hour=0, minute=0)

# Start the scheduler
scheduler.start()

# Ensure the scheduler shuts down when the app stops
import atexit
atexit.register(lambda: scheduler.shutdown())

@app.route('/test_shift_pm_to_am', methods=['GET'])
def test_shift_pm_to_am():
    shift_pm_to_am()
    return "PM stock shifted to AM stock successfully!"

if __name__ == '__main__':
    app.run(debug=True)