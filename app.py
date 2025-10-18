from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, send_file, jsonify
from models import db, bcrypt, Customer, Login, CustomerDetails, Ebook, Category, SupportMessage
from flask_mail import Mail, Message
import os
from difflib import SequenceMatcher
import re
import requests
import random
from werkzeug.utils import secure_filename
from PyPDF2 import PdfReader, PdfWriter
from io import BytesIO
from functools import wraps
from dotenv import load_dotenv
from sqlalchemy import or_
import google.generativeai as genai
import threading
import razorpay
from coinbase_commerce.client import Client # Import Coinbase Commerce
from flask_migrate import Migrate


load_dotenv()

app = Flask(__name__)

# --- Configuration from Environment Variables ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['ADMIN_SECRET_CODE'] = os.getenv('ADMIN_SECRET_CODE')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'ebooks')
app.config['TEMP_UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'temp_uploads')

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# # AI Configuration
# try:
#     genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
#     # NEW, CORRECTED LINE
#     # Ensure this line uses 'gemini-pro'
#     gemini_model = genai.GenerativeModel('gemini-pro')
#     print("[*] Google Gemini AI configured successfully.")
# except Exception as e:
#     gemini_model = None
#     print(f"[!] Warning: Could not configure Gemini AI. Error: {e}")

# --- Razorpay Configuration ---
RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET')

if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
    razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    print("[*] Razorpay client configured for testing.")
else:
    razorpay_client = None
    print("[!] Warning: Razorpay API keys not found. Payment features will be disabled.")

# --- Coinbase Commerce Configuration ---
COINBASE_API_KEY = os.getenv('COINBASE_COMMERCE_API_KEY')
if COINBASE_API_KEY and COINBASE_API_KEY != 'YOUR_COINBASE_COMMERCE_API_KEY':
    coinbase_client = Client(api_key=COINBASE_API_KEY)
    print("[*] Coinbase Commerce client configured.")
else:
    coinbase_client = None
    print("[!] Warning: Coinbase Commerce API key not found. Crypto payments will be disabled.")


# --- Initialize Extensions ---
db.init_app(app)
bcrypt.init_app(app)
mail = Mail(app)
migrate = Migrate(app, db)


# --- AI Helper Function ---
def analyze_ebook_content_with_gemini(pdf_bytes, max_pages=10, max_chars=4000, min_text_length=50):
    try:
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment.")

        genai.configure(api_key=api_key)

        # Auto-detect the correct Gemini Pro model
        gemini_model_name = None
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods and 'gemini-pro' in m.name:
                gemini_model_name = m.name
                break
        if not gemini_model_name:
            raise ValueError("No Gemini Pro model found that supports generateContent.")

        model = genai.GenerativeModel(gemini_model_name)

    except Exception as e:
        print(f"[!] Critical AI Config Error: {e}")
        return {"summary": "AI system could not be configured.", "assessment": "Configuration Failed."}

    try:
        pdf_reader = PdfReader(BytesIO(pdf_bytes))
        total_pages = len(pdf_reader.pages)
        text = ""

        # Collect all pages with meaningful text
        meaningful_pages = []
        for i, page in enumerate(pdf_reader.pages):
            page_text = page.extract_text()
            if page_text and len(page_text.strip()) >= min_text_length:
                meaningful_pages.append(i)

        if not meaningful_pages:
            return {"summary": "Could not extract meaningful text from the PDF.", "assessment": "Unable to analyze."}

        # Sample pages
        if len(meaningful_pages) > max_pages:
            pages_to_read = sorted(random.sample(meaningful_pages, max_pages))
        else:
            pages_to_read = meaningful_pages

        # Extract text from selected pages
        for page_num in pages_to_read:
            page_text = pdf_reader.pages[page_num].extract_text()
            if page_text:
                text += page_text + "\n"

        # Limit text length for AI prompt
        text = text[:max_chars]

        prompt = f"""
Analyze the following text extracted from selected pages of a PDF document.

Text: "{text}"

Please provide two things in your response, separated by '---':
1. SUMMARY: A brief, one-paragraph summary of the content.
2. ASSESSMENT: An assessment of whether this appears to be a genuine book or document.
"""

        response = model.generate_content(prompt)

        summary = "Could not parse summary from AI response."
        assessment = "Could not parse assessment from AI response."

        if "---" in response.text:
            parts = response.text.split("---")
            summary = parts[0].replace("1. SUMMARY:", "").replace("**SUMMARY:**", "").strip()
            assessment = parts[1].replace("2. ASSESSMENT:", "").replace("**ASSESSMENT:**", "").strip()

        return {"summary": summary, "assessment": assessment}

    except Exception as e:
        print(f"[!] Error during AI analysis: {e}")
        return {"summary": "An error occurred during AI analysis.", "assessment": f"Error: {e}"}


# --- Background Task for Processing Submissions ---


def verify_book_with_google_api(title, author, ai_assessment_text=None):
    """Hybrid book verification using Google Books API + AI assessment clues"""
    try:
        query = f"{title} {author}"
        url = f"https://www.googleapis.com/books/v1/volumes?q={query}"
        res = requests.get(url, timeout=10)
        data = res.json()

        if "items" not in data:
            return {"verified": False, "confidence": 0.0, "message": "No results found."}

        # Compare similarity of titles/authors
        best_match = data["items"][0]["volumeInfo"]
        matched_title = best_match.get("title", "")
        matched_authors = best_match.get("authors", [])

        title_sim = SequenceMatcher(None, title.lower(), matched_title.lower()).ratio()
        author_sim = max([SequenceMatcher(None, author.lower(), a.lower()).ratio() for a in matched_authors]) if matched_authors else 0

        # Combine confidence
        score = (0.6 * title_sim) + (0.4 * author_sim)

        # Boost score if AI analysis supports authenticity
        legitimacy_words = ["genuine", "authentic", "legitimate", "official", "real", "verified", "true", "credible"]
        if ai_assessment_text:
            if any(word in ai_assessment_text.lower() for word in legitimacy_words):
                score += 0.15  # small bonus if AI thinks it’s genuine

        verified = score >= 0.55  # lowered threshold slightly for better tolerance

        return {
            "verified": verified,
            "confidence": round(score, 2),
            "message": f"Matched with: {matched_title} by {', '.join(matched_authors)}"
        }

    except Exception as e:
        return {"verified": False, "confidence": 0.0, "message": f"Error: {e}"}


import shutil

def process_submission_in_background(app, temp_path, filename, title, author, category_name, submitter_username):
    """Background process: analyze + verify + email + auto-upload if valid"""
    with app.app_context():
        permanent_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            # Read PDF bytes
            with open(temp_path, 'rb') as f:
                pdf_bytes = f.read()

            # Step 1: Analyze content with Gemini
            ai_report = analyze_ebook_content_with_gemini(pdf_bytes)

            # Step 2: Verify book authenticity via Google Books API
            book_check = verify_book_with_google_api(title, author, ai_report['assessment'])

            # Step 3: Auto-upload if verified
            auto_status = "⚠️ Requires Manual Review"
            if book_check["verified"]:
                try:
                    category = Category.query.filter_by(name=category_name).first()
                    category_id = category.category_id if category else None

                    # Add ebook record to DB
                    new_ebook = Ebook(
                        title=title,
                        author_name=author,
                        genre=category_name,
                        price=0.0,
                        file_path=filename,
                        category_id=category_id
                    )
                    db.session.add(new_ebook)
                    db.session.commit()
                    auto_status = "✅ AUTO-UPLOADED"

                    # Move PDF to permanent folder
                    if not os.path.exists(permanent_path):
                        shutil.move(temp_path, permanent_path)
                        print(f"[*] PDF moved to permanent folder: {permanent_path}")
                    else:
                        print(f"[!] PDF already exists in permanent folder: {permanent_path}")

                except Exception as db_error:
                    print(f"[!] Auto-upload failed: {db_error}")
                    auto_status = f"❌ Auto-upload failed: {db_error}"

            # Step 4: Send admin email
            # Attach the permanent file (if moved) or temp file as fallback
            attach_bytes = None
            if os.path.exists(permanent_path):
                with open(permanent_path, 'rb') as f:
                    attach_bytes = f.read()
            else:
                attach_bytes = pdf_bytes

            msg = Message(
                subject=f"New eBook Submission: {title}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[app.config['MAIL_USERNAME']]
            )
            msg.body = f"""
--- SUBMISSION DETAILS ---
Title: {title}
Author: {author}
Suggested Category: {category_name}
Submitted by: {submitter_username}

--- AI SUMMARY ---
{ai_report['summary']}

--- AI ASSESSMENT ---
{ai_report['assessment']}

--- BOOK VALIDATION (via Google Books API) ---
{book_check['message']}
Confidence: {book_check['confidence']}
Status: {auto_status}
"""
            msg.attach(filename, 'application/pdf', attach_bytes)
            mail.send(msg)
            print(f"[*] Admin email sent for {filename}")

        except Exception as e:
            print(f"[!] Error in background task for {filename}: {e}")

        finally:
            # Remove temp file only if it still exists (wasn't moved)
            if os.path.exists(temp_path):
                os.remove(temp_path)


# --- Decorators for access control ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('auth'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'is_admin' not in session or not session['is_admin']:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# --- Main Routes ---
@app.route('/')
def dashboard():
    categories = Category.query.order_by(Category.name).all()
    ebooks = Ebook.query.all()
    return render_template('dashboard.html', ebooks=ebooks, categories=categories, logged_in='logged_in' in session)

# --- API ROUTE FOR LIVE SEARCH ---
@app.route('/api/search')
def api_search():
    search_query = request.args.get('q', '')
    category_id = request.args.get('category', '')
    query = Ebook.query
    if search_query:
        query = query.filter(or_(Ebook.title.ilike(f'%{search_query}%'), Ebook.author_name.ilike(f'%{search_query}%')))
    if category_id:
        query = query.filter(Ebook.category_id == category_id)
    ebooks = query.all()
    results = [{'id': e.ebook_id, 'title': e.title, 'author_name': e.author_name, 'genre': e.genre or 'General', 'price': e.price, 'file_path': e.file_path} for e in ebooks]
    return jsonify(results)

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        if 'register' in request.form:
            is_admin_request = 'admin_toggle' in request.form
            admin_code = request.form.get('admin_code', '')
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            username = request.form['username']
            password = request.form['password']
            
            existing_email = CustomerDetails.query.filter_by(email_id=email).first()
            if existing_email:
                flash('That email address is already registered.', 'danger')
                return redirect(url_for('auth'))
            
            existing_user = Login.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists.', 'danger')
                return redirect(url_for('auth'))
            
            is_admin = False
            if is_admin_request:
                if admin_code == app.config['ADMIN_SECRET_CODE']:
                    is_admin = True
                else:
                    flash('Invalid Admin Code.', 'danger')
                    return redirect(url_for('auth'))

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_customer = Customer(cust_first_name=first_name, cust_last_name=last_name)
            db.session.add(new_customer)
            db.session.commit()

            new_details = CustomerDetails(email_id=email, customer_id=new_customer.customer_id)
            new_login = Login(username=username, password_hash=hashed_password, customer_id=new_customer.customer_id, is_admin=is_admin)
            db.session.add(new_details)
            db.session.add(new_login)
            db.session.commit()
            
            flash('Successfully registered! Please log in.', 'success')
            return redirect(url_for('auth'))
        
        elif 'login' in request.form:
            username = request.form['username']
            password_candidate = request.form['password']
            user_login = Login.query.filter_by(username=username).first()
            
            if user_login and bcrypt.check_password_hash(user_login.password_hash, password_candidate):
                session['logged_in'] = True
                session['username'] = username
                session['customer_id'] = user_login.customer_id
                session['is_admin'] = user_login.is_admin
                
                if user_login.is_admin:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
                return redirect(url_for('auth'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('dashboard'))

# --- Book Viewing Routes ---
@app.route('/view/<int:ebook_id>')
@login_required
def view_full_ebook(ebook_id):
    ebook = db.session.get(Ebook, ebook_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], ebook.file_path)

@app.route('/view/preview/<int:ebook_id>')
def view_preview_ebook(ebook_id):
    ebook = db.session.get(Ebook, ebook_id)
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], ebook.file_path)
    try:
        reader = PdfReader(full_path)
        writer = PdfWriter()
        num_pages = len(reader.pages)
        preview_pages = min(num_pages, 10)
        for i in range(preview_pages):
            writer.add_page(reader.pages[i])
        
        preview_buffer = BytesIO()
        writer.write(preview_buffer)
        preview_buffer.seek(0)
        
        return send_file(preview_buffer, as_attachment=False, download_name=f'preview_{ebook.file_path}', mimetype='application/pdf')
    except Exception as e:
        flash(f'Could not generate preview: {e}', 'danger')
        return redirect(url_for('dashboard'))

# --- User Submission Route ---
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        category_id = request.form.get('category_id')
        ebook_file = request.files['ebook_file']
        
        category_name = "N/A"
        if category_id:
            category = db.session.get(Category, category_id)
            if category:
                category_name = category.name

        if ebook_file and ebook_file.filename.endswith('.pdf'):
            filename = secure_filename(ebook_file.filename)
            temp_path = os.path.join(app.config['TEMP_UPLOAD_FOLDER'], filename)
            ebook_file.save(temp_path)
            
            # Updated thread creation
            thread = threading.Thread(
                target=process_submission_in_background,
                args=(app, temp_path, filename, title, author, category_name, session.get('username'))
            )
            thread.start()
            
            flash('Your book has been submitted successfully!', 'popup-success')
            return redirect(url_for('dashboard'))
        else:
            flash('Please upload a valid PDF file.', 'warning')

    categories = Category.query.order_by(Category.name).all()
    return render_template('submit.html', categories=categories)


# --- PAYMENT ROUTES ---

# Step 1: Main 'buy' route that shows payment options
@app.route('/buy/<int:ebook_id>')
@login_required
def buy_ebook(ebook_id):
    ebook = db.session.get(Ebook, ebook_id)
    if not ebook or ebook.price <= 0:
        flash('This book is not available for purchase.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Create Razorpay Order
    razorpay_order_data = None
    if razorpay_client:
        try:
            # IMPORTANT: Razorpay requires the amount in the smallest currency unit.
            # For INR, this is paise. 1 Rupee = 100 Paise.
            # So, we multiply the book's price in rupees by 100.
            # e.g., ₹10.00 becomes 1000 paise.
            amount_in_paise = int(ebook.price * 100)
            
            currency = 'INR'
            receipt = f'ebook_{ebook.ebook_id}_{session["customer_id"]}_{os.urandom(4).hex()}'
            
            order_payload = {
                'amount': amount_in_paise,
                'currency': currency,
                'receipt': receipt
            }
            razorpay_order_data = razorpay_client.order.create(order_payload)

        except Exception as e:
            print(f"[!] Razorpay Exception: {e}")
            flash('Could not connect to Razorpay. Please try again later.', 'warning')
            # Set order data to None so the checkout page doesn't break
            razorpay_order_data = None
            
    # Fetch Customer Details for Prefill
    customer = db.session.get(Customer, session['customer_id'])
    customer_details = customer.details
    customer_name = f"{customer.cust_first_name} {customer.cust_last_name}"

    return render_template(
        'checkout.html', 
        ebook=ebook,
        order=razorpay_order_data, 
        api_key=RAZORPAY_KEY_ID,
        customer_name=customer_name,
        customer_email=customer_details.email_id
    )

# Step 2: Razorpay Verification
@app.route('/payment-verification', methods=['POST'])
@login_required
def payment_verification():
    payment_data = request.form
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': payment_data['razorpay_order_id'],
            'razorpay_payment_id': payment_data['razorpay_payment_id'],
            'razorpay_signature': payment_data['razorpay_signature']
        })
        flash('Payment successful! Thank you for your purchase.', 'success')
    except razorpay.errors.SignatureVerificationError as e:
        print(f"[!] Payment Verification Failed: {e}")
        flash('Payment verification failed. Please contact support.', 'danger')
    except Exception as e:
        print(f"[!] An unexpected error occurred during verification: {e}")
        flash('An unexpected error occurred. Please contact support.', 'danger')
    return redirect(url_for('dashboard'))

# Step 3: Create Coinbase Commerce Charge
@app.route('/buy-crypto/<int:ebook_id>')
@login_required
def buy_crypto(ebook_id):
    if not coinbase_client:
        flash('Crypto payment system is currently unavailable.', 'danger')
        return redirect(url_for('dashboard'))

    ebook = db.session.get(Ebook, ebook_id)
    if not ebook:
        return redirect(url_for('dashboard'))

    try:
        charge_info = {
            "name": ebook.title,
            "description": f"Purchase of '{ebook.title}' by {session['username']}",
            "local_price": {
                "amount": f"{ebook.price:.2f}",
                "currency": "INR"
            },
            "pricing_type": "fixed_price",
            "redirect_url": url_for('dashboard', _external=True),
            "cancel_url": url_for('buy_ebook', ebook_id=ebook.ebook_id, _external=True)
        }
        charge = coinbase_client.charge.create(**charge_info)
        return redirect(charge.hosted_url)
    except Exception as e:
        print(f"[!] Coinbase Commerce Exception: {e}")
        flash('An error occurred while connecting to the crypto payment gateway.', 'danger')
        return redirect(url_for('buy_ebook', ebook_id=ebook.ebook_id))

# Step 4: Coinbase Webhook for verification (Placeholder)
@app.route('/crypto-webhook', methods=['POST'])
def crypto_webhook():
    payload = request.data.decode('utf-8')
    print("[*] Received Coinbase Webhook:", payload)
    return "Webhook received", 200


# --- Admin Routes ---
@app.route('/admin-dashboard')
@admin_required
def admin_dashboard():
    ebooks = Ebook.query.all()
    categories = Category.query.order_by(Category.name).all()
    return render_template('admin_dashboard.html', ebooks=ebooks, categories=categories)

@app.route('/admin-upload', methods=['GET', 'POST'])
@admin_required
def admin_upload():
    if request.method == 'POST':
        title = request.form['title']
        author_name = request.form['author_name']
        genre = request.form.get('genre') 
        price = request.form.get('price', 0.0)
        category_id = request.form.get('category_id')
        ebook_file = request.files['ebook_file']
        
        if not category_id:
            flash('Please select a category.', 'danger')
            return redirect(url_for('admin_upload'))

        if ebook_file and ebook_file.filename.endswith('.pdf'):
            filename = secure_filename(ebook_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            ebook_file.save(file_path)
            
            new_ebook = Ebook(title=title, author_name=author_name, genre=genre, price=float(price), file_path=filename, category_id=category_id)
            db.session.add(new_ebook)
            db.session.commit()
            
            flash(f'"{title}" has been successfully uploaded.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid file. Please upload a PDF.', 'danger')

    categories = Category.query.order_by(Category.name).all()
    return render_template('upload.html', categories=categories)

@app.route('/add-category', methods=['POST'])
@admin_required
def add_category():
    name = request.form.get('category_name')
    if name:
        new_category = Category(name=name)
        db.session.add(new_category)
        db.session.commit()
        flash(f'Category "{name}" has been added.', 'success')
    else:
        flash('Category name cannot be empty.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit-ebook/<int:ebook_id>', methods=['GET', 'POST'])
@admin_required
def edit_ebook(ebook_id):
    ebook_to_edit = db.session.get(Ebook, ebook_id)
    categories = Category.query.order_by(Category.name).all()
    if request.method == 'POST':
        ebook_to_edit.title = request.form['title']
        ebook_to_edit.author_name = request.form['author_name']
        ebook_to_edit.genre = request.form.get('genre')
        ebook_to_edit.price = float(request.form.get('price', 0.0))
        ebook_to_edit.category_id = request.form.get('category_id')
        db.session.commit()
        flash(f'"{ebook_to_edit.title}" has been updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_ebook.html', ebook=ebook_to_edit, categories=categories)

@app.route('/delete-ebook/<int:ebook_id>', methods=['POST'])
@admin_required
def delete_ebook(ebook_id):
    ebook_to_delete = db.session.get(Ebook, ebook_id)
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], ebook_to_delete.file_path)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(ebook_to_delete)
        db.session.commit()
        flash(f'"{ebook_to_delete.title}" has been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting book: {e}', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete-category/<int:category_id>', methods=['POST'])
@admin_required
def delete_category(category_id):
    category_to_delete = db.session.get(Category, category_id)
    if not category_to_delete:
        flash('Category not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Optional safety check: Ensure no ebooks are using this category
    ebooks_in_category = Ebook.query.filter_by(category_id=category_id).count()
    if ebooks_in_category > 0:
        flash('Cannot delete category — there are eBooks assigned to it.', 'warning')
        return redirect(url_for('admin_dashboard'))

    try:
        db.session.delete(category_to_delete)
        db.session.commit()
        flash(f'Category "{category_to_delete.name}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting category: {e}', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message_body = request.form['message']

        try:
            msg = Message(
                subject=f"[Support] {subject}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[app.config['MAIL_USERNAME']]
            )
            msg.body = f"""
New Support Message from {email}

Subject: {subject}

Message:
{message_body}
"""
            mail.send(msg)
            flash('Your message has been sent successfully! Our support team will contact you soon.', 'success')
        except Exception as e:
            flash(f'Error sending message: {e}', 'error')

        return redirect(url_for('contact'))

    return render_template('contact.html')



if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        if not os.path.exists(app.config['TEMP_UPLOAD_FOLDER']):
            os.makedirs(app.config['TEMP_UPLOAD_FOLDER'])
        db.create_all()
    app.run(debug=True)


