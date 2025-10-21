# eBook Library - Flask Web Application 📚

A full-stack web application for managing and accessing an online ebook library, built with Python (Flask), MySQL, and AWS S3. Features user authentication, distinct admin/user roles, PDF previews, AI-powered submission analysis, and multiple payment options.

---

## ✨ Live Demo

Check out the live deployed version: **[https://ebook-library-ml2r.onrender.com](https://ebook-library-ml2r.onrender.com)**

---

## 🚀 Features

* **User Authentication:** Secure signup and login for users and administrators (with a secret admin code).
* **Admin Dashboard:** Full CRUD (Create, Read, Update, Delete) operations for ebooks and categories.
* **User Dashboard:** Browse, search (live search!), and filter the ebook collection by category.
* **PDF Handling:**
    * Upload ebooks (PDF only).
    * Generate PDF previews (first 10 pages) for non-logged-in users.
    * Read full PDFs online (for logged-in users).
    * Download free ebooks.
* **Cloud Storage Integration:** Uses **AWS S3** for storing and serving ebook files securely and efficiently.
* **AI-Powered Submission Review:**
    * Users can submit books for inclusion.
    * Submissions are analyzed using **Google Gemini AI** for a summary and authenticity assessment.
    * Integration with **Google Books API** for additional verification.
    * Automated addition to the library if verification passes, otherwise flagged for admin review.
    * Admin receives email notifications with AI reports.
* **Payment Integration:**
    * Supports purchasing ebooks using **Razorpay** (Cards, UPI, etc. for INR).
    * Supports purchasing ebooks using **Cryptocurrency** via **Coinbase Commerce**.
* **Contact Form:** Allows logged-in users to send support messages via email.

---

## 🛠️ Technology Stack

* **Backend:** Python 3, Flask
* **Database:** MySQL (Deployed using TiDB Cloud)
* **ORM:** Flask-SQLAlchemy, Flask-Migrate
* **Authentication:** Flask-Bcrypt
* **File Storage:** AWS S3 (using `boto3`)
* **PDF Processing:** PyPDF2
* **AI Integration:** Google Generative AI (Gemini Pro)
* **Payment Gateways:** Razorpay, Coinbase Commerce
* **Email:** Flask-Mail (using Gmail SMTP)
* **Environment Variables:** python-dotenv
* **Deployment:** Render (using Gunicorn)
* **Frontend:** HTML, CSS, Vanilla JavaScript

---

## ⚙️ Local Setup Instructions

Follow these steps to run the project on your local machine:

1.  **Prerequisites:**
    * Python 3.9+ installed.
    * Git installed.
    * A local MySQL server installed and running.

2.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/Debmalya727/ebook-library.git](https://github.com/Debmalya727/ebook-library.git)
    cd ebook-library
    ```

3.  **Create and Activate Virtual Environment:**
    ```bash
    # Create a virtual environment
    python -m venv .venv 
    # Activate it (Windows PowerShell)
    .\.venv\Scripts\Activate
    # (Use 'source .venv/bin/activate' on Linux/macOS)
    ```

4.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Set Up Local Database:**
    * Connect to your local MySQL server.
    * Create a database for the project (e.g., `ebook_management`).

6.  **Configure Environment Variables:**
    * Create a file named `.env` in the project root directory.
    * Copy the following variables into it and **fill in your actual credentials**. Use your **local database** details here, not your TiDB Cloud ones.

        ```env
        # --- Flask App ---
        SECRET_KEY='generate_a_strong_random_key_here' # Use e.g., python -c 'import secrets; print(secrets.token_hex(24))'
        ADMIN_SECRET_CODE='your_chosen_admin_signup_code' 

        # --- Local Database ---
        DATABASE_URI='mysql+pymysql://YOUR_LOCAL_MYSQL_USER:YOUR_LOCAL_MYSQL_PASSWORD@localhost/ebook_management'

        # --- Gmail (use a 16-digit App Password) ---
        MAIL_SERVER='smtp.gmail.com'
        MAIL_PORT=587
        MAIL_USE_TLS=True
        MAIL_USERNAME='your_gmail_address@gmail.com'
        MAIL_PASSWORD='your_16_digit_gmail_app_password'

        # --- API Keys ---
        GOOGLE_API_KEY='your_google_ai_api_key'

        # --- AWS S3 ---
        AWS_ACCESS_KEY_ID=your_aws_access_key_id
        AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
        AWS_BUCKET_NAME=your_s3_bucket_name 
        AWS_REGION=your_s3_bucket_region 

        # --- Payment Keys (Use Test Keys for local development) ---
        RAZORPAY_KEY_ID='your_razorpay_test_key_id'
        RAZORPAY_KEY_SECRET='your_razorpay_test_key_secret'
        COINBASE_COMMERCE_API_KEY='your_coinbase_commerce_api_key'
        ```

7.  **Initialize Database Tables:**
    * Make sure your virtual environment is active.
    * Run the Flask app once; the `db.create_all()` command in the `if __name__ == '__main__':` block (for local setup) should create the tables. Alternatively, you can run:
        ```bash
        flask shell
        ```
        Then inside the Python shell:
        ```python
        from app import db
        db.create_all()
        exit()
        ```

8.  **Run the Application:**
    ```bash
    python app.py
    ```
    The application should now be running locally at `http://127.0.0.1:5000`.

---

## 📖 Usage

* **Users:** Can sign up, log in, browse books, search/filter, preview free/paid books, read purchased/free books online, download free books, and purchase paid books via Razorpay or Crypto. Users can also submit books for review and contact support.
* **Administrators:** Sign up using the `ADMIN_SECRET_CODE`. Can access the `/admin-dashboard` to upload new books, manage categories (add/delete), and edit or delete existing books. They receive email notifications for user submissions.

---



## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
