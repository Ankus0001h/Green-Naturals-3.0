# 🌿 GreenNaturals - Premium E-Commerce Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.0-green.svg)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-MongoDB%20Atlas-47A248.svg)](https://www.mongodb.com/cloud/atlas)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](#license)

**GreenNaturals** is a modern, high-performance full-stack e-commerce web application tailored for organic, natural wellness products. Built with **Flask** and **MongoDB Atlas**, it features multi-gateway payment processing, WhatsApp & SMS OTP verification, Google OAuth 2.0 authentication, dynamic PDF invoice generation, and a powerful admin management dashboard.

---

## ✨ Features

### 🛒 Customer Storefront
* **Interactive Shopping Experience**: Dynamic product catalog with category filtering, size/weight variants, ratings, and customer reviews.
* **Smart Shopping Cart**: Real-time quantity adjustments, coupon discounts, dynamic shipping calculation, and instant subtotal updates.
* **Multi-Gateway Checkout**: Seamless payment processing supporting **Razorpay**, **Paytm**, and **Cash on Delivery (COD)**.
* **Order History & Live Tracking**: Real-time order progress tracking (Processing, Shipped, Out for Delivery, Delivered) with automated SMS/Email notifications.
* **PDF Invoice Downloads**: Instant generation and download of branded PDF tax invoices powered by `xhtml2pdf` and `ReportLab`.
* **Returns & Refunds System**: User-initiated return requests with status updates and admin approval workflow.
* **Wellness Guide & Content**: Integrated blog, FAQ, About Us, Contact, Privacy Policy, and Terms of Service.

### 🔐 Authentication & Security
* **Google OAuth 2.0 Integration**: One-click social authentication via Google.
* **OTP Phone/Email Verification**: Passwordless & 2FA login/signup with WhatsApp OTP (**Green API**), SMS (**MSG91 / Twilio**), and transactional email (**Brevo**).
* **Security Audit Logging**: User login session recording with IP address detection, Geolocation tracking, and User-Agent device parsing.
* **Console Compatibility**: Cross-platform console logging with Unicode/emoji protection (`safe_print`, `safe_str`) for Windows environments.

### 📊 Admin Control Panel
* **Executive Dashboard**: Key performance metrics including total revenue, order count, active users, and recent sales trends.
* **Product & Stock Management**: Add, update, and manage products with media uploads hosted directly on **Cloudinary CDN**.
* **Order Processing**: Detailed order management overview with status mutation, shipping updates, and refund processing.
* **Return Management**: Review and authorize customer return requests.

---

## 🛠️ Technology Stack

| Category | Technology / Library |
| :--- | :--- |
| **Backend Framework** | [Flask 3.0](https://flask.palletsprojects.com/) (Python) |
| **Database** | [MongoDB Atlas](https://www.mongodb.com/) via `pymongo` |
| **Frontend** | HTML5, Jinja2 Templates, [TailwindCSS](https://tailwindcss.com/), JavaScript (ES6) |
| **Authentication** | Authlib (Google OAuth 2.0), Werkzeug, PyCryptodome |
| **Cloud Storage** | [Cloudinary API](https://cloudinary.com/) (Product Images & Media) |
| **Payments** | [Razorpay](https://razorpay.com/), [Paytm Merchant SDK](https://developer.paytm.com/) |
| **Communications** | Brevo (Transactional Email), Green API (WhatsApp OTP), MSG91 / Twilio |
| **PDF Generation** | `xhtml2pdf`, `ReportLab`, `Pillow` |
| **Environment & Config**| `python-dotenv`, `dnspython` |

---

## 📁 Directory Structure

```text
GreenNaturals/
├── app.py                  # Main Flask application & route handlers
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables configuration (ignored in Git)
├── robots.txt              # Search engine crawler instructions
├── sitemap.xml             # SEO Sitemap
├── TODO.md                 # Project updates and feature task list
├── static/                 # Static assets (CSS, JS, images, logos)
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Main layout blueprint
│   ├── index.html          # Homepage
│   ├── product_details.html# Product detail view
│   ├── cart.html           # Cart page
│   ├── checkout.html       # Checkout & payment page
│   ├── profile.html        # User account & security dashboard
│   ├── my_orders.html      # Order history & tracking
│   ├── invoice.html        # PDF invoice template
│   ├── admin_base.html     # Admin layout
│   ├── admin_dashboard.html# Admin metrics & analytics
│   └── admin/              # Detailed admin operational views
└── venv/                   # Python virtual environment
```

---

## 🚀 Getting Started

### Prerequisites
* **Python 3.10+** installed on your system.
* **MongoDB Atlas** cluster or a local MongoDB database instance.

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/GreenNaturals.git
   cd GreenNaturals
   ```

2. **Create and Activate Virtual Environment**:
   * **Windows**:
     ```powershell
     python -m venv venv
     .\venv\Scripts\activate
     ```
   * **macOS / Linux**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**:
   Create a `.env` file in the root directory and add your credentials:
   ```env
   SECRET_KEY=your_flask_secret_key
   MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/<dbname>

   # Google OAuth
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret

   # Cloudinary
   CLOUDINARY_CLOUD_NAME=your_cloud_name
   CLOUDINARY_API_KEY=your_api_key
   CLOUDINARY_API_SECRET=your_api_secret

   # Razorpay & Paytm
   RAZORPAY_KEY_ID=your_razorpay_key_id
   RAZORPAY_KEY_SECRET=your_razorpay_key_secret
   RAZORPAY_MODE=live # or test

   PAYTM_MERCHANT_ID=your_paytm_mid
   PAYTM_MERCHANT_KEY=your_paytm_key
   PAYTM_WEBSITE=WEBSTAGING
   PAYTM_MODE=TEST

   # Communications (WhatsApp & Email)
   GREEN_API_ID_INSTANCE=your_green_api_instance_id
   GREEN_API_TOKEN_INSTANCE=your_green_api_token
   BREVO_API_KEY=your_brevo_api_key
   SENDER_EMAIL=noreply@greennaturals.store
   ADMIN_GMAIL=admin@greennaturals.store
   ```

5. **Run the Application**:
   ```bash
   python app.py
   ```

   The app will run locally at `http://127.0.0.1:5000` (or configured port).

---

## 🔒 Security & Best Practices

* Never commit the `.env` file containing sensitive credentials to public version control.
* Use environment-specific variables for `SECRET_KEY`, Database URIs, and API tokens.
* Payment gateway integrations use secure signature validation (`razorpay` HMAC verification, `paytmchecksum`).

---

## 📄 License

This project is licensed under the **MIT License**.

---

Designed & Developed for **GreenNaturals** 🌿
