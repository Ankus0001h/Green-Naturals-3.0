import os
import threading
import sys
import re
import warnings

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response, make_response

# Authlib 1.7.0 internally calls simplefilter("always") during its own import,
# which overrides any pre-set warning filters. The only reliable way to suppress
# the "authlib.jose is deprecated" warning is to temporarily intercept warnings.warn.
_original_warn = warnings.warn
def _suppress_authlib_jose_warn(message, *args, **kwargs):
    if 'authlib.jose' in str(message):
        return
    _original_warn(message, *args, **kwargs)
warnings.warn = _suppress_authlib_jose_warn
from authlib.integrations.flask_client import OAuth
warnings.warn = _original_warn  # restore immediately
from pymongo import MongoClient
from dotenv import load_dotenv
import requests
import cloudinary
import cloudinary.uploader
from bson import ObjectId

import random
import json

from flask import session, redirect, url_for, flash
from datetime import timedelta
from datetime import datetime, timezone
import time
import razorpay
import io
from xhtml2pdf import pisa

# 🔧 UTF-8 FIX for Windows Charmap Error
if sys.platform.startswith('win'):
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

def safe_print(msg):
    """Safe print that strips emojis for Windows console"""
    if isinstance(msg, Exception):
        msg = safe_str(msg)
    # Replace common emojis with text equivalents
    emoji_replacements = {
        '📧': '[Email]', '🔔': '[Bell]', '✅': '[OK]', '❌': '[Error]',
        '🚀': '[Rocket]', '🔴': '[Red]', '⚙️': '[Gear]', '🚨': '[Alert]',
        '\U0001f4e7': '[Email]', '\U0001f514': '[Bell]'  # Unicode escapes
    }
    clean_msg = msg
    for emoji, replacement in emoji_replacements.items():
        clean_msg = clean_msg.replace(emoji, replacement)
    print(clean_msg)

def safe_str(obj):
    """Safe str() that handles Unicode errors"""
    try:
        return str(obj)
    except UnicodeEncodeError:
        return str(obj, errors='replace').encode('ascii', 'replace').decode('ascii')

def record_user_login(user_id):
    """Records security-related login information for a user."""
    try:
        # 1. Get IP Address (Vercel/Proxy friendly)
        ip = request.headers.get('X-Forwarded-For') or \
             request.headers.get('X-Real-IP') or \
             request.remote_addr
             
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        
        # 2. Get Geolocation (Vercel Headers -> Fallback API)
        import urllib.parse
        import requests
        
        city = urllib.parse.unquote(request.headers.get('x-vercel-ip-city', ''))
        country = request.headers.get('x-vercel-ip-country', '')
        
        # Fallback if Vercel headers are missing (e.g., local test or proxy issues)
        if not city or city == 'Unknown City':
            if ip in ['127.0.0.1', 'localhost', '::1']:
                city, country = "Local Dev", "IN"
            else:
                try:
                    # Use a fast public API for fallback
                    geo_resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
                    if geo_resp.get('status') == 'success':
                        city = geo_resp.get('city', 'Unknown City')
                        country = geo_resp.get('countryCode', 'IN')
                except:
                    city, country = "Global", "IN"

        final_location = f"{city}, {country}"
        
        # 3. Get Device/UA and Parse it
        ua_string = request.headers.get('User-Agent', 'Unknown Device')
        device_info = "Unknown Device"
        
        # Simple Parser for common devices
        if 'Windows' in ua_string: device_info = "Windows PC"
        elif 'iPhone' in ua_string: device_info = "iPhone"
        elif 'iPad' in ua_string: device_info = "iPad"
        elif 'Android' in ua_string: device_info = "Android Mobile"
        elif 'Macintosh' in ua_string: device_info = "MacBook/Mac"
        elif 'Linux' in ua_string: device_info = "Linux System"
        
        # Browser detection
        browser = "Browser"
        if 'Chrome' in ua_string: browser = "Chrome"
        elif 'Firefox' in ua_string: browser = "Firefox"
        elif 'Safari' in ua_string and 'Chrome' not in ua_string: browser = "Safari"
        elif 'Edge' in ua_string: browser = "Edge"
        
        final_device = f"{device_info} • {browser}"
        
        login_entry = {
            "timestamp": datetime.now(timezone.utc),
            "ip": ip,
            "location": final_location,
            "device": final_device,
            "raw_ua": ua_string, # Keep raw for deep audit if needed
            "date_ist": (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).strftime("%d %b %Y, %I:%M %p")
        }
        
        # Update user doc
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {"last_login": login_entry},
                "$push": {
                    "login_history": {
                        "$each": [login_entry],
                        "$slice": -10
                    }
                }
            }
        )
        
        # 4. Send Security Alert Email
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user and user.get('email'):
            alert_html = f"""
            <div style="font-family: 'Inter', system-ui, sans-serif; max-width: 500px; margin: auto; border: 1px solid #f1f5f9; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.05);">
                <div style="background: #0f172a; padding: 30px; text-align: center; color: white;">
                    <div style="font-size: 32px; margin-bottom: 15px;">🛡️</div>
                    <h2 style="margin: 0; font-size: 20px; font-weight: 800;">New Login Detected</h2>
                    <p style="margin: 5px 0 0; opacity: 0.7; font-size: 13px;">Security Notification from Green Naturals</p>
                </div>
                
                <div style="padding: 30px; background: white;">
                    <p style="font-size: 14px; color: #64748b; margin-top: 0;">Hi {user.get('username', 'User')},</p>
                    <p style="font-size: 14px; color: #1e293b; line-height: 1.6;">A new login was detected on your Green Naturals account. If this was you, you can safely ignore this email.</p>
                    
                    <div style="margin: 25px 0; padding: 20px; background: #f8fafc; border-radius: 12px; border: 1px solid #f1f5f9;">
                        <table style="width: 100%; font-size: 13px; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px 0; color: #64748b; font-weight: 600; width: 100px;">Location</td>
                                <td style="padding: 8px 0; color: #0f172a; font-weight: 700;">{final_location}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: #64748b; font-weight: 600;">Device</td>
                                <td style="padding: 8px 0; color: #0f172a; font-weight: 700;">{final_device}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: #64748b; font-weight: 600;">IP Address</td>
                                <td style="padding: 8px 0; color: #0f172a; font-weight: 700; font-family: monospace;">{ip}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: #64748b; font-weight: 600;">Time (IST)</td>
                                <td style="padding: 8px 0; color: #0f172a; font-weight: 700;">{login_entry['date_ist']}</td>
                            </tr>
                        </table>
                    </div>

                    <p style="font-size: 12px; color: #ef4444; background: #fef2f2; padding: 12px; border-radius: 8px; border: 1px solid #fee2e2; margin-bottom: 25px;">
                        <strong>Security Tip:</strong> If you did not recognize this activity, please reset your password immediately and logout from all devices.
                    </p>

                    <div style="text-align: center;">
                        <a href="https://greennaturals.store/profile" style="background: #0f172a; color: white; padding: 12px 25px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px; display: inline-block;">Manage Account Security</a>
                    </div>
                </div>
                
                <div style="background: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #f1f5f9;">
                    <p style="margin: 0; font-size: 11px; color: #94a3b8;">&copy; 2026 Green Naturals. All rights reserved.</p>
                </div>
            </div>
            """
            
            # Send async
            from threading import Thread
            sender_email_fixed = os.getenv("SENDER_EMAIL", "noreply@greennaturals.store")
            def send_login_alert():
                try:
                    send_email(
                        subject="Security Alert: New Login Detected",
                        html_content=alert_html,
                        to_email=user['email'],
                        to_name=user.get('username', 'User'),
                        sender_email=sender_email_fixed,
                        sender_name="Green Naturals Security"
                    )
                except Exception as e:
                    safe_print(f"❌ [LOGIN ALERT ERROR] {e}")
            
            Thread(target=send_login_alert).start()
            
    except Exception as e:
        safe_print(f"❌ [LOGIN LOG ERROR] {e}")

def log_otp(identifier, otp_type, otp_code=None):
    """Central helper to log all OTP attempts for admin visibility."""
    try:
        now_utc = datetime.now(timezone.utc)
        ist_date = (now_utc + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d")
        otp_logs.insert_one({
            "identifier": identifier,
            "type": otp_type,
            "otp_code": otp_code,
            "status": "sent", # Default status
            "timestamp": now_utc,
            "date": ist_date
        })
    except Exception as e:
        safe_print(f"❌ [OTP LOG ERROR] {e}")



def mark_otp_success(identifier):
    """Marks the most recent OTP for an identifier as verified."""
    try:
        # Find the most recent 'sent' OTP for this identifier and mark it verified
        otp_logs.update_one(
            {"identifier": identifier, "status": "sent"},
            {"$set": {"status": "verified", "verified_at": datetime.now(timezone.utc)}},
            sort=[("timestamp", -1)]
        )
    except Exception as e:
        safe_print(f"❌ [OTP MARK ERROR] {e}")

# .env file se configurations load karne ke liye
load_dotenv()

# --- DEVELOPMENT ONLY: Allow Insecure OAuth (HTTP) ---
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

# --- Admin Credentials from .env -12--
ADMIN_GMAIL = os.getenv("ADMIN_GMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

app.secret_key = os.getenv("SECRET_KEY", "GreenVeda_Super_Secret_2026")
# Admin session 30 minutes tak valid rahega
app.permanent_session_lifetime = timedelta(days=90)

# --- 1. MongoDB Setup ---
# Database connection string .env se uthayi gayi hai
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client['GreenVedaNaturals']
products_collection = db['products']
coupons_collection = db['coupons']
contact_messages_collection = db['contact_messages']
settings_collection = db['settings']
users_collection = db['users']
orders_collection = db['orders']
subscribers_collection = db['subscribers']
returns_collection = db['return_requests']
otp_logs = db['otp_logs']
analytics = db['analytics']

def track_visitor():
    """Tracks page hits with high accuracy (Session-based, Admin excluded, Bot filtered)."""
    # 1. Exclude static, API, and Admin activity
    if any(request.path.startswith(p) for p in ['/static', '/api', '/admin', '/favicon.ico']):
        return
    if session.get('logged_in'): # Admin logged in
        return
        
    # 2. Simple Bot Filtering
    ua = request.headers.get('User-Agent', '').lower()
    bots = ['bot', 'crawler', 'spider', 'slurp', 'googlebot', 'bingbot', 'yandex']
    if any(b in ua for b in bots):
        return

    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        now = datetime.now(timezone.utc)
        ist_now = now + timedelta(hours=5, minutes=30)
        today_str = ist_now.strftime("%Y-%m-%d")
        
        # 3. Session-based deduplication (Prevent reload inflation)
        # Only increment if this session hasn't hit this path in the last 30 mins
        session_key = f"hit_{request.path}"
        last_hit = session.get(session_key)
        
        should_increment = True
        if last_hit:
            last_hit_time = datetime.fromisoformat(last_hit)
            if (now - last_hit_time).total_seconds() < 1800: # 30 mins
                should_increment = False

        if should_increment:
            # Update last hit in session
            session[session_key] = now.isoformat()
            
            # Update Traffic Stats
            analytics.update_one(
                {"type": "traffic_stats", "date": today_str},
                {"$inc": {"hits": 1}, "$setOnInsert": {"unique_ips": []}},
                upsert=True
            )
            
            # Unique Visitors (Daily)
            analytics.update_one(
                {"type": "traffic_stats", "date": today_str},
                {"$addToSet": {"unique_ips": ip}}
            )
        
        # 4. Live Presence (Always update timestamp for 'Live' accuracy)
        analytics.update_one(
            {"type": "live_users", "ip": ip},
            {"$set": {"last_active": now}},
            upsert=True
        )
    except Exception as e:
        pass 

@app.before_request
def before_request_logic():
    track_visitor()

# --- Ensure Unique Indexes (No Duplicate Accounts) ---
users_collection.create_index("email", unique=True)
users_collection.create_index("phone", unique=True)

@app.context_processor
def inject_global_settings():
    """Makes WhatsApp number, Support Email and other settings available to all templates globally."""
    support_setting = settings_collection.find_one({"key": "support_whatsapp"})
    email_setting = settings_collection.find_one({"key": "support_email"})
    
    # Offer Banner Settings
    banner_tag = settings_collection.find_one({"key": "banner_tag"})
    banner_title = settings_collection.find_one({"key": "banner_title"})
    banner_desc = settings_collection.find_one({"key": "banner_desc"})
    
    # Global Products for SEO indexing
    all_products_seo = list(db.products.find({}, {"name": 1, "category": 1, "_id": 0}))
    
    # Smart Avatar Helper
    def get_avatar(username, profile_image=None):
        if profile_image and "api.dicebear.com" not in profile_image:
            return profile_image
            
        if not username:
            return "https://api.dicebear.com/7.x/avataaars/svg?seed=guest&backgroundColor=b6e3f4"
            
        import urllib.parse
        safe_name = urllib.parse.quote(username.strip())
        first_name = username.split(' ')[0].lower()
        
        # Super-fast offline heuristic (0ms latency)
        female_endings = ('a', 'i', 'ee', 'ya', 'ha', 'ta', 'ti', 'u', 'y')
        exceptions_male = (
            'aditya', 'krishna', 'shiva', 'surya', 'rishi', 'ravi', 'hari', 
            'raju', 'sanjay', 'vijay', 'ajay', 'pranay', 'abhay', 'jay', 
            'sacha', 'sachin', 'arya', 'baba', 'raja', 'rana', 'sharma', 
            'gupta', 'mishra', 'shukla', 'verma', 'yadav', 'jha', 'bhatia', 'kumar', 'singh'
        )
        
        if first_name in exceptions_male:
            gender = 'boy'
        elif first_name.endswith(female_endings):
            gender = 'girl'
        else:
            gender = 'boy'
            
        # Bulletproof Global CDN (Dicebear Micah) - Zero Parameters to Prevent 400 Errors
        # We use pre-verified seeds that strictly look like beautiful Boy/Girl 3D avatars
        
        current_month = datetime.now().month # 1 to 12
        name_len = len(safe_name)
        index = (name_len + current_month) % 5
        
        boy_seeds = ["Felix", "Oliver", "Jack", "Leo", "Max"]
        girl_seeds = ["Mia", "Sophia", "Lily", "Chloe", "Zoe"]
        
        if gender == 'girl':
            chosen_seed = girl_seeds[index]
            return f"https://api.dicebear.com/9.x/micah/svg?seed={chosen_seed}&backgroundColor=ffdfbf,ffd5dc,d1d4f9"
        else:
            chosen_seed = boy_seeds[index]
            return f"https://api.dicebear.com/9.x/micah/svg?seed={chosen_seed}&backgroundColor=b6e3f4,c0aede,d1d4f9"
    
    return {
        "whatsapp_num": support_setting['value'] if support_setting else "919876543210",
        "support_email": email_setting['value'] if email_setting else "support@greennaturals.store",
        "banner_tag": banner_tag['value'] if banner_tag else "Exclusive Offers",
        "banner_title": banner_title['value'] if banner_title else "Get 20% Off On Your Order",
        "banner_desc": banner_desc['value'] if banner_desc else "Join thousands who trust Green Naturals for their daily Ayurvedic wellness routine.",
        "all_products_seo": all_products_seo,
        "get_avatar": get_avatar
    }

# --- 2. Green API Setup (WhatsApp OTP Verification) ---
GREEN_API_ID_INSTANCE = os.getenv("GREEN_API_ID_INSTANCE", "710722702487")
GREEN_API_TOKEN_INSTANCE = os.getenv("GREEN_API_TOKEN_INSTANCE", "3a479b7c1a2c49c495cd0d43251928598b35370b377e4c4ebf")

def get_whatsapp_chat_id(phone):
    digits = re.sub(r'\D', '', str(phone))
    if len(digits) == 10:
        digits = f"91{digits}"
    return f"{digits}@c.us"

def send_green_api_otp(phone, otp_type="login_sms"):
    """Generates a 6-digit OTP and sends it via Green API WhatsApp."""
    otp_code = str(random.randint(100000, 999999))
    chat_id = get_whatsapp_chat_id(phone)
    
    id_inst = os.getenv("GREEN_API_ID_INSTANCE", "710722702487")
    token_inst = os.getenv("GREEN_API_TOKEN_INSTANCE", "3a479b7c1a2c49c495cd0d43251928598b35370b377e4c4ebf")
    
    url = f"https://api.green-api.com/waInstance{id_inst}/sendMessage/{token_inst}"
    message = (
        f"🌿 *Green Naturals Verification Code*\n\n"
        f"Your OTP code is: *{otp_code}*\n\n"
        f"This code is valid for 10 minutes. Please do not share this code with anyone."
    )
    
    payload = {
        "chatId": chat_id,
        "message": message
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        res_data = response.json()
        safe_print(f"📲 [GREEN API RESP] {response.status_code} - {res_data}")
        
        if response.status_code == 200 and ("idMessage" in res_data or res_data.get("idMessage")):
            clean_phone = re.sub(r'\D', '', str(phone))
            session[f"otp_{clean_phone}"] = {
                "code": otp_code,
                "created_at": time.time(),
                "attempts": 0
            }
            log_otp(phone, otp_type, otp_code)
            return True, "Verification code sent successfully via WhatsApp!"
        else:
            err = res_data.get("message") or res_data.get("error") or "Failed to send WhatsApp message."
            return False, f"WhatsApp Delivery Failed: {err}"
    except Exception as e:
        safe_print(f"❌ [GREEN API ERROR] {e}")
        return False, "Failed to send OTP via WhatsApp. Please try again."

def verify_green_api_otp(phone, otp_entered):
    """Verifies the OTP code entered by user against session storage."""
    if not phone or not otp_entered:
        return False, "Phone number and OTP code are required."
        
    clean_phone = re.sub(r'\D', '', str(phone))
    otp_data = session.get(f"otp_{clean_phone}")
    
    if not otp_data:
        return False, "OTP session expired or not found. Please request a new OTP."
        
    # Check 10-minute expiry (600 seconds)
    if time.time() - otp_data.get("created_at", 0) > 600:
        session.pop(f"otp_{clean_phone}", None)
        return False, "OTP code has expired. Please request a new one."
        
    if str(otp_data.get("code")).strip() == str(otp_entered).strip():
        session.pop(f"otp_{clean_phone}", None)
        mark_otp_success(phone)
        return True, "Verification successful!"
    else:
        attempts = otp_data.get("attempts", 0) + 1
        if attempts >= 5:
            session.pop(f"otp_{clean_phone}", None)
            return False, "Maximum attempts exceeded. Please request a new OTP."
        otp_data["attempts"] = attempts
        session[f"otp_{clean_phone}"] = otp_data
        return False, "Invalid OTP code. Please try again."

def handle_twilio_error(e):
    return str(e)

# --- 3. Cloudinary Setup (Image Hosting) ---
# Herbal products ki photos upload karne ke liye configuration
cloudinary.config( 
    cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME"), 
    api_key = os.getenv("CLOUDINARY_API_KEY"), 
    api_secret = os.getenv("CLOUDINARY_API_SECRET"),
    secure = True
)

# --- 4. Google OAuth Setup ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- 4. Razorpay Setup ---
razorpay_client = razorpay.Client(auth=(os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET")))
razorpay_mode = os.getenv("RAZORPAY_MODE", "test")

# --- 4. Standard SMTP Setup (Email Service) ---
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from email.mime.base import MIMEBase
from email import encoders


def send_email(subject, html_content, to_email, to_name, sender_email, sender_name="Green Naturals", attachment_data=None, attachment_filename=None):
    """
    Enhanced common email function with attachment support.
    Uses Brevo SMTP Relay.
    """
    smtp_server = "smtp-relay.brevo.com"
    smtp_port = 587
    smtp_login = "9ac783001@smtp-brevo.com"
    smtp_password = os.getenv("BREVO_SMTP_PASSWORD") or os.getenv("BREVO_API_KEY") 

    msg = MIMEMultipart("mixed") # Changed to mixed to support attachments
    msg['Subject'] = subject
    msg['From'] = f"{sender_name} <{sender_email}>"
    msg['To'] = f"{to_name} <{to_email}>"

    # Attach HTML Content
    msg_body = MIMEMultipart("alternative")
    msg_body.attach(MIMEText(html_content, 'html'))
    msg.attach(msg_body)

    # Attach File if provided
    if attachment_data and attachment_filename:
        safe_print(f"[DEBUG] Attaching file {attachment_filename} ({len(attachment_data)} bytes)")
        part = MIMEBase('application', "octet-stream")
        part.set_payload(attachment_data)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{attachment_filename}"')
        msg.attach(part)
    else:
        safe_print(f"[DEBUG] No attachment provided for email to {to_email}")

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_login, smtp_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
        safe_print(f"📧 SMTP Email sent to {to_email} via {sender_email}")
        
        try:
            from datetime import datetime, timezone
            now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            db['email_tracking'].update_one(
                {"date": now_str},
                {"$inc": {"count": 1}},
                upsert=True
            )
        except Exception as e:
            safe_print(f"Failed to track email count: {e}")

        return True
    except Exception as e:
        safe_print(f"❌ SMTP Error: {str(e)}")
        return False

def generate_invoice_pdf(order_data):
    """
    Generate a PDF invoice that matches the thermal receipt design from order-success.html.
    """
    safe_print(f"[PDF] generate_invoice_pdf called for order: {order_data.get('order_id', 'UNKNOWN')}")
    try:
        # Process items
        items_html = ""
        item_subtotal = 0
        for item in order_data.get('items', []):
            qty = int(item.get('qty', item.get('quantity', 1)))
            price = float(item.get('price', 0))
            line_total = round(price * qty, 2)
            item_subtotal += line_total
            items_html += f"""
            <tr>
                <td style="padding: 4px 0; border-bottom: 1px dotted #ccc;">{item.get('name', '')}</td>
                <td style="padding: 4px 0; border-bottom: 1px dotted #ccc; text-align: center;">{qty}</td>
                <td style="padding: 4px 0; border-bottom: 1px dotted #ccc; text-align: right;">Rs. {line_total:.2f}</td>
            </tr>"""

        # Extract values
        order_id = order_data.get('order_id', '')
        total = float(order_data.get('total', 0))
        shipping = float(order_data.get('shipping', 0))
        handling = float(order_data.get('handling_fee', 0))
        round_off = float(order_data.get('round_off', 0))
        payment_mode = order_data.get('payment_mode', order_data.get('payment_method', 'N/A')).upper()
        # Date handling - convert to IST
        from datetime import timedelta
        created_at = order_data.get('created_at')
        if isinstance(created_at, datetime):
            # Convert UTC to IST (+5:30)
            created_at = created_at + timedelta(hours=5, minutes=30)
        elif not created_at:
            created_at = datetime.now() + timedelta(hours=5, minutes=30)
            
        date_str = created_at.strftime('%d %b %Y, %I:%M %p') if hasattr(created_at, 'strftime') else str(created_at)

        # Customer
        c = order_data.get('customer', {})
        cust_name = c.get('name', 'Customer').upper()
        cust_phone = c.get('phone', '')
        cust_addr = f"{c.get('address', '')}, {c.get('city', '')}, {c.get('state', '')} - {c.get('pincode', '')}"

        # Transaction details
        txn_id = order_data.get('payment_id', '')
        rzp_oid = order_data.get('razorpay_order_id', '')
        
        txn_html = ""
        if txn_id and txn_id != 'COD_ORDER':
            txn_html += f'<div style="margin-bottom: 5px;">TXN ID: <b>{txn_id}</b></div>'
        if rzp_oid:
            txn_html += f'<div style="margin-bottom: 5px;">RZP OID: <b>{rzp_oid}</b></div>'

        html_content = f"""
        <html>
        <head>
            <style>
                @page {{ size: A4; margin: 0.5cm 1cm; }}
                body {{ font-family: 'Helvetica', 'Arial', sans-serif; color: #1a1a1a; line-height: 1.2; margin: 0; padding: 0; font-size: 11px; }}
                .thermal-container {{ max-width: 420px; margin: 0 auto; }}
                .header {{ text-align: center; margin-bottom: 10px; }}
                .brand {{ font-size: 24px; font-weight: bold; text-transform: uppercase; margin-bottom: 2px; color: #000; }}
                .tagline {{ font-size: 11px; color: #555; }}
                .divider {{ border-bottom: 2px solid #000; margin: 5px 0; }}
                .dotted-divider {{ border-bottom: 1px dotted #888; margin: 5px 0; }}
                .details {{ font-size: 11px; margin-bottom: 10px; }}
                .details div {{ margin-bottom: 2px; }}
                .customer-info {{ margin-top: 5px; font-size: 12px; }}
                .items-table {{ width: 100%; border-collapse: collapse; font-size: 11px; margin: 10px 0; }}
                .totals {{ font-size: 11px; }}
                .grand-total {{ font-size: 20px; font-weight: bold; border-top: 2px solid #000; padding-top: 5px; margin-top: 5px; }}
                .footer {{ text-align: center; margin-top: 15px; font-size: 10px; }}
            </style>
        </head>
        <body>
            <div class="thermal-container">
                <div class="header">
                    <div class="brand">Green Naturals</div>
                    <div class="tagline">Premium Organic Ayurvedic Store</div>
                </div>

                <div class="divider"></div>

                <div class="details">
                    <div style="font-size: 18px;">ORDER ID: <b>#{order_id}</b></div>
                    <div>DATE: <b>{date_str}</b></div>
                    <div>PAYMENT: <b>{payment_mode}</b></div>
                    {txn_html}
                </div>

                <div class="dotted-divider"></div>

                <div class="customer-info">
                    <div style="font-size: 20px; font-weight: bold; margin-bottom: 5px;">{cust_name}</div>
                    <div>Phone: {cust_phone}</div>
                    <div>Address: {cust_addr}</div>
                </div>

                <div class="divider"></div>

                <table class="items-table">
                    <thead>
                        <tr style="border-bottom: 1px solid #000;">
                            <th style="text-align: left; padding-bottom: 10px;">ITEM</th>
                            <th style="text-align: center; padding-bottom: 10px; width: 50px;">QTY</th>
                            <th style="text-align: right; padding-bottom: 10px; width: 80px;">AMT</th>
                        </tr>
                    </thead>
                    <tbody>
                        {items_html}
                    </tbody>
                </table>

                <div class="dotted-divider"></div>

                <div class="totals">
                    <table width="100%" border="0" cellpadding="0" cellspacing="0">
                        <tr>
                            <td style="padding-bottom: 5px;">SUBTOTAL:</td>
                            <td style="text-align: right; padding-bottom: 5px;">Rs. {item_subtotal:.2f}</td>
                        </tr>
                        <tr>
                            <td style="padding-bottom: 5px;">DELIVERY:</td>
                            <td style="text-align: right; padding-bottom: 5px;">{"FREE" if shipping <= 0 else f"Rs. {shipping:.2f}"}</td>
                        </tr>
                        {" " if handling <= 0.01 else f'''
                        <tr>
                            <td style="padding-bottom: 5px;">HANDLING:</td>
                            <td style="text-align: right; padding-bottom: 5px;">Rs. {handling:.2f}</td>
                        </tr>'''}
                        {" " if abs(round_off) < 0.01 else f'''
                        <tr>
                            <td style="padding-bottom: 5px; color: #666; font-style: italic;">ROUND OFF:</td>
                            <td style="text-align: right; padding-bottom: 5px; color: #666; font-style: italic;">{"+" if round_off > 0 else "-" if round_off < 0 else ""}Rs. {abs(round_off):.2f}</td>
                        </tr>'''}
                    </table>
                    
                    <div class="grand-total">
                        <table width="100%" border="0" cellpadding="0" cellspacing="0">
                            <tr>
                                <td>TOTAL:</td>
                                <td style="text-align: right;">Rs. {total:.2f}</td>
                            </tr>
                        </table>
                    </div>
                </div>

                <div class="footer">
                    <div style="font-size: 20px; font-weight: bold; margin-bottom: 5px;">*** THANK YOU ***</div>
                    <div style="font-size: 14px;">Visit again for more Organic Goodness</div>
                    <div style="margin-top: 30px; color: #888; font-size: 10px; border-top: 1px solid #eee; padding-top: 10px;">COMPUTER GENERATED INVOICE</div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create PDF in memory
        result = io.BytesIO()
        pdf = pisa.pisaDocument(io.BytesIO(html_content.encode("UTF-8")), result)
        
        if not pdf.err:
            pdf_bytes = result.getvalue()
            result.close()
            safe_print(f"[PDF] SUCCESS - Generated {len(pdf_bytes)} bytes for order {order_data.get('order_id')}")
            return pdf_bytes
        safe_print(f"[PDF] FAILED - pisa error: {pdf.err}")
        return None
    except Exception as e:
        safe_print(f"[PDF] EXCEPTION: {str(e)}")
        import traceback
        safe_print(traceback.format_exc())
        return None

# --- ROUTES ---

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        try:
            name = request.form.get('name')
            email = request.form.get('email')
            subject = request.form.get('subject')
            message = request.form.get('message')
            
            ticket_id = f"TK-{random.randint(100000, 999999)}"
            
            # 1. Capture image bytes in main thread
            img_data = None
            img_name = None
            if 'contact_image' in request.files:
                file = request.files['contact_image']
                if file and file.filename != '':
                    img_data = file.read()
                    img_name = file.filename
            
            # 2. Save ticket to DB (immediate)
            contact_messages_collection.insert_one({
                "ticket_id": ticket_id,
                "name": name,
                "email": email,
                "subject": subject,
                "message": message,
                "image_url": None, # Will be updated in background
                "created_at": datetime.now(timezone.utc)
            })

            # 3. Background Task: Cloudinary + Order Context + Emails
            def background_process(img_bytes, filename):
                try:
                    # A. Cloudinary Upload
                    image_url = None
                    if img_bytes:
                        try:
                            import io
                            up = cloudinary.uploader.upload(io.BytesIO(img_bytes), folder="contact_inquiries")
                            image_url = up.get('secure_url')
                            contact_messages_collection.update_one({"ticket_id": ticket_id}, {"$set": {"image_url": image_url}})
                        except Exception as ce:
                            safe_print(f"Cloudinary Error: {ce}")

                    # B. Fetch Order Details for Admin Context
                    order_ctx_html = ""
                    # Look for Order IDs starting with GN- (e.g., GN-20260423-8585)
                    order_match = re.search(r'(GN-[\d-]+)', message)
                    if order_match:
                        oid = order_match.group(1).strip()
                        order = orders_collection.find_one({"order_id": oid})
                        if order:
                            # 1. Correct Field Mappings based on DB Dump
                            rows = ""
                            for item in order.get('items', []):
                                # Use 'qty' instead of 'quantity' based on dump
                                item_qty = item.get('qty', item.get('quantity', 1))
                                rows += f"<tr><td style='padding:8px;border-bottom:1px solid #eee'>{item.get('name','Product')}</td><td style='padding:8px;border-bottom:1px solid #eee;text-align:center'>{item_qty}</td><td style='padding:8px;border-bottom:1px solid #eee;text-align:right'>₹{item.get('price',0)}</td></tr>"
                            
                            # 2. Get Customer & Shipping Info
                            cust = order.get('customer', {})
                            c_name = cust.get('name', order.get('name', name))
                            c_phone = cust.get('phone', order.get('phone', 'N/A'))
                            
                            # Build detailed address
                            addr_parts = [
                                cust.get('address', ''),
                                cust.get('landmark', ''),
                                cust.get('city', ''),
                                cust.get('state', ''),
                                cust.get('pincode', '')
                            ]
                            addr_str = ", ".join([p for p in addr_parts if p])
                            
                            # 3. Format Date properly (IST +5:30)
                            o_date_raw = order.get('created_at', 'N/A')
                            ist_date_str = "N/A"
                            if isinstance(o_date_raw, datetime):
                                # Convert to IST if it's UTC or naive
                                if o_date_raw.tzinfo is None or o_date_raw.tzinfo == timezone.utc:
                                    ist_date = o_date_raw.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=5, minutes=30)))
                                else:
                                    ist_date = o_date_raw
                                ist_date_str = ist_date.strftime('%d %b %Y, %I:%M %p')
                            
                            # 4. Correct Payment & Status
                            pay_method = order.get('payment_mode', order.get('payment_method', 'N/A'))
                            
                            # Status: Priority is order_status > last tracking > status
                            # 'status' field is always 'PENDING' from checkout, never updated
                            # 'order_status' is the real admin-updated status
                            real_status = order.get('order_status', '').strip().lower()
                            
                            # Fallback: check last tracking entry
                            if not real_status:
                                tracking = order.get('tracking', [])
                                if tracking and isinstance(tracking, list):
                                    real_status = tracking[-1].get('status', '').strip().lower()
                            
                            # Final fallback: original status field
                            if not real_status:
                                real_status = order.get('status', 'pending').strip().lower()
                            
                            # Normalize for display
                            if real_status in ('pending', 'new', '', 'processing'):
                                normalized_st = 'CONFIRMED'
                            else:
                                normalized_st = real_status.upper().replace('_', ' ')

                            order_ctx_html = f"""
                            <div style='margin-top:20px; background:#f8fafc; border:1px solid #cbd5e0; border-radius:12px; padding:18px; font-family:Arial, sans-serif;'>
                                <!-- Header Section with wrapping fixed -->
                                <div style='border-bottom:2px solid #166534; padding-bottom:10px; margin-bottom:15px;'>
                                    <div style='font-size:16px; font-weight:bold; color:#166534; margin-bottom:5px;'>Order: {oid}</div>
                                    <div style='font-size:12px; color:#4a5568;'>
                                        <span style='display:inline-block; margin-right:15px;'><strong>Phone:</strong> {c_phone}</span>
                                        <span style='display:inline-block;'><strong>Date:</strong> {ist_date_str}</span>
                                    </div>
                                </div>
                                
                                <div style='margin-bottom:15px; font-size:13px;'>
                                    <strong>Customer:</strong> {c_name}
                                </div>

                                <table style='width:100%; border-collapse:collapse; font-size:12px; margin-bottom:15px;'>
                                    <thead><tr style='background:#edf2f7; color:#4a5568;'><th style='padding:8px;text-align:left;border:1px solid #e2e8f0;'>Item</th><th style='padding:8px;text-align:center;border:1px solid #e2e8f0;'>Qty</th><th style='padding:8px;text-align:right;border:1px solid #e2e8f0;'>Price</th></tr></thead>
                                    <tbody>{rows}</tbody>
                                </table>

                                <div style='background:white; border:1px solid #e2e8f0; border-radius:8px; padding:12px; font-size:12px;'>
                                    <table style='width:100%;'>
                                        <tr><td style='padding:3px 0;'><strong>Total Amount:</strong></td><td style='text-align:right; font-weight:bold;'>₹{order.get('total_amount', order.get('total', 0))}</td></tr>
                                        <tr><td style='padding:3px 0;'><strong>Payment:</strong></td><td style='text-align:right;'>{pay_method}</td></tr>
                                        <tr><td style='padding:3px 0;'><strong>Current Status:</strong></td><td style='text-align:right; color:#16a34a; font-weight:bold;'>{normalized_st}</td></tr>
                                        <tr><td colspan='2' style='padding-top:10px; border-top:1px solid #f1f5f9; font-size:11px; color:#4a5568;'>
                                            <strong>Shipping Address:</strong><br>{addr_str}
                                        </td></tr>
                                    </table>
                                </div>
                            </div>
                            """

                    # C. Admin Email
                    admin_html = f"""
                    <div style='font-family:Arial,sans-serif; max-width:600px; padding:20px; border:1px solid #eee; border-radius:15px;'>
                        <h2 style='color:#166534; text-align:center;'>New Support Request</h2>
                        <div style='background:#f0fdf4; padding:15px; border-radius:10px;'>
                            <p><strong>From:</strong> {name} ({email})</p>
                            <p><strong>Ticket:</strong> {ticket_id}</p>
                            <p><strong>Subject:</strong> {subject}</p>
                            <p><strong>Message:</strong><br>{message.replace('\\n', '<br>')}</p>
                        </div>
                        {order_ctx_html}
                        {f"<div style='margin-top:20px; text-align:center;'><a href='{image_url}' style='background:#166534; color:white; padding:10px 20px; text-decoration:none; border-radius:5px;'>View Attachment</a></div>" if image_url else ""}
                    </div>
                    """
                    send_email(f"New Ticket [{ticket_id}] - {subject}", admin_html, ADMIN_GMAIL, "Green Admin", "noreply@greennaturals.store", "GN Support", img_bytes, filename)

                    # D. User Email (Simple)
                    user_html = f"""
                    <div style='font-family:Arial,sans-serif; max-width:600px; border:1px solid #eee; border-radius:15px; overflow:hidden;'>
                        <div style='background:#166534; padding:20px; color:white; text-align:center;'>
                            <h3>We've received your request!</h3>
                            <p>Ticket ID: {ticket_id}</p>
                        </div>
                        <div style='padding:20px;'>
                            <p>Hi {name},</p>
                            <p>Thank you for contacting us regarding <strong>"{subject}"</strong>. Our team will get back to you shortly.</p>
                            <p>Team Green Naturals</p>
                        </div>
                    </div>
                    """
                    send_email(f"Ticket Received! [#{ticket_id}]", user_html, email, name, "noreply@greennaturals.store", "Green Naturals Support")
                except Exception as bge:
                    safe_print(f"🚨 Background Error: {bge}")

            threading.Thread(target=background_process, args=(img_data, img_name)).start()

            if is_ajax:
                return jsonify({"success": True, "ticket_id": ticket_id, "created_at_iso": datetime.now(timezone.utc).isoformat()})
            flash(f"Ticket {ticket_id} created!", "success")
            return redirect(url_for('contact'))
        except Exception as e:
            safe_print(f"🚨 POST Error: {e}")
            if is_ajax: return jsonify({"success": False, "message": str(e)}), 500
            return redirect(url_for('contact'))

    # Fetch user details and tickets for pre-filling/history
    user_data = None
    user_tickets = []
    if session.get('user_id'):
        uid = session.get('user_id')
        user_data = users_collection.find_one({"_id": ObjectId(uid) if ObjectId.is_valid(uid) else uid})
        if user_data:
            # Fetch last 5 tickets for the user
            user_tickets = list(contact_messages_collection.find({"email": user_data.get('email')}).sort("created_at", -1).limit(5))
            for t in user_tickets:
                t['_id'] = str(t['_id'])
                if 'created_at' in t:
                    # Explicitly ensure UTC offset for JS parsing
                    dt = t['created_at']
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    t['created_at_iso'] = dt.isoformat()
    
    # Fetch WhatsApp number from settings
    support_setting = settings_collection.find_one({"key": "support_whatsapp"})
    whatsapp_num = support_setting['value'] if support_setting else "919876543210"
    
    return render_template('contact.html', whatsapp_num=whatsapp_num, user_data=user_data, user_tickets=user_tickets)

# --- SUPPORT BOT API ---
@app.route('/api/support/orders', methods=['GET'])
def support_orders():
    if not session.get('user_id'):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Use the robust query helper to find user orders - Fetch ALL
    query = _user_order_query()
    user_orders = list(orders_collection.find(query).sort("created_at", -1))
    
    orders_data = []
    for order in user_orders:
        # Process order using safe helper
        processed = _process_safe_order(order)
        # Get first item info
        items = processed.get('items', [])
        first_item = items[0] if items else {}
        
        # Calculate total quantity across all items
        total_qty = sum(item.get('quantity', item.get('qty', 1)) for item in items)
        first_qty = items[0].get('quantity', items[0].get('qty', 1)) if items else 1
        
        orders_data.append({
            "order_id": processed.get('order_id', str(order['_id'])),
            "status": processed.get('status_label', 'Confirmed'),
            "status_class": processed.get('status_class', 'confirmed'),
            "total": processed.get('total', 0),
            "date": processed.get('created_at').strftime('%d %b, %Y'),
            "expected": processed.get('expected_delivery').strftime('%d %b'),
            "product_name": first_item.get('name', 'Ayurvedic Product'),
            "product_image": first_item.get('image', '/static/images/logo.jpg'),
            "item_count": len(items),
            "total_qty": total_qty,
            "first_qty": first_qty
        })
    
    return jsonify({"orders": orders_data})

# --- ADMIN API: SUPPORT SETTINGS ---
@app.route('/admin/api/get-support-settings', methods=['GET'])
def get_support_settings():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    
    support_setting = settings_collection.find_one({"key": "support_whatsapp"})
    email_setting = settings_collection.find_one({"key": "support_email"})
    
    # Banner settings
    banner_tag = settings_collection.find_one({"key": "banner_tag"})
    banner_title = settings_collection.find_one({"key": "banner_title"})
    banner_desc = settings_collection.find_one({"key": "banner_desc"})
    
    return jsonify({
        "whatsapp_num": support_setting['value'] if support_setting else "919876543210",
        "support_email": email_setting['value'] if email_setting else "support@greennaturals.store",
        "banner_tag": banner_tag['value'] if banner_tag else "Exclusive Offers",
        "banner_title": banner_title['value'] if banner_title else "Get 20% Off On Your Order",
        "banner_desc": banner_desc['value'] if banner_desc else "Join thousands who trust Green Naturals for their daily Ayurvedic wellness routine."
    })

@app.route('/admin/api/update-support-settings', methods=['POST'])
def update_support_settings():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    whatsapp_num = data.get('whatsapp_num', '').strip()
    support_email = data.get('support_email', '').strip()
    
    # Banner settings
    banner_tag = data.get('banner_tag', '').strip()
    banner_title = data.get('banner_title', '').strip()
    banner_desc = data.get('banner_desc', '').strip()
    
    if whatsapp_num:
        settings_collection.update_one({"key": "support_whatsapp"}, {"$set": {"value": whatsapp_num}}, upsert=True)
    
    if support_email:
        settings_collection.update_one({"key": "support_email"}, {"$set": {"value": support_email}}, upsert=True)

    if banner_tag:
        settings_collection.update_one({"key": "banner_tag"}, {"$set": {"value": banner_tag}}, upsert=True)
    
    if banner_title:
        settings_collection.update_one({"key": "banner_title"}, {"$set": {"value": banner_title}}, upsert=True)
        
    if banner_desc:
        settings_collection.update_one({"key": "banner_desc"}, {"$set": {"value": banner_desc}}, upsert=True)
        
    return jsonify({"success": True})

from flask import render_template, session # session ko import zaroor karein

from bson import ObjectId

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/returns')
def returns():
    return render_template('returns.html')

@app.route('/shipping')
def shipping():
    return render_template('shipping.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')
@app.route('/wellness-guide')
def wellness_guide():
    products = list(products_collection.find())
    return render_template('wellness_guide.html', products=products)

@app.route('/about')
def about():
    return render_template('about.html')

# --- SEO: robots.txt ---
@app.route('/robots.txt')
def robots_txt():
    content = """User-agent: *
Disallow: /admin
Disallow: /admin-login
Disallow: /admin-dashboard
Disallow: /api/
Allow: /

Sitemap: https://greennaturals.store/sitemap.xml"""
    return Response(content, mimetype='text/plain')

# --- SEO: sitemap.xml ---
@app.route('/sitemap.xml')
def sitemap_xml():
    pages = [
        {'url': '/', 'priority': '1.0', 'freq': 'daily'},
        {'url': '/about', 'priority': '0.7', 'freq': 'monthly'},
        {'url': '/contact', 'priority': '0.7', 'freq': 'monthly'},
        {'url': '/faq', 'priority': '0.5', 'freq': 'monthly'},
        {'url': '/shipping', 'priority': '0.5', 'freq': 'monthly'},
        {'url': '/returns', 'priority': '0.5', 'freq': 'monthly'},
        {'url': '/terms', 'priority': '0.3', 'freq': 'yearly'},
        {'url': '/wellness-guide', 'priority': '0.9', 'freq': 'weekly'},
    ]
    
    # Add product pages dynamically
    try:
        all_products = products_collection.find({}, {"_id": 1})
        for p in all_products:
            pages.append({'url': f'/product/{str(p["_id"])}', 'priority': '0.8', 'freq': 'weekly'})
    except: pass
    
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for page in pages:
        xml += f'  <url>\n'
        xml += f'    <loc>https://greennaturals.store{page["url"]}</loc>\n'
        xml += f'    <changefreq>{page["freq"]}</changefreq>\n'
        xml += f'    <priority>{page["priority"]}</priority>\n'
        xml += f'  </url>\n'
    xml += '</urlset>'
    
    return Response(xml, mimetype='application/xml')


@app.route('/')
@app.route('/shop')
def index():
    # 1. Database se Products fetch karna
    try:
        # Latest products fetch karein
        raw_products = list(products_collection.find().sort("_id", -1))
        
        all_products = []
        for p in raw_products:
            # MongoDB ObjectId ko String mein convert karna zaroori hai
            p['_id'] = str(p['_id'])
            
            # Slider safety: Ensure other_images hamesha ek list ho
            if 'other_images' not in p or not isinstance(p['other_images'], list):
                p['other_images'] = []
                
            all_products.append(p)
            
    except Exception as e:
        safe_print(f"❌ Product Fetch Error: {safe_str(e)}")
        all_products = []

    # 2. Authenticated User Data fetch karna
    user_data = {'is_authenticated': False}
    
    if 'user_id' in session:
        try:
            current_user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
            
            if current_user:
                user_data = {
                    'is_authenticated': True,
                    'username': current_user.get('username', 'User'),
                    'email': current_user.get('email'),
                    'phone': current_user.get('phone')
                }
            else:
                session.clear() 
        except Exception:
            user_data = {'is_authenticated': False}

    # 3. Frontend ko data pass karna
    return render_template(
        'index.html', 
        products=all_products, 
        user=user_data,
        product_count=len(all_products)
    )
    
@app.route('/product/<product_id>')
def product_detail(product_id):
    try:
        from bson import ObjectId
        product = products_collection.find_one({"_id": ObjectId(product_id)})
        if not product:
            flash("Product not found.", "error")
            return redirect(url_for('index'))
        
        # Authenticated User Data fetch karna (Header ke liye)
        user_data = {'is_authenticated': False}
        if 'user_id' in session:
            try:
                current_user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
                if current_user:
                    user_data = {
                        'is_authenticated': True,
                        'username': current_user.get('username', 'User'),
                        'email': current_user.get('email'),
                        'phone': current_user.get('phone')
                    }
            except: pass

        if product:
            product['_id'] = str(product['_id'])
            # Ensure prices are floats for template calculations
            try:
                product['o_price'] = float(product.get('o_price', 0))
                product['d_price'] = float(product.get('d_price', 0))
            except: pass

        return render_template('product_details.html', product=product, user=user_data)
    except Exception as e:
        flash("Invalid Product ID.", "error")
        return redirect(url_for('index'))

@app.route('/api/check-delivery', methods=['POST'])
def check_delivery():
    data = request.get_json()
    pincode = data.get('pincode', '')
    
    if not pincode or not pincode.isdigit() or len(pincode) != 6:
        return jsonify({"status": "error", "message": "Please enter a valid 6-digit pincode"}), 400
    
    # --- Mock Delhivery Logic ---
    prefix = pincode[0]
    serviceable = True
    eta = ""
    cod = "Available"
    message = ""
    
    if prefix == '1': # North (Delhi, NCR, UP)
        eta = "2-3 Days (Express)"
    elif prefix == '4': # West (Mumbai, Gujarat)
        eta = "3-4 Days"
    elif prefix == '5': # South (Bangalore, Chennai, Hyderabad)
        eta = "3-5 Days"
    elif prefix == '7': # East (Kolkata, Bihar)
        eta = "5-6 Days"
    elif prefix == '0' or prefix == '9': # Rare/Unserviceable for demo
        serviceable = False
        message = "Remote location - currently not serviceable by Delhivery"
    else:
        eta = "4-5 Days (Surface)"
        
    if serviceable:
        return jsonify({
            "status": "success",
            "eta": eta,
            "provider": "Delhivery",
            "cod": cod,
            "message": "Serviceable via Delhivery"
        })
    else:
        return jsonify({
            "status": "error",
            "message": message
        })

# --- Newsletter Subscription ---
@app.route('/api/subscribe-newsletter', methods=['POST'])
def subscribe_newsletter():
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'status': 'error', 'message': 'Invalid email address'}), 400

    try:
        # Check if already subscribed
        existing = subscribers_collection.find_one({'email': email})
        if existing:
            return jsonify({'status': 'info', 'message': 'You are already part of the family! ✨'})

        subscribers_collection.insert_one({
            'email': email,
            'subscribed_at': datetime.now(timezone.utc)
        })
        return jsonify({'status': 'success', 'message': 'Welcome to the Green Naturals family! 🌿'})
    except Exception as e:
        safe_print(f"❌ Subscription Error: {safe_str(e)}")
        return jsonify({'status': 'error', 'message': 'Server error, try later'}), 500

# --- Green API WhatsApp OTP Routes ---
@app.route('/send-otp', methods=['POST'])
def send_otp():
    phone = request.form.get('phone') # Format: +91XXXXXXXXXX
    success, msg = send_green_api_otp(phone, "signup_sms")
    if success:
        return jsonify({"status": "pending", "msg": "OTP sent successfully via WhatsApp!"})
    else:
        return jsonify({"status": "error", "msg": msg})

    
@app.route('/verify-signup-otp', methods=['POST'])
def signup_verify_otp():
    if 'temp_user' not in session:
        return redirect(url_for('signup'))

    otp_code = request.form.get('otp')
    user_data = session['temp_user']
    phone = user_data['phone']

    success, msg = verify_green_api_otp(phone, otp_code)
    if success:
        # 1. Database mein save karein
        user_doc = {
            "username": user_data['username'],
            "email": user_data['email'],
            "phone": user_data['phone'],
            "password": user_data['password'],
            "created_at": datetime.now(timezone.utc)
        }
        result = users_collection.insert_one(user_doc)
        
        # 2. Direct Login (90 Days Session)
        app.permanent_session_lifetime = timedelta(days=90)
        session.permanent = True
        session['user_id'] = str(result.inserted_id)
        session['username'] = user_data['username']
        
        # Record Login Security Info
        record_user_login(str(result.inserted_id))

        # 3. Welcome Email Logic
        sender_email_fixed = os.getenv("SENDER_EMAIL", "noreply@greennaturals.store")
        welcome_html = f"""
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: auto; border: 1px solid #eef2f6; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
            <div style="background: linear-gradient(135deg, #10b981, #047857); padding: 40px 20px; text-align: center; color: white;">
                <div style="font-size: 40px; margin-bottom: 10px;">🌱</div>
                <h1 style="margin: 0; font-size: 26px; font-weight: 800; letter-spacing: -0.5px;">Welcome to Green Naturals!</h1>
                <p style="margin: 8px 0 0; opacity: 0.9; font-size: 15px;">Your journey to a healthier lifestyle begins here.</p>
            </div>
            <div style="padding: 35px 30px; background: #ffffff;">
                <p style="font-size: 16px; color: #1e293b; margin-top: 0;">Hi <strong>{user_data['username']}</strong>,</p>
                <p style="font-size: 15px; color: #475569; line-height: 1.6;">Humein bahut khushi hai ki aap <strong>Green Naturals</strong> family ka hissa bane. Aapka account successfully create aur verify ho gaya hai.</p>
                <div style="margin: 30px 0; padding: 20px; background: #f0fdf4; border-radius: 12px; border-left: 4px solid #22c55e;">
                    <h3 style="margin: 0 0 10px; color: #166534; font-size: 16px;">What's next?</h3>
                    <ul style="margin: 0; padding-left: 20px; color: #334155; font-size: 14px; line-height: 1.8;">
                        <li>Explore our 100% natural and organic products.</li>
                        <li>Track your orders easily from your dashboard.</li>
                        <li>Enjoy exclusive member benefits and fast delivery.</li>
                    </ul>
                </div>
                <div style="text-align: center; margin: 35px 0;">
                    <a href="https://greennaturals.store/" style="background: #1e293b; color: white; padding: 14px 32px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; display: inline-block; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">Start Shopping Now</a>
                </div>
            </div>
        </div>
        """
        
        def send_async_welcome_1(e, n, h):
            try:
                send_email(
                    subject="Welcome to Green Naturals! 🌱",
                    html_content=h,
                    to_email=e,
                    to_name=n,
                    sender_email=sender_email_fixed,
                    sender_name="Green Naturals"
                )
            except Exception as err:
                print(f"Welcome Email Error: {err}")
        
        from threading import Thread
        Thread(target=send_async_welcome_1, args=(user_data['email'], user_data['username'], welcome_html)).start()

        # Temp session saaf karein
        session.pop('temp_user', None)
        
        flash("Phone verified! Account created successfully.", "success")
        return redirect(url_for('welcome'))
    else:
        flash(msg, "error")
        return render_template('verify_signup_otp.html', phone=phone)
    
# --- Cloudinary Image Upload Route ---
@app.route('/upload-image', methods=['POST'])
def upload_image():
    file = request.files.get('file')
    if file:
        try:
            res = cloudinary.uploader.upload(file, folder="green_naturals_products")
            return jsonify({"status": "success", "url": res['secure_url']})
        except Exception as e:
            return jsonify({"status": "error", "msg": str(e)})
    return jsonify({"status": "error", "msg": "No file uploaded"})

@app.route('/get-captcha')
def get_new_captcha():
    captcha_code = str(random.randint(1000, 9999))
    session['captcha'] = captcha_code
    return jsonify({"captcha": captcha_code})

# --- Route: Admin Login ---
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    # If already authenticated and it's a GET request, bypass login screen
    if session.get('logged_in') and request.method == 'GET':
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Combining the 4 separate captcha inputs into a single string
        captcha_entered = "".join([request.form.get(f'c{i}', '') for i in range(1, 5)])
        
        # Credentials validation using environment variables
        if email == os.getenv("ADMIN_GMAIL") and password == os.getenv("ADMIN_PASSWORD"):
            # Captcha validation
            if captcha_entered == session.get('captcha'):
                
                # --- UPDATE: Admin ke liye session 30 minutes set karna ---
                session.permanent = True
                app.permanent_session_lifetime = timedelta(minutes=30) 
                
                session['logged_in'] = True
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Security verification failed. Please check the captcha code.", "error")
        else:
            flash("Invalid administrator credentials. Access denied.", "error")

    # Generate a fresh 4-digit captcha code on every GET request
    captcha_code = str(random.randint(1000, 9999))
    session['captcha'] = captcha_code
    return render_template('admin_login.html', captcha=captcha_code)

# --- Route: Admin Logout ---
@app.route('/admin-logout')
def admin_logout():
    session.pop('logged_in', None) # Session se login data hatayein
    flash("Aapne successfully logout kar liya hai.", "success")
    return redirect(url_for('admin_login'))

from bson.objectid import ObjectId

# --- Product Schema Reference ---
# { "name": str, "category": str, "o_price": int, "d_price": int, 
#   "discount_pct": int, "stock": int, "image_url": str, "image_id": str }

@app.route('/admin/add-product', methods=['GET', 'POST'])
def add_product():
    if not session.get('logged_in'): 
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        
        # 1. Strict Numeric Validation
        try:
            o_price = float(request.form.get('o_price', 0))
            d_price = float(request.form.get('d_price', 0))
            stock = int(request.form.get('stock', 0))
        except ValueError:
            flash("Invalid numbers provided.", "error")
            return redirect(url_for('add_product'))

        # 2. Logic: No Negative values & Sale Price < Base Price
        if o_price <= 0 or d_price <= 0 or stock < 0:
            flash("Price and Stock cannot be negative or zero.", "error")
            return redirect(url_for('add_product'))
            
        if d_price > o_price:
            flash(f"Sale Price (₹{d_price}) cannot be higher than MRP (₹{o_price}).", "error")
            return redirect(url_for('add_product'))

        # 3. Multiple Images Logic
        image_data_list = request.form.getlist('cropped_image') 
        if not image_data_list or len(image_data_list) == 0:
            flash("At least one product image is required.", "error")
            return redirect(url_for('add_product'))

        # 4. Category Logic
        selected_category = request.form.get('category')
        custom_category = request.form.get('custom_category', '').strip()
        final_category = custom_category.title() if selected_category == "Custom" else selected_category

        discount_pct = round(((o_price - d_price) / o_price) * 100) if o_price > 0 else 0

        try:
            urls = []
            public_ids = []

            # Cloudinary Upload Loop
            for img_data in image_data_list:
                if img_data:
                    upload_result = cloudinary.uploader.upload(img_data, folder="green_naturals_products")
                    urls.append(upload_result['secure_url'])
                    public_ids.append(upload_result['public_id'])
            
            # 5. Database Document Creation
            product_doc = {
                "name": name, 
                "category": final_category,
                "o_price": o_price, 
                "d_price": d_price,
                "discount_pct": discount_pct, 
                "stock": stock,
                "uses": request.form.get('uses', '').strip(),
                "ingredients": request.form.get('ingredients', '').strip(),
                "images": urls,
                "image_ids": public_ids,
                "image_url": urls[0],   # Legacy Support
                "image_id": public_ids[0],
                "created_at": datetime.now(timezone.utc)
            }
            
            products_collection.insert_one(product_doc)

            # --- 6. THERMAL PRINTING STYLE EMAIL NOTIFICATION (ENGLISH) ---
            sender_email_fixed = os.getenv("SENDER_EMAIL", "noreply@greennaturals.store")
            admin_receiver = os.getenv("ADMIN_GMAIL")
            
            email_subject = f"INVENTORY UPDATE: {name.upper()}"
            
            # Thermal Receipt Aesthetic
            email_html = f"""
            <div style="font-family: 'Courier New', Courier, monospace; max-width: 400px; margin: auto; padding: 20px; border: 1px solid #000; background-color: #fff; color: #000;">
                <div style="text-align: center; border-bottom: 2px dashed #000; padding-bottom: 15px; margin-bottom: 15px;">
                    <h2 style="margin: 0; font-size: 20px; font-weight: bold;">GREEN NATURALS</h2>
                    <p style="margin: 5px 0; font-size: 12px;">OFFICIAL INVENTORY RECEIPT</p>
                    <p style="margin: 0; font-size: 10px;">DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div style="font-size: 13px; line-height: 1.5;">
                    <p style="text-align: center; margin-bottom: 20px; font-weight: bold;">*** NEW PRODUCT REGISTERED ***</p>
                    
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 5px 0;">PRODUCT:</td>
                            <td style="padding: 5px 0; text-align: right; font-weight: bold;">{name.upper()}</td>
                        </tr>
                        <tr>
                            <td style="padding: 5px 0;">CATEGORY:</td>
                            <td style="padding: 5px 0; text-align: right;">{final_category.upper()}</td>
                        </tr>
                        <tr>
                            <td style="padding: 5px 0;">MRP:</td>
                            <td style="padding: 5px 0; text-align: right;">INR {o_price}</td>
                        </tr>
                        <tr>
                            <td style="padding: 5px 0;">SALE PRICE:</td>
                            <td style="padding: 5px 0; text-align: right; font-weight: bold;">INR {d_price}</td>
                        </tr>
                        <tr>
                            <td style="padding: 5px 0;">DISCOUNT:</td>
                            <td style="padding: 5px 0; text-align: right;">{discount_pct}% OFF</td>
                        </tr>
                        <tr>
                            <td style="padding: 5px 0; border-bottom: 1px dashed #000;">STOCK QTY:</td>
                            <td style="padding: 5px 0; text-align: right; border-bottom: 1px dashed #000; font-weight: bold;">{stock} UNITS</td>
                        </tr>
                    </table>

                    <div style="text-align: center; margin: 20px 0; padding: 10px; border: 1px solid #ccc;">
                        <p style="font-size: 10px; margin-bottom: 8px;">VISUAL PREVIEW</p>
                        <img src="{urls[0]}" style="width: 150px; height: 150px; filter: grayscale(100%); border: 1px solid #000;">
                        <p style="font-size: 9px; margin-top: 5px;">[SECURE CLOUDINARY LINK]</p>
                    </div>

                    <div style="text-align: center; border-top: 2px dashed #000; padding-top: 15px; margin-top: 15px;">
                        <p style="margin: 0; font-weight: bold;">ENTRY SUCCESSFUL</p>
                        <p style="margin: 5px 0; font-size: 11px;">SYSTEM_USER: ADMIN_ACCESS</p>
                        <p style="margin: 0; font-size: 10px;">--------------------------------</p>
                        <p style="margin: 5px 0; font-size: 10px;">END OF NOTIFICATION</p>
                    </div>
                </div>
            </div>
            """

            # Brevo Email Call
            send_email(
                subject=email_subject,
                html_content=email_html,
                to_email=admin_receiver,
                to_name="Green Naturals Admin",
                sender_email=sender_email_fixed,
                sender_name="Green Naturals"
            )

            flash(f"Success: {name} added. Thermal receipt generated.", "success")
            return redirect(url_for('add_product'))
            
        except Exception as e:
            flash(f"System Error: {str(e)}", "error")
            return redirect(url_for('add_product'))

    # GET Request Logic
    search_query = request.args.get('search', '')
    query = {"name": {"$regex": search_query, "$options": "i"}} if search_query else {}
    all_products = list(products_collection.find(query).sort("created_at", -1))

    existing_categories = products_collection.distinct("category")
    default_cats = ["Tablets", "Powder", "Oil"]
    final_cat_list = sorted(list(set(default_cats + existing_categories)))

    return render_template('admin/add_product.html', 
                           categories=final_cat_list, 
                           products=all_products)
    
import cloudinary.api # Cloudinary stats ke liye zaroori hai
from datetime import datetime, timezone

def get_time_ago(dt):
    """Returns a human-readable time ago string."""
    if not dt: return "Just now"
    
    # Handle both naive and aware datetimes
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    diff = now - dt
    
    seconds = diff.total_seconds()
    if seconds < 60: return f"{int(seconds)}s ago"
    if seconds < 3600: return f"{int(seconds/60)}m ago"
    if seconds < 86400: return f"{int(seconds/3600)}h ago"
    return f"{int(seconds/86400)}d ago"

@app.route('/api/admin/notifications')
def admin_get_notifications():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
        
    notifications = []
    
    # 1. Fetch Latest 10 Orders
    recent_orders = list(orders_collection.find().sort("_id", -1).limit(10))
    for o in recent_orders:
        items = o.get('items', [])
        item_count = len(items)
        total_price = o.get('total', 0)
        
        # Exact Structure Mapping: o['customer']['name']
        customer = o.get('customer', {})
        name = customer.get('name') or o.get('customer_name') or o.get('user_name') or "Customer"
        city = customer.get('city') or "India"
        
        # Primary Item Name (Optional)
        main_item = items[0].get('name') if items else "Multiple Items"
        
        notifications.append({
            "id": str(o['_id']),
            "type": "order",
            "title": f"Order: ₹{total_price}",
            "subtitle": f"{name} ({city}) • {main_item} ({item_count})",
            "timestamp": o.get('created_at', datetime.now(timezone.utc)).isoformat() if isinstance(o.get('created_at'), datetime) else datetime.now(timezone.utc).isoformat(),
            "time_ago": get_time_ago(o.get('created_at')),
            "link": f"/admin/orders?highlight={o['_id']}"
        })
        
    # 2. Fetch Latest 5 Signups
    recent_users = list(users_collection.find().sort("_id", -1).limit(5))
    for u in recent_users:
        method = "Google" if u.get('google_id') else "Phone/Email"
        notifications.append({
            "id": str(u['_id']),
            "type": "user",
            "title": f"New {method} User",
            "subtitle": f"{u.get('name', 'Anonymous')} joined our hub",
            "timestamp": u.get('created_at', datetime.now(timezone.utc)).isoformat() if u.get('created_at') else datetime.now(timezone.utc).isoformat(),
            "time_ago": get_time_ago(u.get('created_at')),
            "link": "/admin/manage-users"
        })
        
    # Sort all by timestamp descending
    notifications.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({
        "notifications": notifications[:10],
        "new_count": len([n for n in notifications if n['timestamp'] > (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()])
    })

@app.route('/admin-dashboard')
def admin_dashboard():
    # 1. Access Control: Ensure only logged-in admin enters
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    # 2. Fetch Products: Database se latest products uthana
    all_products = list(products_collection.find().sort("_id", -1))
    
    # 3. Fetch Shipping Fee: Database se current shipping setting uthana
    current_shipping = 0
    try:
        shipping_doc = db.settings.find_one({"type": "shipping_config"})
        if shipping_doc:
            current_shipping = shipping_doc.get('fee', 0)
    except Exception as e:
        print(f"Shipping Fetch Error: {e}")
        current_shipping = 0

    # 4. Email Limit Tracking: 300 emails per day limit
    emails_left = 300
    try:
        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        email_record = db['email_tracking'].find_one({"date": now_str})
        emails_sent = email_record.get('count', 0) if email_record else 0
        emails_left = max(0, 300 - emails_sent)
    except Exception as e:
        print(f"Email Stats Error: {e}")
        emails_left = 300
        
    # 5. Visitor Analytics
    traffic_stats = {"total_hits": 0, "today_hits": 0, "total_unique": 0, "live_now": 0}
    try:
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        ist_now = now + timedelta(hours=5, minutes=30)
        today_str = ist_now.strftime("%Y-%m-%d")
        
        # Today's Hits & Unique
        today_record = analytics.find_one({"type": "traffic_stats", "date": today_str})
        if today_record:
            traffic_stats['today_hits'] = today_record.get('hits', 0)
            traffic_stats['today_unique'] = len(today_record.get('unique_ips', []))
            
        # Total Hits
        total_hits_pipeline = [{"$match": {"type": "traffic_stats"}}, {"$group": {"_id": None, "total": {"$sum": "$hits"}}}]
        total_hits_res = list(analytics.aggregate(total_hits_pipeline))
        traffic_stats['total_hits'] = total_hits_res[0]['total'] if total_hits_res else 0
        
        # Live Users (Active in last 5 mins)
        five_mins_ago = now - timedelta(minutes=5)
        traffic_stats['live_now'] = analytics.count_documents({"type": "live_users", "last_active": {"$gte": five_mins_ago}})
        
        # 7-Day History for Graph
        history_labels = []
        history_hits = []
        history_unique = []
        for i in range(6, -1, -1):
            d = (ist_now - timedelta(days=i)).strftime("%Y-%m-%d")
            display_date = (ist_now - timedelta(days=i)).strftime("%d %b")
            record = analytics.find_one({"type": "traffic_stats", "date": d})
            history_labels.append(display_date)
            history_hits.append(record.get('hits', 0) if record else 0)
            history_unique.append(len(record.get('unique_ips', [])) if record else 0)
            
        traffic_stats['history'] = {
            "labels": history_labels,
            "hits": history_hits,
            "unique": history_unique
        }
    except Exception as e:
        print(f"Analytics Fetch Error: {e}")

    # 6. Database Health: MongoDB Connection Check
    db_status = "CONNECTED"
    try:
        client.admin.command('ping')
    except Exception:
        db_status = "DISCONNECTED"

    # 7. Render: Ab isme 'current_shipping' aur 'emails_left' bhi pass ho raha hai
    return render_template('admin_dashboard.html', 
                          products=all_products, 
                          emails_left=emails_left, 
                          db_status=db_status,
                          current_shipping=current_shipping,
                          traffic=traffic_stats)



@app.template_filter('last_chars')
def last_chars_filter(s):
    return str(s)[-5:]

@app.route('/admin/products')
def manage_products():
    if not session.get('logged_in'): 
        return redirect(url_for('admin_login'))
    
    # Database se saare products fetch karein
    all_products = list(products_collection.find().sort("created_at", -1))
    
    return render_template('admin/manage_products.html', products=all_products)

from bson.objectid import ObjectId

@app.route('/admin/delete-product/<id>')
def delete_product(id):
    # 1. Access Control: Check if Admin is logged in
    if not session.get('logged_in'): 
        return redirect(url_for('admin_login'))
    
    try:
        # 2. Database se product fetch karein taaki image_ids mil sakein
        product = products_collection.find_one({"_id": ObjectId(id)})
        
        if not product:
            flash("Error: Product not found in database.", "error")
            return redirect(url_for('manage_products'))

        # 3. Cloudinary se images delete karein
        # Case A: Agar multiple images hain (List format)
        if "image_ids" in product and isinstance(product['image_ids'], list):
            for img_id in product['image_ids']:
                if img_id: # Ensure ID is not empty
                    cloudinary.uploader.destroy(img_id)
        
        # Case B: Agar purana single image format hai
        elif "image_id" in product and product['image_id']:
            cloudinary.uploader.destroy(product['image_id'])

        # 4. MongoDB se product record delete karein
        result = products_collection.delete_one({"_id": ObjectId(id)})
        
        if result.deleted_count > 0:
            flash(f"Success: '{product.get('name')}' and its media purged from system.", "success")
        else:
            flash("Error: Record could not be deleted.", "error")

    except Exception as e:
        # System error handling
        print(f"Delete Error: {str(e)}")
        flash(f"System Error: {str(e)}", "error")

    # 5. Wapas Manage Products page par redirect karein
    return redirect(url_for('manage_products'))

@app.route('/admin/edit-product/<id>')
def edit_product(id):
    if not session.get('logged_in'): return redirect(url_for('admin_login'))
    
    product = products_collection.find_one({"_id": ObjectId(id)})
    if not product:
        flash("Product not found!", "error")
        return redirect(url_for('manage_products'))
        
    # Categories fetch karna dropdown ke liye
    existing_categories = products_collection.distinct("category")
    return render_template('admin/edit_product.html', product=product, categories=existing_categories)

@app.route('/admin/update-product/<id>', methods=['POST'])
def update_product(id):
    if not session.get('logged_in'): return redirect(url_for('admin_login'))
    
    try:
        old_product = products_collection.find_one({"_id": ObjectId(id)})
        
        # 1. Basic Data
        name = request.form.get('name')
        o_price = float(request.form.get('o_price'))
        d_price = float(request.form.get('d_price'))
        stock = int(request.form.get('stock'))
        
        # 2. Category Logic (Add New Category Support)
        category = request.form.get('category')
        if category == "Custom":
            category = request.form.get('custom_category').strip()

        if d_price > o_price:
            flash("Sale price cannot be higher than MRP!", "error")
            return redirect(url_for('edit_product', id=id))

        # 3. Image Management (Keeping Old + Adding New)
        new_image_data_list = request.form.getlist('cropped_image')
        
        # Existing lists maintain karein
        final_urls = old_product.get('images', [])
        final_ids = old_product.get('image_ids', [])

        if new_image_data_list:
            for img_data in new_image_data_list:
                if img_data:
                    res = cloudinary.uploader.upload(img_data, folder="products")
                    final_urls.append(res['secure_url'])
                    final_ids.append(res['public_id'])

        # 4. Final Database Update
        discount_pct = round(((o_price - d_price) / o_price) * 100)
        
        update_data = {
            "name": name,
            "category": category,
            "o_price": o_price,
            "d_price": d_price,
            "stock": stock,
            "uses": request.form.get('uses', '').strip(),
            "ingredients": request.form.get('ingredients', '').strip(),
            "discount_pct": discount_pct,
            "images": final_urls,
            "image_ids": final_ids,
            "image_url": final_urls[0] if final_urls else "", # First image as primary
            "updated_at": datetime.now()
        }

        products_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})
        flash(f"'{name}' updated successfully!", "success")
        
    except Exception as e:
        flash(f"Update failed: {str(e)}", "error")
        
    return redirect(url_for('manage_products'))

@app.route('/admin/delete-product-image/<product_id>/<path:image_id>')
def delete_product_image(product_id, image_id):
    if not session.get('logged_in'): 
        return redirect(url_for('admin_login'))
    
    try:
        # 1. Database se product fetch karein
        product = products_collection.find_one({"_id": ObjectId(product_id)})
        
        if product and "image_ids" in product:
            # Safety: Kam se kam 1 image honi chahiye
            if len(product['image_ids']) <= 1:
                flash("Cannot delete the last image. Add a new one first!", "error")
                return redirect(request.referrer or url_for('manage_products'))

            # 2. Index find karein taaki sahi URL delete ho
            try:
                idx = product['image_ids'].index(image_id)
                image_url = product['images'][idx]
            except ValueError:
                flash("Image not found in our records.", "error")
                return redirect(request.referrer or url_for('manage_products'))

            # 3. Cloudinary se image delete karein
            cloudinary.uploader.destroy(image_id)

            # 4. MongoDB se pull karein (URL aur ID dono)
            products_collection.update_one(
                {"_id": ObjectId(product_id)},
                {
                    "$pull": {
                        "image_ids": image_id,
                        "images": image_url
                    }
                }
            )
            
            # 5. Primary Image Sync (Agar main image delete hui hai)
            # Naya data fetch karein update ke baad
            updated_product = products_collection.find_one({"_id": ObjectId(product_id)})
            
            # Agar purani 'image_url' field delete hui photo dikha rahi thi
            if product.get('image_url') == image_url:
                products_collection.update_one(
                    {"_id": ObjectId(product_id)},
                    {"$set": {
                        "image_url": updated_product['images'][0],
                        "image_id": updated_product['image_ids'][0]
                    }}
                )

            flash("Media asset removed successfully.", "success")
        else:
            flash("Asset record not found.", "error")
            
    except Exception as e:
        flash(f"System Error: {str(e)}", "error")

    # --- FIX: Wapas usi page par bhejna jahan se request aayi thi ---
    return redirect(request.referrer or url_for('manage_products'))

from werkzeug.security import generate_password_hash, check_password_hash

# Helper function to validate password strength
def is_strong_password(password):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[@$!%*?&#^_-]", password):
        return False, "Password must contain at least one special character."
    return True, "Valid"

# Helper function to format phone number
def format_phone(phone):
    phone = str(phone).strip()
    # Agar number 10 digits ka hai, toh +91 prefix lagao
    if len(phone) == 10 and phone.isdigit():
        return f"+91{phone}"
    # Agar user ne pehle se +91 likha hai, toh as-is rakho
    return phone

# --- USER LOGIN ROUTE (OTP + PASSWORD) ---
# --- USER LOGIN ROUTE (Updated for 90 Days Session) ---
# --- NEW INLINE SIGNUP VERIFICATION APIs ---
@app.route('/api/signup/send-email-otp', methods=['POST'])
def signup_send_email_otp():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    username = data.get('username', 'User')
    
    if not email or "@" not in email:
        return jsonify({"success": False, "error": "Valid email is required."})
        
    if users_collection.find_one({"email": email}):
        return jsonify({"success": False, "error": "Email already registered."})

    otp = str(random.randint(100000, 999999))
    log_otp(email, "signup_email", otp)
    session['signup_email_otp'] = otp
    session['signup_email'] = email
    
    subject = "Verify Your Email - Green Naturals"
    email_html = f"""
    <div style="font-family: sans-serif; max-width: 450px; margin: auto; padding: 30px; border: 1px solid #ecfdf5; border-radius: 20px; text-align: center;">
        <h2 style="color: #064e3b;">Email Verification</h2>
        <p>Use the code below to verify your email address for Green Naturals.</p>
        <div style="background: #ecfdf5; padding: 20px; border-radius: 12px; margin: 20px 0; font-size: 32px; font-weight: 800; color: #059669; border: 1px dashed #10b981;">
            {otp}
        </div>
    </div>
    """
    from threading import Thread
    Thread(target=send_email, args=(subject, email_html, email, username, os.getenv("SENDER_EMAIL"), "Green Naturals")).start()
    return jsonify({"success": True})

@app.route('/api/signup/verify-email-otp', methods=['POST'])
def signup_verify_email_otp():
    data = request.get_json()
    otp_entered = data.get('otp')
    if otp_entered == session.get('signup_email_otp'):
        session['signup_email_verified'] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid code."})

@app.route('/api/signup/send-phone-otp', methods=['POST'])
def signup_send_phone_otp():
    data = request.get_json()
    raw_phone = str(data.get('phone', '')).strip()
    
    # Handle edge case where +91 might be sent twice from frontend
    if raw_phone.startswith('+91+91'):
        raw_phone = raw_phone.replace('+91+91', '+91')
        
    phone = format_phone(raw_phone)
    
    if not phone or len(phone) < 10:
        return jsonify({"success": False, "error": "Valid phone number is required."})
        
    if users_collection.find_one({"phone": phone}):
        return jsonify({"success": False, "error": "Phone number already registered."})

    success, msg = send_green_api_otp(phone, "signup_sms")
    if success:
        session['signup_phone'] = phone
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": msg})

@app.route('/api/signup/verify-phone-otp', methods=['POST'])
def signup_verify_phone_otp():
    data = request.get_json()
    otp_entered = data.get('otp')
    phone = session.get('signup_phone')
    
    if not phone: return jsonify({"success": False, "error": "Session expired."})

    success, msg = verify_green_api_otp(phone, otp_entered)
    if success:
        session['signup_phone_verified'] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "error": msg})

# --- GOOGLE OAUTH ROUTES ---
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    try:
        # Get access token (this won't fail with 'iss' anymore)
        token = google.authorize_access_token()
        
        # Fetch user info manually using the token
        resp = google.get('https://www.googleapis.com/oauth2/v1/userinfo')
        user_info = resp.json()
        
        email = user_info.get('email', '').lower().strip()
        name = user_info.get('name', 'Google User')
        picture = user_info.get('picture')
        # Google ID is usually in 'id' for this endpoint
        google_id = user_info.get('id')

        if not email:
            flash("Could not retrieve email from Google. Please try again.", "error")
            return redirect(url_for('login'))

        # Check if user exists
        user = users_collection.find_one({"email": email})
        
        if user:
            # 1. Check for Active Session
            last_active = user.get('last_active')
            active_threshold = datetime.now(timezone.utc) - timedelta(minutes=10)
            
            if user.get('current_session_token') and last_active and last_active.replace(tzinfo=timezone.utc) > active_threshold:
                flash("Already logged in on another device. Please logout from all devices first.", "danger")
                # For Google users, we use a special placeholder or verify via Google again
                return render_template('login.html', show_logout_all=True, identifier=email, is_google=True)

            # 2. Generate Single Session Token
            import secrets
            session_token = secrets.token_hex(16)
            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "google_id": google_id, 
                    "email_verified": True,
                    "profile_image": picture or user.get('profile_image'),
                    "current_session_token": session_token,
                    "last_active": datetime.now(timezone.utc)
                }}
            )
            
            # Record Login Security Info
            record_user_login(str(user['_id']))
            
            # Set Session
            app.permanent_session_lifetime = timedelta(days=90)
            session.permanent = True 
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['profile_image'] = user.get('profile_image', '')
            session['session_token'] = session_token
            
            flash(f"Logged in successfully as {user['username']}!", "success")
            return redirect(url_for('welcome'))
            
        else:
            # NEW USER: Don't create account yet. Save to session and ask for phone.
            session['google_pending_user'] = {
                "username": name,
                "email": email,
                "google_id": google_id,
                "profile_image": picture
            }
            flash("Almost there! Please verify your phone number to complete your account.", "info")
            return redirect(url_for('complete_google_signup_page'))
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        safe_print(f"❌ Google OAuth Error: {str(e)}")
        # Save to a debug file so we can read it
        with open("oauth_debug.log", "a") as f:
            f.write(f"\n--- {datetime.now()} ---\n")
            f.write(f"Error: {str(e)}\n")
            f.write(error_details)
            f.write("\n")
            
        flash("Google login failed. Please try again.", "error")
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Agar user pehle se login hai aur GET request hai, toh index par bhejein
    if 'user_id' in session and request.method == 'GET':
        return redirect(url_for('index'))

    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        login_type = request.form.get('login_type')

        # Identifier formatting (Phone number check)
        formatted_identifier = format_phone(identifier) if identifier.isdigit() else identifier.lower().strip()

        # User ko DB mein search karein
        user = users_collection.find_one({
            "$or": [
                {"email": formatted_identifier}, 
                {"phone": formatted_identifier}
            ]
        })

        if not user:
            flash("No account found. Please signup first.", "error")
            return redirect(url_for('login'))

        # --- CASE 1: Password Login ---
        if login_type == 'password':
            if check_password_hash(user['password'], password):
                # 1. Check for Active Session
                last_active = user.get('last_active')
                active_threshold = datetime.now(timezone.utc) - timedelta(minutes=10)
                
                # Agar session active hai aur force login nahi hai
                if user.get('current_session_token') and last_active and last_active.replace(tzinfo=timezone.utc) > active_threshold:
                    # Log OTP Attempt (Displacement Alert)
                    log_otp(identifier, "login_displacement_alert")
                    
                    flash("Already logged in on another device. Please logout from all devices first.", "danger")
                    return render_template('login.html', show_logout_all=True, identifier=identifier, password=password)

                # 2. Generate Single Session Token
                import secrets
                session_token = secrets.token_hex(16)
                users_collection.update_one(
                    {"_id": user["_id"]}, 
                    {"$set": {
                        "current_session_token": session_token,
                        "last_active": datetime.now(timezone.utc)
                    }}
                )

                # IMPORTANT: User ke liye 90 days lifetime set karein
                app.permanent_session_lifetime = timedelta(days=90)
                session.permanent = True 
                
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                session['profile_image'] = user.get('profile_image', '')
                session['session_token'] = session_token
                
                # Record Login Security Info
                record_user_login(str(user['_id']))
                
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for('welcome'))
            else:
                flash("Invalid password.", "error")
        
        # --- CASE 2: OTP Login ---
        elif login_type == 'otp':
            try:
                # Detect if it's email or phone
                is_email = "@" in identifier
                
                if is_email:
                    # 1. Generate Custom OTP for Email
                    otp = str(random.randint(100000, 999999))
                    log_otp(identifier, "login_email", otp)
                    session['login_otp'] = otp
                    session['login_email'] = identifier
                    session['login_method'] = 'email'
                    session['last_otp_time'] = time.time()
                    
                    # 2. Send Email
                    subject = f"{otp} is your Green Naturals verification code"
                    email_html = f"""
                    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 550px; margin: auto; padding: 40px; border: 1px solid #f0fdf4; border-radius: 32px; text-align: center; background: #ffffff; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);">
                        <img src="https://greennaturals.store/static/images/official_brand_logo.png" style="width: 70px; height: 70px; margin-bottom: 24px;">
                        <h2 style="color: #064e3b; margin-bottom: 12px; font-size: 26px; font-weight: 800;">Login Verification</h2>
                        <p style="color: #4b5563; font-size: 16px; line-height: 1.6;">Hello {user.get('username', 'Customer')}, use the secure code below to access your account:</p>
                        
                        <div style="margin: 30px 0; text-align: center;">
                            <div style="background: #f0fdf4; padding: 25px 15px; border-radius: 20px; font-size: 42px; font-weight: 900; letter-spacing: 0.3em; color: #166534; border: 2px dashed #22c55e; display: inline-block; min-width: 240px; margin: 0 auto; text-indent: 0.3em;">
                                {otp}
                            </div>
                        </div>
                        
                        <p style="color: #9ca3af; font-size: 13px; margin-top: 24px;">This code will expire in 10 minutes for your security.<br>If you didn't request this, please ignore this email.</p>
                        <div style="margin-top: 32px; padding-top: 24px; border-top: 1px solid #f3f4f6;">
                            <p style="color: #064e3b; font-weight: 700; font-size: 14px; margin-bottom: 4px;">Green Naturals</p>
                            <p style="color: #16a34a; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.2em;">Pure Herbal Excellence</p>
                        </div>
                    </div>
                    """
                    def send_and_log():
                        try:
                            # SENDER_EMAIL environment variable se utha rahe hain
                            sender = os.getenv("SENDER_EMAIL", "security@greennaturals.store")
                            send_email(subject, email_html, formatted_identifier, user.get('username', 'Customer'), sender, "Green Naturals Security")
                            safe_print(f"?? [SUCCESS] Email OTP {otp} sent to {formatted_identifier}")
                        except Exception as e:
                            safe_print(f"?? [ERROR] Email OTP failed for {formatted_identifier}: {str(e)}")
                            
                    from threading import Thread
                    Thread(target=send_and_log).start()
                    
                    return redirect(url_for('verify_login_otp_page'))
                    
                else:
                    # 3. Green API WhatsApp OTP for Phone
                    safe_print(f"📲 [INFO] Attempting Green API WhatsApp OTP for {user['phone']}...")
                    success, msg = send_green_api_otp(user['phone'], "login_sms")
                    if success:
                        session['login_phone'] = user['phone']
                        session['login_method'] = 'phone'
                        session['last_otp_time'] = time.time()
                        return redirect(url_for('verify_login_otp_page'))
                    else:
                        flash(msg, "error")
                        return redirect(url_for('login'))
                    
            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout-all-devices', methods=['POST'])
def logout_all_devices():
    identifier = request.form.get('identifier')
    password = request.form.get('password')
    
    # 1. Formatting
    formatted_identifier = format_phone(identifier) if identifier.isdigit() else identifier.lower().strip()
    
    # 2. User Search
    user = users_collection.find_one({
        "$or": [{"email": formatted_identifier}, {"phone": formatted_identifier}]
    })
    
    # Verify via password OR check if it was a Google/OTP login attempt
    is_google = request.form.get('is_google') == 'True'
    is_otp_bypass = request.form.get('is_otp_bypass') == 'True'
    can_logout = False
    
    if user:
        if is_google or is_otp_bypass:
            # Google/OTP identity already verified by respective handlers before redirect
            can_logout = True 
        elif password and check_password_hash(user['password'], password):
            can_logout = True

    if can_logout:
        # 3. Clear Token and Activity
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"current_session_token": None, "last_active": None}}
        )
        flash("SUCCESS: All active sessions have been terminated. Now you can login safely.", "success")
    else:
        flash("Could not verify identity. Please try again.", "error")
        
    return redirect(url_for('login'))

# --- USER SIGNUP: STEP 1 (Details & Send OTP) ---
@app.route('/complete-google-signup', methods=['GET'])
def complete_google_signup_page():
    if 'google_pending_user' not in session:
        flash("Session expired. Please try Google login again.", "error")
        return redirect(url_for('login'))
    return render_template('complete_google_signup.html', user=session['google_pending_user'])

@app.route('/api/google-signup/verify-phone', methods=['POST'])
def google_signup_verify_phone():
    if 'google_pending_user' not in session:
        return jsonify({"success": False, "error": "Session expired."}), 400
    
    data = request.json
    otp = data.get('otp')
    phone = data.get('phone')
    
    # Green API Verification
    try:
        success, msg = verify_green_api_otp(phone, otp)
        if not success:
            return jsonify({"success": False, "error": msg}), 400
                
        # OTP Success: Create User
        pending = session['google_pending_user']
        
        # Double check if email was taken while user was verifying phone
        if users_collection.find_one({"email": pending['email']}):
            session.pop('google_pending_user', None)
            return jsonify({"success": False, "error": "This email was just registered by someone else."}), 400
            
        import base64
        random_pw = base64.b64encode(os.urandom(24)).decode()
        
        new_user = {
            "username": pending['username'],
            "email": pending['email'],
            "phone": phone,
            "google_id": pending['google_id'],
            "profile_image": pending['profile_image'],
            "password": generate_password_hash(random_pw),
            "created_at": datetime.now(timezone.utc),
            "email_verified": True,
            "phone_verified": True,
            "addresses": [],
            "last_used_address": None
        }
        
        result = users_collection.insert_one(new_user)
        user_id = str(result.inserted_id)
        
        # Log in the user
        session.pop('google_pending_user', None)
        session.permanent = True
        session['user_id'] = user_id
        session['username'] = pending['username']
        session['profile_image'] = pending.get('profile_image', '')

        # --- SEND PREMIUM WELCOME EMAIL ---
        try:
            subject = "Welcome to Green Naturals! 🌱"
            username = pending['username']
            email = pending['email']
            
            email_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
            </head>
            <body style="font-family: 'Inter', sans-serif; background-color: #f8fafc; margin: 0; padding: 0;">
                <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f8fafc; padding: 40px 20px;">
                    <tr>
                        <td align="center">
                            <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 24px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.05);">
                                <!-- Header -->
                                <tr>
                                    <td style="padding: 40px 40px 20px; text-align: center; border-bottom: 1px solid #f1f5f9;">
                                        <img src="https://greennaturals.store/static/images/official_brand_logo.png" alt="Green Naturals" style="width: 70px; height: 70px; margin-bottom: 20px;">
                                        <h1 style="margin: 0; font-size: 28px; font-weight: 800; color: #064e3b; letter-spacing: -0.5px;">Welcome to the Family!</h1>
                                        <p style="margin: 10px 0 0; font-size: 16px; color: #64748b;">Your journey to pure, natural wellness starts here.</p>
                                    </td>
                                </tr>
                                
                                <!-- Body -->
                                <tr>
                                    <td style="padding: 40px;">
                                        <p style="margin: 0 0 20px; font-size: 16px; color: #334155; line-height: 1.6;">Hi <strong style="color: #0f172a;">{username}</strong>,</p>
                                        <p style="margin: 0 0 30px; font-size: 16px; color: #475569; line-height: 1.6;">
                                            Thank you for choosing Green Naturals. Your account has been successfully created via Google. We are thrilled to have you with us!
                                        </p>
                                        
                                        <div style="background-color: #ecfdf5; border-radius: 16px; padding: 24px; margin-bottom: 30px; border-left: 4px solid #10b981;">
                                            <h3 style="margin: 0 0 12px; font-size: 16px; font-weight: 600; color: #065f46;">What's Next?</h3>
                                            <ul style="margin: 0; padding-left: 20px; color: #047857; font-size: 15px; line-height: 1.8;">
                                                <li>Discover 100% natural, premium products.</li>
                                                <li>Enjoy fast, reliable delivery across India.</li>
                                                <li>Track your orders seamlessly from your profile.</li>
                                            </ul>
                                        </div>
                                        
                                        <table width="100%" cellpadding="0" cellspacing="0">
                                            <tr>
                                                <td align="center">
                                                    <a href="https://greennaturals.store/" style="display: inline-block; background-color: #10b981; color: #ffffff; font-size: 16px; font-weight: 600; text-decoration: none; padding: 16px 36px; border-radius: 12px; box-shadow: 0 4px 6px rgba(16, 185, 129, 0.25);">Explore Products</a>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                
                                <!-- Footer -->
                                <tr>
                                    <td style="background-color: #f8fafc; padding: 30px; text-align: center; border-top: 1px solid #f1f5f9;">
                                        <p style="margin: 0 0 10px; font-size: 14px; font-weight: 600; color: #64748b;">Green Naturals Team</p>
                                        <p style="margin: 0; font-size: 12px; color: #94a3b8;">If you have any questions, simply reply to this email.</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            """
            from threading import Thread
            sender = os.getenv("SENDER_EMAIL", "security@greennaturals.store")
            Thread(target=send_email, args=(subject, email_html, email, username, sender, "Green Naturals")).start()
            
        except Exception as e:
            safe_print(f"?? [ERROR] Welcome email failed for Google user: {str(e)}")
        
        return jsonify({"success": True, "message": "Account created successfully!"})
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/welcome')
def welcome():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    name = session.get('username', 'User')
    # Get first name only for Apple-style greeting
    first_name = name.split(' ')[0]
    return render_template('welcome.html', name=first_name)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email').lower().strip()
        phone = format_phone(request.form.get('phone'))
        password = request.form.get('password')

        is_strong, msg = is_strong_password(password)
        if not is_strong:
            flash(msg, "error")
            return redirect(url_for('signup'))

        # Critical Security Check: Ensure session flags are true
        if not session.get('signup_email_verified') or not session.get('signup_phone_verified'):
            flash("Please verify both email and phone first.", "error")
            return redirect(url_for('signup'))
            
        if email != session.get('signup_email') or phone != session.get('signup_phone'):
            flash("Verification details mismatch. Please verify again.", "error")
            return redirect(url_for('signup'))

        # Create user
        user_doc = {
            "username": username,
            "email": email,
            "phone": phone,
            "password": generate_password_hash(password),
            "created_at": datetime.now(timezone.utc)
        }
        result = users_collection.insert_one(user_doc)
        
        # Auto Login
        session.clear()
        session.permanent = True
        session['user_id'] = str(result.inserted_id)
        session['username'] = username

        # --- SEND PREMIUM WELCOME EMAIL ---
        subject = "Welcome to Green Naturals! 🌱"
        email_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Inter', sans-serif; background-color: #f8fafc; margin: 0; padding: 0;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f8fafc; padding: 40px 20px;">
                <tr>
                    <td align="center">
                        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 24px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.05);">
                            <!-- Header -->
                            <tr>
                                <td style="padding: 40px 40px 20px; text-align: center; border-bottom: 1px solid #f1f5f9;">
                                    <img src="https://greennaturals.store/static/images/official_brand_logo.png" alt="Green Naturals" style="width: 70px; height: 70px; margin-bottom: 20px;">
                                    <h1 style="margin: 0; font-size: 28px; font-weight: 800; color: #064e3b; letter-spacing: -0.5px;">Welcome to the Family!</h1>
                                    <p style="margin: 10px 0 0; font-size: 16px; color: #64748b;">Your journey to pure, natural wellness starts here.</p>
                                </td>
                            </tr>
                            
                            <!-- Body -->
                            <tr>
                                <td style="padding: 40px;">
                                    <p style="margin: 0 0 20px; font-size: 16px; color: #334155; line-height: 1.6;">Hi <strong style="color: #0f172a;">{username}</strong>,</p>
                                    <p style="margin: 0 0 30px; font-size: 16px; color: #475569; line-height: 1.6;">
                                        Thank you for choosing Green Naturals. Your account has been successfully created and verified. We are thrilled to have you with us!
                                    </p>
                                    
                                    <div style="background-color: #ecfdf5; border-radius: 16px; padding: 24px; margin-bottom: 30px; border-left: 4px solid #10b981;">
                                        <h3 style="margin: 0 0 12px; font-size: 16px; font-weight: 600; color: #065f46;">What's Next?</h3>
                                        <ul style="margin: 0; padding-left: 20px; color: #047857; font-size: 15px; line-height: 1.8;">
                                            <li>Discover 100% natural, premium products.</li>
                                            <li>Enjoy fast, reliable delivery across India.</li>
                                            <li>Track your orders seamlessly from your profile.</li>
                                        </ul>
                                    </div>
                                    
                                    <table width="100%" cellpadding="0" cellspacing="0">
                                        <tr>
                                            <td align="center">
                                                <a href="https://greennaturals.store/" style="display: inline-block; background-color: #10b981; color: #ffffff; font-size: 16px; font-weight: 600; text-decoration: none; padding: 16px 36px; border-radius: 12px; box-shadow: 0 4px 6px rgba(16, 185, 129, 0.25);">Explore Products</a>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                            
                            <!-- Footer -->
                            <tr>
                                <td style="background-color: #f8fafc; padding: 30px; text-align: center; border-top: 1px solid #f1f5f9;">
                                    <p style="margin: 0 0 10px; font-size: 14px; font-weight: 600; color: #64748b;">Green Naturals Team</p>
                                    <p style="margin: 0; font-size: 12px; color: #94a3b8;">If you have any questions, simply reply to this email.</p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        from threading import Thread
        Thread(target=send_email, args=(subject, email_html, email, username, os.getenv("SENDER_EMAIL"), "Green Naturals")).start()
        
        flash("Welcome to Green Naturals! Your account is ready.", "success")
        return redirect(url_for('welcome'))

    return render_template('signup.html')

# --- USER LOGIN OTP VERIFY ROUTE ---
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    identifier = request.form.get('identifier')
    otp_code = request.form.get('otp')
    method = session.get('login_method', 'phone')
    
    try:
        if method == 'email':
            stored_otp = session.get('login_otp')
            if otp_code == stored_otp:
                mark_otp_success(identifier)
                user = users_collection.find_one({"email": identifier})
                if not user:
                    flash("Account not found.", "error")
                    return redirect(url_for('signup'))
                
                # Check for Active Session
                last_active = user.get('last_active')
                active_threshold = datetime.now(timezone.utc) - timedelta(minutes=10)
                if user.get('current_session_token') and last_active and last_active.replace(tzinfo=timezone.utc) > active_threshold:
                    flash("Already logged in on another device. Please logout from all devices first.", "danger")
                    # We store the identifier but no password since they used OTP
                    return render_template('login.html', show_logout_all=True, identifier=identifier, is_otp_bypass=True)

                # Success
                import secrets
                session_token = secrets.token_hex(16)
                users_collection.update_one({"_id": user["_id"]}, {"$set": {"current_session_token": session_token, "last_active": datetime.now(timezone.utc)}})

                session.permanent = True 
                session['user_id'] = str(user['_id'])
                session['username'] = user.get('username', 'User')
                session['profile_image'] = user.get('profile_image', '')
                session['session_token'] = session_token
                
                # Record Login Security Info
                record_user_login(str(user['_id']))
                
                flash(f"Login Successful! Welcome {session['username']}", "success")
                return redirect(url_for('welcome'))
            else:
                flash("Invalid verification code.", "error")
                return render_template('user_verify_otp.html', identifier=identifier)
        else:
            # Green API WhatsApp OTP Check for Phone
            success, msg = verify_green_api_otp(identifier, otp_code)
            if success:
                user = users_collection.find_one({"phone": identifier})
                if user:
                    # Check for Active Session
                    last_active = user.get('last_active')
                    active_threshold = datetime.now(timezone.utc) - timedelta(minutes=10)
                    if user.get('current_session_token') and last_active and last_active.replace(tzinfo=timezone.utc) > active_threshold:
                        flash("Already logged in on another device. Please logout from all devices first.", "danger")
                        return render_template('login.html', show_logout_all=True, identifier=identifier, is_otp_bypass=True)

                    # Generate Single Session Token
                    import secrets
                    session_token = secrets.token_hex(16)
                    users_collection.update_one({"_id": user["_id"]}, {"$set": {"current_session_token": session_token, "last_active": datetime.now(timezone.utc)}})

                    session.permanent = True 
                    session['user_id'] = str(user['_id'])
                    session['username'] = user.get('username', 'User')
                    session['profile_image'] = user.get('profile_image', '')
                    session['session_token'] = session_token
                    
                    # Record Login Security Info
                    record_user_login(str(user['_id']))
                    
                    flash(f"Login Successful! Welcome {session['username']}", "success")
                    return redirect(url_for('welcome'))
                else:
                    flash("Verified but account not found.", "error")
                    return redirect(url_for('signup'))
            else:
                flash(msg, "error")
                return render_template('user_verify_otp.html', identifier=identifier)
                
    except Exception as e:
        flash(str(e), "error")
        return redirect(url_for('login'))
    
# --- OTP VERIFICATION PAGES ---
@app.route('/verify-login-otp-page')
@app.route('/verify-otp-page')
def verify_login_otp_page():
    method = session.get('login_method')
    identifier = session.get('login_email') if method == 'email' else session.get('login_phone')
    
    if not identifier:
        return redirect(url_for('login'))
        
    return render_template('user_verify_otp.html', identifier=identifier, method=method)

@app.route('/resend-login-otp')
def resend_login_otp():
    method = session.get('login_method')
    identifier = session.get('login_email') if method == 'email' else session.get('login_phone')
    
    if not identifier:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for('login'))
    
    last_sent = session.get('last_otp_time', 0)
    if time.time() - last_sent < 30:
        flash("Please wait before requesting a new code.", "error")
        return redirect(url_for('verify_login_otp_page'))
    
    try:
        if method == 'email':
            # Resend Email OTP
            otp = str(random.randint(100000, 999999))
            log_otp(session.get('login_email') or session.get('login_phone'), "resend_otp", otp)
            session['login_otp'] = otp
            session['last_otp_time'] = time.time()
            
            subject = "Your Login Verification Code"
            email_html = f"""
            <div style="font-family: sans-serif; max-width: 500px; margin: auto; padding: 30px; border: 1px solid #ecfdf5; border-radius: 24px; text-align: center; background: #ffffff;">
                <h2 style="color: #064e3b; margin-bottom: 10px;">Login Verification</h2>
                <div style="margin: 30px 0; text-align: center;">
                    <div style="background: #f0fdf4; padding: 25px 15px; border-radius: 20px; font-size: 42px; font-weight: 900; letter-spacing: 0.3em; color: #166534; border: 2px dashed #22c55e; display: inline-block; min-width: 240px; margin: 0 auto; text-indent: 0.3em;">
                        {otp}
                    </div>
                </div>
                <p style="color: #6b7280; font-size: 12px;">This code is valid for 10 minutes. If you didn't request this, please ignore.</p>
            </div>
            """
            from threading import Thread
            sender = os.getenv("SENDER_EMAIL", "security@greennaturals.store")
            Thread(target=send_email, args=(subject, email_html, identifier, "Customer", sender, "Green Naturals Security")).start()
            flash(f"A new verification code has been sent to {identifier}", "success")
            
        else:
            # Resend Green API WhatsApp OTP
            success, msg = send_green_api_otp(identifier, "resend_sms")
            if success:
                session['last_otp_time'] = time.time()
                flash(f"A new verification code has been sent via WhatsApp to {identifier}", "success")
            else:
                flash(msg, "error")
            
    except Exception as e:
        flash(str(e), "error")
        
    return redirect(url_for('verify_login_otp_page'))

# --- FORGOT PASSWORD ROUTES ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html', step=1)

    step = request.form.get('step')

    # --- STEP 1: Phone number lein aur OTP bhejein ---
    if step == 'send_otp':
        raw_phone = request.form.get('phone', '').strip()
        formatted_phone = format_phone(raw_phone)

        # Check if user exists
        user = users_collection.find_one({"phone": formatted_phone})
        if not user:
            flash("No account found with this phone number.", "error")
            return render_template('forgot_password.html', step=1)

        success, msg = send_green_api_otp(formatted_phone, "forgot_password_sms")
        if success:
            session['forgot_phone'] = formatted_phone
            session['forgot_otp_time'] = time.time()
            session['forgot_verified'] = False

            flash(f"Verification code sent via WhatsApp to {formatted_phone}", "success")
            return render_template('forgot_password.html', step=2, phone=formatted_phone)
        else:
            flash(msg, "error")
            return render_template('forgot_password.html', step=1)

    # --- STEP 2: OTP verify karein ---
    elif step == 'verify_otp':
        phone = request.form.get('phone', '')
        otp_code = request.form.get('otp', '')

        if not phone or phone != session.get('forgot_phone'):
            flash("Session expired. Please try again.", "error")
            return render_template('forgot_password.html', step=1)

        success, msg = verify_green_api_otp(phone, otp_code)
        if success:
            session['forgot_verified'] = True
            return render_template('forgot_password.html', step=3, phone=phone)
        else:
            flash(msg, "error")
            return render_template('forgot_password.html', step=2, phone=phone)

    # --- STEP 3: Naya password set karein ---
    elif step == 'reset_password':
        phone = request.form.get('phone', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Security checks
        if not session.get('forgot_verified') or phone != session.get('forgot_phone'):
            flash("Unauthorized request. Please restart.", "error")
            return render_template('forgot_password.html', step=1)

        is_strong, msg = is_strong_password(new_password)
        if not is_strong:
            flash(msg, "error")
            return render_template('forgot_password.html', step=3, phone=phone)

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('forgot_password.html', step=3, phone=phone)

        # Check if new password is same as old password
        user_data = users_collection.find_one({"phone": phone})
        if user_data and check_password_hash(user_data.get('password', ''), new_password):
            flash("New password cannot be the same as your current password. Please choose a different one.", "error")
            return render_template('forgot_password.html', step=3, phone=phone)

        try:
            hashed = generate_password_hash(new_password)
            users_collection.update_one(
                {"phone": phone},
                {"$set": {"password": hashed, "password_updated_at": datetime.now(timezone.utc)}}
            )

            # --- SEND CONFIRMATION EMAIL ---
            user_data = users_collection.find_one({"phone": phone})
            if user_data and user_data.get('email'):
                subject = "Security Alert: Password Changed Successfully"
                user_name = user_data.get('username', 'Valued Customer')
                
                # Format time for IST
                ist_now = datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime('%d %b %Y, %I:%M %p')
                
                email_html = f"""
                <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e2e8f0; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                    <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 40px 20px; text-align: center; color: white;">
                        <div style="background: rgba(255,255,255,0.2); width: 64px; height: 64px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px;">
                            <span style="font-size: 32px;">🔒</span>
                        </div>
                        <h1 style="margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.025em;">Password Reset Successful</h1>
                    </div>
                    
                    <div style="padding: 40px; background: #ffffff;">
                        <p style="font-size: 16px; color: #1f2937; margin-top: 0;">Hi <strong>{user_name}</strong>,</p>
                        <p style="font-size: 15px; color: #4b5563; line-height: 1.6;">The password for your Green Naturals account associated with <strong>{phone}</strong> has been successfully changed.</p>
                        
                        <div style="background: #f9fafb; border: 1px solid #f3f4f6; border-radius: 12px; padding: 24px; margin: 30px 0;">
                            <h3 style="margin: 0 0 10px 0; font-size: 14px; color: #374151; text-transform: uppercase; letter-spacing: 0.05em;">Security Details:</h3>
                            <table style="width: 100%; font-size: 14px; color: #6b7280;">
                                <tr>
                                    <td style="padding: 4px 0;">Time:</td>
                                    <td style="padding: 4px 0; text-align: right; color: #111827;">{ist_now} IST</td>
                                </tr>
                                <tr>
                                    <td style="padding: 4px 0;">Status:</td>
                                    <td style="padding: 4px 0; text-align: right; color: #059669; font-weight: 600;">Updated Successfully</td>
                                </tr>
                            </table>
                        </div>

                        <div style="background: #fffbeb; border-left: 4px solid #f59e0b; padding: 16px; margin-bottom: 30px;">
                            <p style="margin: 0; font-size: 14px; color: #92400e;"><strong>Didn't do this?</strong> If you didn't change your password, please contact our support team immediately to secure your account.</p>
                        </div>

                        <div style="text-align: center;">
                            <a href="https://greennaturals.store/login" style="background: #111827; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; display: inline-block;">Login to your account</a>
                        </div>
                    </div>
                    
                    <div style="background: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #f1f5f9;">
                        <p style="font-size: 12px; color: #94a3b8; margin: 0;">&copy; 2026 Green Naturals. All rights reserved.</p>
                    </div>
                </div>
                """
                
                # Send email in background
                threading.Thread(target=send_email, args=(
                    subject, 
                    email_html, 
                    user_data['email'], 
                    user_name, 
                    os.getenv("SENDER_EMAIL", "security@greennaturals.store"),
                    "Green Naturals Security"
                )).start()

            # Clear forgot password session data
            session.pop('forgot_phone', None)
            session.pop('forgot_otp_time', None)
            session.pop('forgot_verified', None)

            flash("Password reset successfully! Please login with your new password.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"Error resetting password: {str(e)}", "error")
            return render_template('forgot_password.html', step=3, phone=phone)

    return render_template('forgot_password.html', step=1)

# --- RESEND FORGOT PASSWORD OTP ---
@app.route('/resend-forgot-otp', methods=['POST'])
def resend_forgot_otp():
    phone = session.get('forgot_phone')
    if not phone:
        return jsonify({"status": "error", "msg": "Session expired. Please start over."})

    last_sent = session.get('forgot_otp_time', 0)
    if time.time() - last_sent < 30:
        return jsonify({"status": "error", "msg": "Please wait before requesting a new code."})

    success, msg = send_green_api_otp(phone, "forgot_password_sms")
    if success:
        session['forgot_otp_time'] = time.time()
        return jsonify({"status": "success", "msg": "New code sent via WhatsApp!"})
    else:
        return jsonify({"status": "error", "msg": msg})

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        try:
            user_id_obj = ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id
            users_collection.update_one(
                {"_id": user_id_obj},
                {"$unset": {"current_session_token": "", "last_active": ""}}
            )
        except Exception as e:
            print(f"Logout cleanup error: {e}")

    # Saari session keys remove karein (user_id, username, etc.)
    session.clear()
    flash("Successfully logged out", "success")
    
    # 'index' function ka naam hai jo '/' route handle karta hai
    return redirect(url_for('index'))

@app.route('/admin/manage-users') # URL ko template ke buttons se match karne ke liye update kiya
def manage_users():
    # 1. Session Security Check
    if not session.get('logged_in'): 
        return redirect(url_for('admin_login'))
    
    try:
        # 2. Database Fetching (Latest users first)
        # Agar created_at field nahi hai, toh automatic manage karne ke liye sorting
        all_users = list(users_collection.find().sort([("created_at", -1), ("_id", -1)]))
        
        # Recursive date cleaner to ensure JSON serializability
        def clean_dates(obj):
            if isinstance(obj, dict):
                return {k: clean_dates(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [clean_dates(i) for i in obj]
            elif isinstance(obj, datetime):
                return obj.strftime('%d %b %Y, %H:%M')
            elif isinstance(obj, ObjectId):
                return str(obj)
            else:
                return obj

        # 3. Data Cleaning and attaching Order metrics
        for i in range(len(all_users)):
            user = all_users[i]
            user['username'] = user.get('username', 'Unknown User')
            user['email'] = user.get('email', 'N/A')
            user['phone'] = user.get('phone', 'No Contact')
            user['password'] = user.get('password', 'HIDDEN_HASH') 
            user['status'] = user.get('status', 'active')
            
            # Fetch orders
            user_id_obj = user['_id']
            user_orders = list(orders_collection.find({"$or": [{"user_id": user_id_obj}, {"user_id": str(user_id_obj)}]}))
            user['total_orders'] = len(user_orders)
            user['order_list'] = []
            
            total_spent = 0
            for o in user_orders:
                amt = o.get('total')
                if amt:
                    try:
                        total_spent += float(str(amt).replace(',', '').replace('₹', '').strip())
                    except: pass
                
                user['order_list'].append({
                    "id": str(o.get('_id', '')),
                    "readable_id": o.get('order_id', str(o.get('_id', ''))[-6:].upper()),
                    "total": str(o.get('total', '0')),
                    "status": o.get('status', 'Pending'),
                    "date": o.get('created_at').strftime('%d %b %Y') if o.get('created_at') else 'N/A'
                })
            user['total_spent'] = total_spent
            user['_id'] = str(user['_id'])
            
            # Final Cleanup for JSON
            all_users[i] = clean_dates(user)

        return render_template('admin/manage_users.html', users=all_users)
        
    except Exception as e:
        print(f"Database Error: {e}")
        flash("Could not fetch users at this time.", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle-user-status', methods=['POST'])
def toggle_user_status():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "msg": "Unauthorized"}), 403
    
    data = request.json
    user_id = data.get('user_id')
    new_status = data.get('status') 
    
    if not user_id or not new_status:
        return jsonify({"status": "error", "msg": "Missing data"}), 400
        
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"status": new_status, "updated_at": datetime.now()}}
        )
        return jsonify({"status": "success", "msg": f"User account {new_status}"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route('/admin/toggle-user-suspect', methods=['POST'])
def toggle_user_suspect():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "msg": "Unauthorized"}), 401
    
    data = request.json
    user_id = data.get('user_id')
    is_suspect = data.get('is_suspected')
    
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_suspected": is_suspect}}
        )
        return jsonify({"status": "success", "msg": f"User marked as {'Suspected' if is_suspect else 'Safe'}"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@app.before_request
def check_user_suspension():
    if request.path.startswith('/static') or request.path in ['/login', '/admin-login']:
        return
        
    user_id = session.get('user_id')
    current_token = session.get('session_token')
    
    if user_id:
        try:
            # Update last_active every request
            users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"last_active": datetime.now(timezone.utc)}})
            
            user = users_collection.find_one({"_id": ObjectId(user_id)}, {"status": 1, "current_session_token": 1})
            
            # 1. Suspension Check
            if user and user.get('status') == 'suspended':
                session.clear()
                flash("Your account has been suspended. Please contact support.", "danger")
                return redirect(url_for('login'))
                
            # 2. Single Session Check
            db_token = user.get('current_session_token')
            if current_token and current_token != db_token:
                session.clear()
                flash("Your session has been terminated because you logged out from all devices or logged in elsewhere.", "danger")
                return redirect(url_for('login'))
        except:
            pass

@app.route('/admin/api/users')
def api_users():
    if not session.get('logged_in'):
        return jsonify([])
    users = list(users_collection.find({}, {"_id": 0}))
    return jsonify(users)

from flask import Flask, render_template, request, session, jsonify, redirect, url_for, flash
from bson import ObjectId

# --- 1. Route: Cart Page Render ---
from bson import ObjectId

@app.route('/cart')
def cart_page():
    # Default state for Guest User
    user_data = {
        'is_authenticated': False,
        'username': 'Guest',
        'address_snippet': None
    }

    if 'user_id' in session:
        try:
            user_id = session.get('user_id')
            
            # Check if user_id is a valid ObjectId before querying
            if ObjectId.is_valid(user_id):
                current_user = users_collection.find_one({"_id": ObjectId(user_id)})
                
                if current_user:
                    # Amazon style: Address ka snippet dikhana checkout trust badhata hai
                    address = current_user.get('address', 'No address saved')
                    address_snippet = (address[:30] + '...') if len(address) > 30 else address

                    user_data = {
                        'is_authenticated': True,
                        'username': current_user.get('username', 'User'),
                        'email': current_user.get('email'),
                        'profile_pic': current_user.get('profile_pic', '/static/images/default-avatar.png'),
                        'address_snippet': address_snippet
                    }
                else:
                    # Agar user_id session mein hai par DB mein nahi (rare case)
                    session.pop('user_id', None)
            
        except Exception as e:
            # Error log karein par page load hone dein
            print(f"🔴 Cart Page Error: {str(e)}")

    # Template ko user_data pass karein
    return render_template('cart.html', user=user_data)

from flask import request, jsonify
from bson import ObjectId

@app.route('/api/get-recommendations', methods=['POST']) # GET se POST kar diya
def get_recommendations():
    try:
        # Frontend se cart ki IDs mangwayein
        user_cart = request.json or {}  # Format: {"id1": 1, "id2": 2}
        cart_ids = [ObjectId(p_id) for p_id in user_cart.keys() if ObjectId.is_valid(p_id)]

        # MongoDB Pipeline: 
        # 1. Filter: Jo IDs cart_ids list mein NAHI hain ($nin)
        pipeline = [
            { "$match": { "_id": { "$nin": cart_ids } } }
        ]
        
        products = list(products_collection.aggregate(pipeline))
        
        recom_items = []
        for p in products:
            recom_items.append({
                "id": str(p['_id']),
                "name": p.get('name', 'Product'),
                "price": p.get('d_price', 0),
                "image": p.get('image_url', '/static/placeholder.png'),
                "category": p.get('category', 'General')
            })
            
        return jsonify({"recommendations": recom_items})
    except Exception as e:
        print(f"Recommendation Error: {e}")
        return jsonify({"recommendations": [], "error": str(e)}), 500
      
# --- 2. API: Cart Details Fetch (Security Check) ---
from bson import ObjectId

@app.route('/api/get-cart-details', methods=['POST'])
def get_cart_details():
    user_cart = request.json  # Format: {"id1": 2, "id2": 1}
    if not user_cart:
        return jsonify({"items": [], "total": 0, "shipping_charge": 0})

    response_items = []
    subtotal_sum = 0

    try:
        # 1. Database se current shipping fee nikaalein
        # 'settings' collection mein humne ek document rakha hai jiska key 'config' hai
        settings = db.settings.find_one({"type": "shipping_config"})
        shipping_charge = float(settings.get('fee', 0)) if settings else 0

        # 2. Valid ObjectIds ki list
        valid_ids = [ObjectId(p_id) for p_id in user_cart.keys() if ObjectId.is_valid(p_id)]

        # 3. Bulk fetch products
        products_cursor = products_collection.find({"_id": {"$in": valid_ids}})
        products_map = {str(p['_id']): p for p in products_cursor}

        # 4. Process items
        for p_id, qty in user_cart.items():
            product = products_map.get(p_id)
            if product:
                try:
                    current_qty = int(qty)
                    price = float(product.get('d_price', 0))
                    item_subtotal = price * current_qty
                    original_price = float(product.get('o_price', price))
                    
                    response_items.append({
                        "id": p_id,
                        "name": product.get('name'),
                        "price": price,
                        "original_price": original_price,
                        "image": product.get('image_url'), 
                        "category": product.get('category'),
                        "qty": current_qty,
                        "subtotal": item_subtotal
                    })
                    subtotal_sum += item_subtotal
                except (ValueError, TypeError):
                    continue

        # 5. Final Calculation
        grand_total = round(subtotal_sum + shipping_charge, 2)

        # Session update for checkout
        session['checkout_data'] = {
            "items": response_items,
            "subtotal": subtotal_sum,
            "shipping": shipping_charge,
            "total": grand_total
        }
        
        return jsonify({
            "items": response_items, 
            "subtotal": round(subtotal_sum, 2),
            "shipping_charge": shipping_charge,
            "total": grand_total
        })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "Something went wrong"}), 500

# --- 3. Route: Checkout Page (Login Protected) ---
@app.route('/checkout')
def checkout():
    # Login Check
    if 'user_id' not in session:
        flash("Please login to proceed to checkout", "info")
        return redirect(url_for('login', next=request.url))
    
    # Cart Data Check
    checkout_data = session.get('checkout_data')
    if not checkout_data or checkout_data['total'] == 0:
        flash("Your cart is empty!", "warning")
        return redirect(url_for('cart_page'))

    # User details for address form
    user_info = users_collection.find_one({"_id": ObjectId(session['user_id'])})

    return render_template('checkout.html', data=checkout_data, user=user_info)

@app.route('/api/get-checkout-data')
def get_checkout_data():
    if 'user_id' not in session:
        print("DEBUG: Checkout Data Fetch Failed - No User ID in session")
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    checkout_data = session.get('checkout_data')
    print(f"DEBUG: Session Checkout Data for {session['user_id']}: {checkout_data}")
    
    if not checkout_data:
        print("DEBUG: No checkout data found in session")
        return jsonify({"status": "error", "message": "No checkout data found"}), 404
        
    return jsonify(checkout_data)

@app.route('/admin/api/update-shipping', methods=['POST'])
def update_shipping():
    # Security Check (Optional: Add your admin login check here)
    # if not session.get('is_admin'): return jsonify({"error": "Unauthorized"}), 403

    try:
        data = request.json
        new_fee = data.get('shipping_charge')

        if new_fee is None:
            return jsonify({"error": "Amount is required"}), 400

        # Database mein settings update karein (upsert=True matlab agar nahi hai to bana dega)
        db.settings.update_one(
            {"type": "shipping_config"},
            {"$set": {"fee": float(new_fee)}},
            upsert=True
        )

        return jsonify({"status": "success", "message": "Shipping fee updated"}), 200

    except Exception as e:
        print(f"Admin Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/create-razorpay-order', methods=['POST'])
def create_razorpay_order():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        data = request.json
        amount = int(float(data.get('amount')) * 100) # Razorpay expects paisa
        
        # Create Razorpay Order
        razor_order = razorpay_client.order.create({
            "amount": amount,
            "currency": "INR",
            "payment_capture": 1 # Auto capture
        })
        
        return jsonify({
            "status": "success",
            "razorpay_order_id": razor_order['id'],
            "amount": amount
        })
    except Exception as e:
        safe_print(f"Razorpay Order Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

from datetime import datetime, timezone
import random
from bson import ObjectId
from flask import jsonify, request, session

@app.route('/api/place-order', methods=['POST'])
def place_order():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Please login first"}), 401

    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "No data received"}), 400

        customer_info = data.get('customer')
        cart_items = data.get('items')
        total_bill = data.get('total')
        payment_method = data.get('payment_method')
        payment_id = data.get('payment_id') # For COD this is 'COD_ORDER'
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_signature = data.get('razorpay_signature')

        # VERIFY PAYMENT SIGNATURE (Security First!)
        is_online_payment = payment_method != 'COD'
        if is_online_payment:
            try:
                razorpay_client.utility.verify_payment_signature({
                    'razorpay_order_id': razorpay_order_id,
                    'razorpay_payment_id': payment_id,
                    'razorpay_signature': razorpay_signature
                })
            except Exception as e:
                safe_print(f"❌ Payment Verification Failed: {e}")
                return jsonify({"status": "error", "message": "Payment verification failed. Security alert!"}), 400

        # Basic Validation
        if not customer_info or not customer_info.get('address'):
            return jsonify({"status": "error", "message": "Address details are missing"}), 400

        shipping_charge = data.get('shipping', 0)
        handling_fee = data.get('handling_fee', 0)
        round_off = data.get('round_off', 0)
        
        # Unique Order ID Generation
        order_id = f"GN-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

        # DATABASE DOCUMENT
        order_doc = {
            "order_id": order_id,
            "user_id": ObjectId(session['user_id']),
            "customer": {
                "name": customer_info.get('name'),
                "email": customer_info.get('email') or session.get('user_email'), # Keep historical email
                "phone": customer_info.get('phone'),
                "alt_phone": customer_info.get('alt_phone'),
                "address": customer_info.get('address'),
                "landmark": customer_info.get('landmark'),
                "city": customer_info.get('city'),
                "state": customer_info.get('state'),
                "pincode": customer_info.get('pincode')
            },
            "items": cart_items,
            "total": total_bill,
            "shipping": shipping_charge,
            "handling_fee": handling_fee,
            "round_off": round_off,
            "status": "CONFIRMED",
            "order_status": "confirmed",
            "payment_mode": payment_method,
            "payment_id": payment_id,
            "razorpay_order_id": razorpay_order_id,
            "razorpay_signature": razorpay_signature,
            "payment_status": "PAID" if is_online_payment else "PENDING",
            "created_at": datetime.now(timezone.utc)
        }

        # 1. MongoDB mein order insert karna
        result = orders_collection.insert_one(order_doc)
        
        if result.inserted_id:
            # 2. ADDRESS AUTO-SAVE LOGIC (with trimming to prevent duplicates)
            def clean_val(v): return str(v).strip() if v else ""
            
            new_address = {
                "name": clean_val(customer_info.get('name')),
                "phone": clean_val(customer_info.get('phone')),
                "alt_phone": clean_val(customer_info.get('alt_phone')),
                "address": clean_val(customer_info.get('address')),
                "landmark": clean_val(customer_info.get('landmark')),
                "city": clean_val(customer_info.get('city')),
                "state": clean_val(customer_info.get('state')),
                "pincode": clean_val(customer_info.get('pincode'))
            }

            users_collection.update_one(
                {"_id": ObjectId(session['user_id'])},
                {
                    "$addToSet": {"addresses": new_address},
                    "$set": {"last_used_address": new_address}
                }
            )

            # 3. THERMAL RECEIPT NOTIFICATION LOGIC
            try:
                current_user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
                user_email = current_user.get('email') if current_user else None

                # Thermal Items List Generation
                items_rows = ""
                item_subtotal = 0
                for item in cart_items:
                    item_amt = float(item.get('subtotal', float(item.get('price', 0)) * int(item.get('qty', 1))))
                    item_subtotal += item_amt
                    price_each = item_amt / max(int(item.get('qty', 1)), 1)
                    items_rows += f"""
                    <tr>
                        <td style="padding: 5px 0;">
                            {item['name'].upper()}<br>
                            <small>QTY: {item['qty']} x {price_each:.2f}</small>
                        </td>
                        <td style="padding: 5px 0; text-align: right; vertical-align: top;">{item_amt:.2f}</td>
                    </tr>"""

                alt_phone_val = customer_info.get('alt_phone')
                alt_phone_line = f"ALT PHONE: {alt_phone_val}<br>" if alt_phone_val else ""

                # Thermal Style HTML Template (Unified with PDF)
                thermal_body = f"""
                <div style="font-family: 'Helvetica', 'Arial', sans-serif; max-width: 450px; margin: auto; padding: 30px; border: 1px solid #eee; background-color: #fff; color: #1a1a1a; line-height: 1.4;">
                    <div style="text-align: center; border-bottom: 2px solid #000; padding-bottom: 15px; margin-bottom: 15px;">
                        <h2 style="margin: 0; font-size: 24px; font-weight: bold; text-transform: uppercase;">GREEN NATURALS</h2>
                        <p style="margin: 5px 0; font-size: 13px; color: #555;">Premium Organic Ayurvedic Store</p>
                    </div>

                    <div style="font-size: 13px; margin-bottom: 15px;">
                        <div style="font-size: 16px; margin-bottom: 5px;">ORDER ID: <b>#{order_id}</b></div>
                        <div style="margin-bottom: 3px;">DATE: <b>{datetime.now().strftime('%d %b %Y, %I:%M %p')}</b></div>
                        <div style="margin-bottom: 3px;">PAYMENT: <b>{payment_method.upper()}</b></div>
                    </div>

                    <div style="border-bottom: 1px dotted #888; margin: 15px 0;"></div>

                    <div style="font-size: 14px; margin-bottom: 15px;">
                        <div style="font-size: 18px; font-weight: bold; margin-bottom: 5px;">{customer_info.get('name', '').upper()}</div>
                        <div>Phone: {customer_info.get('phone')}</div>
                        <div>Address: {customer_info.get('address').upper()}, {customer_info.get('city', '').upper()}, {customer_info.get('state', '').upper()} - {customer_info.get('pincode')}</div>
                    </div>

                    <div style="border-bottom: 2px solid #000; margin: 15px 0;"></div>

                    <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                        <thead>
                            <tr style="border-bottom: 1px solid #000;">
                                <th style="text-align: left; padding-bottom: 10px;">ITEM</th>
                                <th style="text-align: right; padding-bottom: 10px;">AMT</th>
                            </tr>
                        </thead>
                        <tbody>
                            {items_rows}
                        </tbody>
                    </table>

                    <div style="border-bottom: 1px dotted #888; margin: 15px 0;"></div>

                    <div style="font-size: 14px;">
                        <table width="100%" border="0" cellpadding="0" cellspacing="0">
                            <tr><td style="padding-bottom: 5px;">SUBTOTAL:</td><td style="text-align: right; padding-bottom: 5px;">Rs. {item_subtotal:.2f}</td></tr>
                            <tr><td style="padding-bottom: 5px;">DELIVERY:</td><td style="text-align: right; padding-bottom: 5px;">{"FREE" if float(shipping_charge) <= 0 else f"Rs. {float(shipping_charge):.2f}"}</td></tr>
                            {" " if float(handling_fee) <= 0.01 else f'<tr><td style="padding-bottom: 5px;">HANDLING:</td><td style="text-align: right; padding-bottom: 5px;">Rs. {float(handling_fee):.2f}</td></tr>'}
                            {" " if abs(float(round_off)) < 0.01 else f'<tr><td style="padding-bottom: 5px; color: #666; font-style: italic;">ROUND OFF:</td><td style="text-align: right; padding-bottom: 5px; color: #666; font-style: italic;">{"+" if float(round_off) > 0 else "-" if float(round_off) < 0 else ""}Rs. {abs(float(round_off)):.2f}</td></tr>'}
                        </table>
                        
                        <div style="font-size: 24px; font-weight: bold; border-top: 2px solid #000; padding-top: 10px; margin-top: 10px;">
                            <table width="100%" border="0" cellpadding="0" cellspacing="0">
                                <tr><td>TOTAL:</td><td style="text-align: right;">Rs. {float(total_bill):.2f}</td></tr>
                            </table>
                        </div>
                    </div>

                    <div style="text-align: center; margin-top: 40px; font-size: 12px;">
                        <div style="font-size: 18px; font-weight: bold; margin-bottom: 5px;">*** THANK YOU ***</div>
                        <div>Visit again for more Organic Goodness</div>
                        <div style="margin-top: 20px; color: #888; font-size: 10px; border-top: 1px solid #eee; padding-top: 10px;">COMPUTER GENERATED INVOICE</div>
                    </div>
                </div>"""

                SENDER_EMAIL = os.getenv("SENDER_EMAIL")

                # 4. Generate Invoice PDF for attachment
                invoice_pdf = generate_invoice_pdf(order_doc)
                pdf_filename = f"Invoice_{order_id}.pdf" if invoice_pdf else None

                # 5. Sending Emails with Invoice PDF attached
                if user_email:
                    send_email(
                        subject=f"🔔 Order Confirmed: {order_id}", 
                        html_content=thermal_body, 
                        to_email=user_email, 
                        to_name=customer_info.get('name'),
                        sender_email=SENDER_EMAIL,
                        attachment_data=invoice_pdf,
                        attachment_filename=pdf_filename
                    )

                # Admin Notification with Invoice PDF
                send_email(
                    subject=f"🔔 NEW ORDER RECEIVED - {order_id}", 
                    html_content=thermal_body, 
                    to_email=os.getenv("ADMIN_GMAIL"), 
                    to_name="Green Naturals Admin",
                    sender_email=SENDER_EMAIL,
                    attachment_data=invoice_pdf,
                    attachment_filename=pdf_filename
                )

            except Exception as mail_err:
                print(f"📧 Mail Error Details: {str(mail_err)}")

            # Session Cleanup
            session.pop('checkout_data', None)
            return jsonify({"status": "success", "order_id": order_id})
        
        return jsonify({"status": "error", "message": "Failed to save order"}), 500

    except Exception as e:
        print(f"❌ CRITICAL ERROR: {str(e)}")
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500
      
@app.route('/admin/api/update-payment-methods', methods=['POST'])
def update_payment_methods():
    data = request.json
    method = data.get('method')   # 'cod' or 'online'
    enabled = data.get('enabled') # True or False
    
    if method == 'cod': field = "cod_enabled"
    elif method == 'online': field = "online_enabled"
    elif method == 'fetch_fee': field = "fetch_razorpay_fee"
    elif method == 'cod_fee': field = "charge_cod_fee"
    elif method == 'upi': field = "upi_enabled"
    elif method == 'card': field = "card_enabled"
    elif method == 'netbanking': field = "netbanking_enabled"
    elif method == 'wallet': field = "wallet_enabled"
    elif method == 'emi': field = "emi_enabled"
    elif method == 'paylater': field = "paylater_enabled"
    else: return jsonify({"status": "error", "message": "Invalid method"}), 400
    
    settings_collection.update_one(
        {"type": "payment_config"},
        {"$set": {field: enabled}},
        upsert=True
    )
    return jsonify({"status": "success"})

@app.route('/api/payment-config')
def public_payment_config():
    settings = settings_collection.find_one({"type": "payment_config"})
    return jsonify({
        "cod_enabled": settings.get('cod_enabled', True) if settings else True,
        "online_enabled": settings.get('online_enabled', True) if settings else True,
        "fetch_razorpay_fee": settings.get('fetch_razorpay_fee', True) if settings else True,
        "charge_cod_fee": settings.get('charge_cod_fee', True) if settings else True,
        "rzp_fee_percent": settings.get('rzp_fee_percent', 2.0) if settings else 2.0,
        "rzp_gst_percent": settings.get('rzp_gst_percent', 18.0) if settings else 18.0,
        "cod_fee": settings.get('cod_fee', 40.0) if settings else 40.0,
        "upi_enabled": settings.get('upi_enabled', True) if settings else True,
        "card_enabled": settings.get('card_enabled', True) if settings else True,
        "netbanking_enabled": settings.get('netbanking_enabled', True) if settings else True,
        "wallet_enabled": settings.get('wallet_enabled', True) if settings else True,
        "emi_enabled": settings.get('emi_enabled', True) if settings else True,
        "paylater_enabled": settings.get('paylater_enabled', True) if settings else True
    })

@app.route('/admin/api/update-payment-percentages', methods=['POST'])
def update_payment_percentages():
    data = request.json
    fee = data.get('rzp_fee_percent', 2.0)
    gst = data.get('rzp_gst_percent', 18.0)
    cod = data.get('cod_fee', 40.0)
    
    settings_collection.update_one(
        {"type": "payment_config"},
        {"$set": {"rzp_fee_percent": fee, "rzp_gst_percent": gst, "cod_fee": cod}},
        upsert=True
    )
    return jsonify({"status": "success"})

@app.route('/admin/api/get-payment-settings')
def get_payment_settings():
    settings = settings_collection.find_one({"type": "payment_config"})
    return jsonify({
        "cod_enabled": settings.get('cod_enabled', True) if settings else True,
        "online_enabled": settings.get('online_enabled', True) if settings else True,
        "fetch_razorpay_fee": settings.get('fetch_razorpay_fee', True) if settings else True,
        "charge_cod_fee": settings.get('charge_cod_fee', True) if settings else True,
        "rzp_fee_percent": settings.get('rzp_fee_percent', 2.0) if settings else 2.0,
        "rzp_gst_percent": settings.get('rzp_gst_percent', 18.0) if settings else 18.0,
        "cod_fee": settings.get('cod_fee', 40.0) if settings else 40.0,
        "upi_enabled": settings.get('upi_enabled', True) if settings else True,
        "card_enabled": settings.get('card_enabled', True) if settings else True,
        "netbanking_enabled": settings.get('netbanking_enabled', True) if settings else True,
        "wallet_enabled": settings.get('wallet_enabled', True) if settings else True,
        "emi_enabled": settings.get('emi_enabled', True) if settings else True,
        "paylater_enabled": settings.get('paylater_enabled', True) if settings else True,
        "razorpay_key_id": os.getenv("RAZORPAY_KEY_ID"),
        "razorpay_mode": os.getenv("RAZORPAY_MODE", "test")
    })

@app.route('/order-success')
def order_success():
    order_id = request.args.get('oid')
    
    if not order_id:
        return redirect('/') 

    if 'user_id' not in session:
        return redirect('/login')

    # Hum check karenge ki order exists karta hai aur isi user ka hai
    exists = orders_collection.find_one({
        "order_id": order_id,
        "user_id": ObjectId(session['user_id'])
    })

    if not exists:
        return redirect('/')

    # Session cleanup
    session.pop('checkout_data', None)
    
    # Sirf page dikhao, data JS fetch kar lega
    return render_template('order-success.html')

from flask import jsonify

@app.route('/api/get-order-details')
def get_order_details():
    order_id = request.args.get('oid')
    
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    try:
        # Database se order fetch karo
        order = orders_collection.find_one({
            "order_id": order_id,
            "user_id": ObjectId(session['user_id'])
        })

        if not order:
            return jsonify({"status": "error", "message": "Order not found"}), 404

        # Debugging ke liye terminal mein check karein (optional)
        # print(f"DEBUG: Order Found - {order}")
        # Frontend JS ke liye clean JSON taiyar karein
        return jsonify({
            "status": "success",
            "order": {
                "order_id": order.get('order_id'),
                "created_at": order.get('created_at'),
                
                "payment_method": order.get('payment_mode', 'COD'), 
                "payment_status": order.get('payment_status', 'Pending'),
                "razorpay_payment_id": order.get('payment_id'),
                "razorpay_order_id": order.get('razorpay_order_id'),
                
                # Customer Details (Aapke schema ke hisab se)
                "customer_name": order.get('customer', {}).get('name'),
                "customer_phone": order.get('customer', {}).get('phone'),
                "customer_alt_phone": order.get('customer', {}).get('alt_phone'),
                "customer_address": order.get('customer', {}).get('address'),
                "customer_city": order.get('customer', {}).get('city'),
                "customer_state": order.get('customer', {}).get('state'),
                "customer_pincode": order.get('customer', {}).get('pincode'),
                "customer_landmark": order.get('customer', {}).get('landmark'),
                
                # Items aur Totals
                "items": order.get('items', []),
                "shipping": order.get('shipping', 0),
                "handling_fee": order.get('handling_fee', 0),
                "round_off": order.get('round_off', 0),
                "total_amount": order.get('total_amount') or order.get('total'),
                "date_formatted": (order.get('created_at') + timedelta(hours=5, minutes=30)).strftime('%d %b %Y, %I:%M %p') if order.get('created_at') else 'N/A'
            }
        })

    except Exception as e:
        print(f"❌ API Error: {str(e)}")
        return jsonify({"status": "error", "message": "Server error occurred"}), 500
    
from flask import jsonify, session
from bson import ObjectId

@app.route('/api/get-user-addresses') # Plural name (optional but recommended)
def get_user_addresses():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
    
    if user:
        # 1. Agar 'addresses' naam ki list exist karti hai toh wo bhejo
        if 'addresses' in user and isinstance(user['addresses'], list):
            return jsonify({
                "status": "success", 
                "addresses": user['addresses']
            })
            
        # 2. Fallback: Agar sirf ek purana 'saved_address' (single object) hai
        elif 'saved_address' in user and user['saved_address']:
            return jsonify({
                "status": "success", 
                "addresses": [user['saved_address']] # Isko list bana kar bheja
            })
    
    # 3. Agar koi address nahi mila
    return jsonify({"status": "no_address", "addresses": []})

@app.route('/api/add-address', methods=['POST'])
def add_address():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "Missing data"}), 400
        
    def clean_val(v): return str(v).strip() if v else ""
    
    new_address = {
        "name": clean_val(data.get('name')),
        "phone": clean_val(data.get('phone')),
        "alt_phone": clean_val(data.get('alt_phone')),
        "address": clean_val(data.get('address')),
        "landmark": clean_val(data.get('landmark')),
        "city": clean_val(data.get('city')),
        "state": clean_val(data.get('state')),
        "pincode": clean_val(data.get('pincode'))
    }
    
    # Required fields check
    if not all([new_address['name'], new_address['phone'], new_address['address'], new_address['city'], new_address['pincode']]):
        return jsonify({"status": "error", "message": "Please fill all required fields"}), 400

    user = db.users.find_one({"_id": ObjectId(session['user_id'])})
    if user and 'addresses' in user:
        for addr in user['addresses']:
            if (addr.get('name') == new_address['name'] and 
                addr.get('address') == new_address['address'] and 
                addr.get('pincode') == new_address['pincode'] and
                addr.get('phone') == new_address['phone']):
                return jsonify({"status": "error", "message": "This address already exists in your saved list!"}), 400

    users_collection.update_one(
        {"_id": ObjectId(session['user_id'])},
        {"$addToSet": {"addresses": new_address}}
    )
    
    return jsonify({"status": "success", "message": "Address added successfully"})

@app.route('/api/delete-address/<int:index>', methods=['POST'])
def delete_address(index):
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    user = db.users.find_one({"_id": ObjectId(session['user_id'])})
    if not user or 'addresses' not in user:
        return jsonify({"status": "error", "message": "User or addresses not found"}), 404

    addresses = user['addresses']
    if 0 <= index < len(addresses):
        removed_addr = addresses.pop(index)
        db.users.update_one(
            {"_id": ObjectId(session['user_id'])},
            {"$set": {"addresses": addresses}}
        )
        return jsonify({"status": "success", "message": "Address deleted successfully"})
    else:
        return jsonify({"status": "error", "message": "Invalid address index"}), 400

from bson.objectid import ObjectId
from flask import render_template, session, flash, redirect, url_for

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("Unauthorized access! Please login.", "error")
        return redirect(url_for('login'))

    # Database se user fetch karein
    user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
    
    if not user:
        flash("User not found!", "error")
        return redirect(url_for('logout'))

    # Secondary Sync: Ensure session image is always fresh from DB
    session['profile_image'] = user.get('profile_image', '')
    session.modified = True

    # Template render karein (Pura 'user' object pass kar rahe hain)
    response = make_response(render_template('profile.html', user=user))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.route('/api/user-stats')
def user_stats():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        user_query = _user_order_query()
        order_count = orders_collection.count_documents(user_query)
        
        user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
        address_count = len(user.get('addresses', [])) if user else 0
        
        # Calculate average rating if any
        pipeline = [
            {"$match": {"$and": [user_query, {"rating": {"$exists": True}}]}},
            {"$group": {"_id": None, "avgRating": {"$avg": "$rating"}}}
        ]
        rating_result = list(orders_collection.aggregate(pipeline))
        avg_rating = rating_result[0]['avgRating'] if rating_result else 0.0

        return jsonify({
            "order_count": order_count,
            "address_count": address_count,
            "avg_rating": round(avg_rating, 1)
        })
    except Exception as e:
        safe_print(f"Stats Error: {e}")
        return jsonify({"order_count": 0, "address_count": 0, "avg_rating": 0.0})

@app.route('/invoice/<order_id>')
def view_invoice(order_id):
    if 'user_id' not in session:
        flash("Please login to view invoice", "error")
        return redirect(url_for('login'))
    
    try:
        # Find order - try multiple approaches
        order = orders_collection.find_one({"order_id": order_id})
        
        if not order:
            flash("Invoice not found.", "error")
            return redirect(url_for('my_orders'))
        
        # Build a simple dict for the template - NO _process_safe_order
        raw = dict(order)
        
        # Extract customer info from nested 'customer' object
        customer = raw.get('customer', {}) or {}
        
        # Build address string
        addr_parts = [
            customer.get('address', ''),
            customer.get('landmark', ''),
            customer.get('city', ''),
            customer.get('state', ''),
            customer.get('pincode', '')
        ]
        full_address = ', '.join([p for p in addr_parts if p])
        
        # Process items
        items = raw.get('items', [])
        processed_items = []
        subtotal = 0.0
        for item in items:
            if not isinstance(item, dict):
                continue
            price = float(item.get('price', 0) or 0)
            qty = int(item.get('quantity', item.get('qty', 1)) or 1)
            line_total = float(item.get('subtotal', item.get('line_total', 0)) or 0)
            if line_total == 0:
                line_total = round(price * qty, 2)
            subtotal += line_total
            processed_items.append({
                'name': item.get('name', 'Product'),
                'quantity': qty,
                'price': price,
                'line_total': line_total
            })
        
        total = float(raw.get('total', raw.get('total_amount', 0)) or 0)
        if total <= 0:
            total = subtotal
        shipping = float(raw.get('shipping', 0))
        handling_fee = float(raw.get('handling_fee', 0))
        
        # Get created_at and convert to IST
        from datetime import timedelta
        created_at = raw.get('created_at')
        if isinstance(created_at, datetime):
            created_at = created_at + timedelta(hours=5, minutes=30)
        
        # Payment method
        pm = raw.get('payment_method') or raw.get('payment_mode') or 'Online'
        
        # Round Off
        round_off = float(raw.get('round_off', 0))
        
        invoice_data = {
            '_id': str(raw.get('_id', '')),
            'order_id': raw.get('order_id', order_id),
            'customer_name': customer.get('name', 'Valued Customer'),
            'shipping_address': full_address or 'No address provided',
            'phone': customer.get('phone', 'N/A'),
            'created_at': created_at,
            'delivery_date': raw.get('updated_at', raw.get('expected_delivery', created_at)),
            'payment_method': str(pm).upper(),
            'razorpay_payment_id': raw.get('payment_id'),
            'razorpay_order_id': raw.get('razorpay_order_id'),
            'items': processed_items,
            'subtotal': round(subtotal, 2),
            'shipping': round(shipping, 2),
            'handling_fee': round(handling_fee, 2),
            'round_off': round(round_off, 2),
            'total': round(total, 2),
            'current_status': str(raw.get('current_status', raw.get('status', 'confirmed'))).lower()
        }
        
        print(f"[Invoice] Rendering for {order_id} with {len(processed_items)} items, total={total}")
        
        # Fetch payment config settings for FREE display logic
        settings = settings_collection.find_one({"type": "payment_config"})
        fetch_fee = settings.get('fetch_razorpay_fee', True) if settings else True
        charge_cod_fee = settings.get('charge_cod_fee', True) if settings else True

        return render_template('invoice.html', 
                               order=invoice_data,
                               fetch_fee=fetch_fee,
                               charge_cod_fee=charge_cod_fee)
        
    except Exception as e:
        print(f"[Invoice] CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading invoice.", "error")
        return redirect(url_for('my_orders'))

@app.route('/profile/upload-photo', methods=['POST'])
def upload_profile_photo():
    if 'user_id' not in session:
        flash("Please login first.", "error")
        return redirect(url_for('login'))

    image_file = request.files.get('profile_image')
    if not image_file or image_file.filename == "":
        flash("Please select an image file.", "error")
        return redirect(url_for('profile'))

    try:
        current_user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
        old_public_id = current_user.get('profile_image_id') if current_user else None

        upload_result = cloudinary.uploader.upload(
            image_file,
            folder="green_naturals_profiles",
            resource_type="image"
        )

        users_collection.update_one(
            {"_id": ObjectId(session['user_id'])},
            {"$set": {
                "profile_image": upload_result.get('secure_url'),
                "profile_image_id": upload_result.get('public_id'),
                "updated_at": datetime.now(timezone.utc)
            }}
        )

        # Update session immediately for real-time UI refresh
        session['profile_image'] = upload_result.get('secure_url')
        session.modified = True

        if old_public_id:
            try:
                cloudinary.uploader.destroy(old_public_id)
            except Exception as cleanup_error:
                safe_print(f"Profile old image cleanup skipped: {safe_str(cleanup_error)}")

        flash("Profile photo updated successfully.", "success")
    except Exception as e:
        safe_print(f"Profile image upload error: {safe_str(e)}")
        flash("Image upload failed. Please try again.", "error")
    
    return redirect(url_for('profile'))

@app.route('/profile/remove-photo', methods=['POST'])
def remove_profile_photo():
    if 'user_id' not in session:
        flash("Please login first.", "error")
        return redirect(url_for('login'))

    try:
        current_user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
        public_id = current_user.get('profile_image_id') if current_user else None

        if public_id:
            # Cloudinary deletion background mein daal rahe hain taaki response fast ho jaye
            threading.Thread(target=cloudinary.uploader.destroy, args=(public_id,)).start()

        users_collection.update_one(
            {"_id": ObjectId(session['user_id'])},
            {
                "$unset": {
                    "profile_image": "",
                    "profile_image_id": ""
                },
                "$set": {
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )

        # Clear session immediately for real-time UI refresh
        session['profile_image'] = ''
        session.modified = True

        flash("Profile photo removed successfully.", "success")
    except Exception as e:
        safe_print(f"Profile image removal error: {safe_str(e)}")
        flash("Failed to remove profile photo. Please try again.", "error")

    return redirect(url_for('profile'))

@app.route('/api/update-profile-name', methods=['POST'])
def update_profile_name():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json()
    new_name = data.get('new_name', '').strip()

    if not new_name:
        return jsonify({"success": False, "error": "Name cannot be empty"}), 400
    
    if len(new_name) > 30:
        return jsonify({"success": False, "error": "Name is too long (max 30 chars)"}), 400

    try:
        user_id = session.get('user_id')
        user_id_obj = ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id
        
        users_collection.update_one(
            {"_id": user_id_obj},
            {"$set": {
                "username": new_name,
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        
        # Update session
        session['username'] = new_name
        session.modified = True
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/request-password-change', methods=['POST'])
def request_password_change():
    if not session.get('user_id'):
        return jsonify({"success": False, "error": "Session expired. Please login again."}), 401
    
    data = request.get_json()
    current_pw = data.get('current_password')
    new_pw = data.get('new_password')
    is_forgot = data.get('is_forgot', False)
    
    uid = session.get('user_id')
    user = users_collection.find_one({"_id": ObjectId(uid) if ObjectId.is_valid(uid) else uid})
    
    if not user:
        return jsonify({"success": False, "error": "User not found."}), 404
        
    # 1. Normal Flow Verification
    if not is_forgot:
        if not new_pw:
            return jsonify({"success": False, "error": "New password is required."}), 400
        if not current_pw:
            return jsonify({"success": False, "error": "Current password is required."}), 400
        if not check_password_hash(user.get('password', ''), current_pw):
            return jsonify({"success": False, "error": "Incorrect current password."}), 400
        if check_password_hash(user.get('password', ''), new_pw):
            return jsonify({"success": False, "error": "New password cannot be the same as your current password."}), 400
        is_strong, msg = is_strong_password(new_pw)
        if not is_strong:
            return jsonify({"success": False, "error": msg}), 400
        session['temp_new_password'] = generate_password_hash(new_pw)
    else:
        # Forgot Flow: No passwords required yet
        session.pop('temp_new_password', None)
        
    # 2. Generate and Send OTP
    if not user.get('email'):
        return jsonify({"success": False, "error": "Email address not found in profile."}), 400
        
    otp = str(random.randint(100000, 999999))
    log_otp(user.get('email'), "password_change", otp)
    session['password_change_otp'] = otp
    session['password_otp_time'] = time.time()
    session['password_change_is_forgot'] = is_forgot
    
    # Send OTP Email
    subject = "Verification Code: Change Password"
    user_name = user.get('username', 'Valued Customer')
    
    email_html = f"""
    <div style="font-family: sans-serif; max-width: 500px; margin: auto; padding: 30px; border: 1px solid #ecfdf5; border-radius: 24px; text-align: center; background: #ffffff; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);">
        <img src="https://greennaturals.store/static/images/official_brand_logo.png" style="width: 60px; height: 60px; margin-bottom: 20px;">
        <h2 style="color: #064e3b; margin-bottom: 10px; font-size: 24px;">Security Verification</h2>
        <p style="color: #374151; font-size: 15px; line-height: 1.5;">Use the following code to verify your password change request:</p>
        <div style="background: #ecfdf5; padding: 20px; border-radius: 16px; margin: 25px 0; font-size: 36px; font-weight: 800; letter-spacing: 0.3em; color: #059669; border: 1px dashed #10b981;">
            {otp}
        </div>
        <p style="color: #6b7280; font-size: 12px;">This code will expire in 10 minutes. If you didn't request this, please secure your account.</p>
    </div>
    """
    
    from threading import Thread
    Thread(target=send_email, args=(
        subject, 
        email_html, 
        user['email'], 
        user_name, 
        os.getenv("SENDER_EMAIL", "security@greennaturals.store"),
        "Green Naturals Security"
    )).start()

    return jsonify({"success": True})

@app.route('/api/confirm-password-change', methods=['POST'])
def confirm_password_change():
    if not session.get('user_id'):
        return jsonify({"success": False, "error": "Session expired."}), 401
        
    data = request.get_json()
    otp_entered = data.get('otp')
    new_pw = data.get('new_password') # Provided only in Forgot flow Step 3
    
    stored_otp = session.get('password_change_otp')
    hashed_new_pw = session.get('temp_new_password')
    is_forgot = session.get('password_change_is_forgot', False)
    otp_time = session.get('password_otp_time', 0)
    
    if not stored_otp:
        return jsonify({"success": False, "error": "Request expired."}), 400
        
    if time.time() - otp_time > 600:
        return jsonify({"success": False, "error": "OTP has expired."}), 400
        
    if otp_entered != stored_otp:
        return jsonify({"success": False, "error": "Invalid verification code."}), 400
        
    # If forgot flow and we are at step 3 (new_pw provided)
    uid = session.get('user_id')
    user = users_collection.find_one({"_id": ObjectId(uid) if ObjectId.is_valid(uid) else uid})
    
    if is_forgot:
        if not new_pw:
            # Step 2 complete, tell frontend to show Step 3
            return jsonify({"success": True, "step": 3})
        
        # Step 3: Validate and set new password
        if check_password_hash(user.get('password', ''), new_pw):
            return jsonify({"success": False, "error": "New password cannot be the same as old."}), 400
        is_strong, msg = is_strong_password(new_pw)
        if not is_strong:
            return jsonify({"success": False, "error": msg}), 400
        hashed_new_pw = generate_password_hash(new_pw)
    
    if not hashed_new_pw:
        return jsonify({"success": False, "error": "Password data missing."}), 400

    # Final Success: Update Database
    users_collection.update_one(
        {"_id": user['_id']},
        {"$set": {"password": hashed_new_pw, "password_updated_at": datetime.now(timezone.utc)}}
    )
    
    # Send Confirmation Email
    if user.get('email'):
        subject = "Security Alert: Password Updated"
        user_name = user.get('username', 'Valued Customer')
        ist_now = datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime('%d %b %Y, %I:%M %p')
        
        email_html = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; border: 1px solid #e2e8f0; border-radius: 16px; overflow: hidden; background: #ffffff;">
            <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 40px; text-align: center; color: white;">
                <h1 style="margin: 0; font-size: 24px; font-weight: 800;">Password Updated</h1>
            </div>
            <div style="padding: 40px;">
                <p>Hi <strong>{user_name}</strong>,</p>
                <p>The password for your Green Naturals account has been successfully changed.</p>
                <div style="background: #f0fdf4; border: 1px solid #dcfce7; border-radius: 12px; padding: 20px; margin: 25px 0;">
                    <p style="margin: 0; font-size: 13px; color: #166534;"><strong>Time:</strong> {ist_now} IST</p>
                    <p style="margin: 5px 0 0; font-size: 13px; color: #166534;"><strong>Method:</strong> Security Modal (Verified)</p>
                </div>
            </div>
        </div>
        """
        from threading import Thread
        Thread(target=send_email, args=(subject, email_html, user['email'], user_name, os.getenv("SENDER_EMAIL"), "Green Naturals Security")).start()

    # Clean up
    session.pop('password_change_otp', None)
    session.pop('temp_new_password', None)
    session.pop('password_otp_time', None)
    session.pop('password_change_is_forgot', None)
    
    return jsonify({"success": True})

@app.route('/api/request-email-change', methods=['POST'])
def request_email_change():
    if not session.get('user_id'):
        return jsonify({"success": False, "error": "Session expired."}), 401
    
    data = request.get_json()
    new_email = data.get('new_email', '').strip().lower()
    
    if not new_email or '@' not in new_email:
        return jsonify({"success": False, "error": "Invalid email address."}), 400

    uid = session.get('user_id')
    user = users_collection.find_one({"_id": ObjectId(uid) if ObjectId.is_valid(uid) else uid})
    if not user:
        return jsonify({"success": False, "error": "User not found."}), 404

    # 24-Hour Restriction Check
    last_update = user.get('email_updated_at')
    if last_update:
        if isinstance(last_update, datetime):
            # Ensure last_update is timezone-aware
            if last_update.tzinfo is None:
                last_update = last_update.replace(tzinfo=timezone.utc)
            
            diff = datetime.now(timezone.utc) - last_update
            if diff.total_seconds() < 86400:
                hours_left = int((86400 - diff.total_seconds()) // 3600)
                mins_left = int(((86400 - diff.total_seconds()) % 3600) // 60)
                return jsonify({
                    "success": False, 
                    "error": f"Security limit: You can change your email once every 24 hours. Please wait {hours_left}h {mins_left}m."
                }), 403
    
    # Check if email is already in use
    existing_user = users_collection.find_one({"email": new_email})
    if existing_user:
        return jsonify({"success": False, "error": "Email is already in use by another account."}), 400
    
    # Generate OTP (Refreshed on every request)
    otp = str(random.randint(100000, 999999))
    log_otp(new_email, "email_change", otp)
    session['email_change_otp'] = otp
    session['email_change_target'] = new_email
    session['email_otp_time'] = time.time()
    session.modified = True
    
    safe_print(f"📧 Email Change OTP Refreshed: {otp} for {new_email}")
    subject = "Verification Code: Update Email Address"
    email_html = f"""
    <div style="font-family: sans-serif; max-width: 500px; margin: auto; padding: 30px; border: 1px solid #e0f2fe; border-radius: 24px; text-align: center; background: #ffffff;">
        <h2 style="color: #0369a1; margin-bottom: 10px;">Verify Your New Email</h2>
        <p style="color: #4b5563; font-size: 15px;">Use the code below to verify your new email address on Green Naturals:</p>
        <div style="background: #f0f9ff; padding: 20px; border-radius: 16px; margin: 25px 0; font-size: 36px; font-weight: 800; color: #0284c7; border: 1px dashed #0ea5e9;">
            {otp}
        </div>
        <p style="color: #9ca3af; font-size: 12px;">If you didn't request this change, you can safely ignore this email.</p>
    </div>
    """
    
    from threading import Thread
    Thread(target=send_email, args=(
        subject, 
        email_html, 
        new_email, 
        "User", 
        os.getenv("SENDER_EMAIL", "security@greennaturals.store"),
        "Green Naturals Security"
    )).start()
    
    return jsonify({"success": True})

@app.route('/api/confirm-email-change', methods=['POST'])
def confirm_email_change():
    if not session.get('user_id'):
        return jsonify({"success": False, "error": "Session expired."}), 401
    
    data = request.get_json()
    otp_entered = data.get('otp')
    
    stored_otp = session.get('email_change_otp')
    new_email = session.get('email_change_target')
    otp_time = session.get('email_otp_time', 0)
    
    if not stored_otp or not new_email:
        return jsonify({"success": False, "error": "Request expired or not found."}), 400
    
    if time.time() - otp_time > 600:
        return jsonify({"success": False, "error": "OTP has expired."}), 400
        
    safe_print(f"🔍 Verifying Email OTP: Entered={otp_entered}, Stored={stored_otp}")
    
    if str(otp_entered).strip() != str(stored_otp).strip():
        return jsonify({"success": False, "error": "Invalid verification code."}), 400
    
    # Double check if email was taken while waiting for OTP
    if users_collection.find_one({"email": new_email}):
         return jsonify({"success": False, "error": "Email was just taken by another user."}), 400

    # Update User
    uid = session['user_id']
    now = datetime.now(timezone.utc)
    users_collection.update_one(
        {"_id": ObjectId(uid) if ObjectId.is_valid(uid) else uid},
        {"$set": {
            "email": new_email, 
            "email_updated_at": now,
            "updated_at": now
        }}
    )
    
    # Update session
    session['user_email'] = new_email
    
    # Clean up
    session.pop('email_change_otp', None)
    session.pop('email_change_target', None)
    session.pop('email_otp_time', None)
    
    return jsonify({"success": True})

from bson import ObjectId
from datetime import datetime, timezone
import re

# ---------- Admin Orders Page ----------
@app.route('/admin/orders')
def admin_orders_page():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin/orders.html')

@app.route('/admin/returns')
def admin_returns_page():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    return_config = settings_collection.find_one({"type": "return_settings"})
    return_settings = return_config if return_config else {"allow_return": True, "allow_exchange": True}
    
    return render_template('admin_returns.html', return_settings=return_settings)

@app.route('/admin/api/update-return-settings', methods=['POST'])
def update_return_settings():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    try:
        data = request.json
        settings_collection.update_one(
            {"type": "return_settings"},
            {"$set": {
                "allow_return": data.get("allow_return", True),
                "allow_exchange": data.get("allow_exchange", True)
            }},
            upsert=True
        )
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

import csv
from io import StringIO
from flask import Response

@app.route('/admin/api/orders/export', methods=['GET', 'POST'])
def admin_export_orders():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    from datetime import datetime, timedelta, timezone

    status = request.args.get('status')   
    search = request.args.get('search')   
    limit = int(request.args.get('limit', 1000))
    format_type = request.args.get('format', 'excel')
    action = request.args.get('action', 'download')
    email_addr = request.args.get('email', '')
    timeframe = request.args.get('timeframe', 'all')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = {}

    if status and status != "all":
        query["order_status"] = status.lower()

    if search:
        query["$or"] = [
            {"customer.phone": {"$regex": search, "$options": "i"}},
            {"order_id": {"$regex": search, "$options": "i"}},
            {"customer.name": {"$regex": search, "$options": "i"}}
        ]
        
    now_utc = datetime.now(timezone.utc)
    if timeframe == '1_month':
        query["created_at"] = {"$gte": now_utc - timedelta(days=30)}
    elif timeframe == '3_months':
        query["created_at"] = {"$gte": now_utc - timedelta(days=90)}
    elif timeframe == '6_months':
        query["created_at"] = {"$gte": now_utc - timedelta(days=180)}
    elif timeframe == '12_months':
        query["created_at"] = {"$gte": now_utc - timedelta(days=365)}
    elif timeframe == 'custom' and start_date and end_date:
        try:
            sd = datetime.strptime(start_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            # Subtract 5:30 to match IST input assuming they select dates in their local timezone?
            # Actually simplest is just to take 00:00 to 23:59
            ed = datetime.strptime(end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            query["created_at"] = {"$gte": sd, "$lte": ed}
        except Exception as e:
            safe_print(f"DEBUG: Date parsing error: {e}")

    orders = list(orders_collection.find(query).sort("created_at", -1).limit(limit))

    if format_type == 'pdf':
        from xhtml2pdf import pisa
        import io
        html = """
        <html>
        <head>
            <style>
                @page { size: A4 landscape; margin: 1cm; }
                body { font-family: 'Helvetica', 'Arial', sans-serif; font-size: 10px; }
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid #ccc; padding: 5px; text-align: left; }
                th { background-color: #f8fafc; font-weight: bold; }
                h2 { text-align: center; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <h2>Green Naturals - Orders Export</h2>
            <table>
                <thead>
                    <tr>
                        <th>S.No.</th>
                        <th>Order ID</th>
                        <th>Date</th>
                        <th>Customer</th>
                        <th>Phone</th>
                        <th>Total</th>
                        <th>Payment</th>
                        <th>Status</th>
                        <th>Items</th>
                    </tr>
                </thead>
                <tbody>
        """
        for i, o in enumerate(orders, 1):
            cust = o.get("customer", {})
            created_at = o.get('created_at', '')
            if isinstance(created_at, datetime):
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                ist_time = created_at.astimezone(timezone(timedelta(hours=5, minutes=30)))
                created_at = ist_time.strftime('%Y-%m-%d %H:%M:%S')
                
            items_str = ", ".join([f"{item.get('name')} (x{item.get('quantity', item.get('qty', 1))})" for item in o.get('items', [])])
            html += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{o.get('order_id', '')}</td>
                        <td>{created_at}</td>
                        <td>{cust.get('name', '')}</td>
                        <td>{cust.get('phone', '')}</td>
                        <td>Rs. {o.get('total', o.get('total_amount', 0))}</td>
                        <td>{o.get('payment_mode', 'COD')}</td>
                        <td>{o.get('order_status', o.get('status', ''))}</td>
                        <td>{items_str}</td>
                    </tr>
            """
        html += """
                </tbody>
            </table>
        </body>
        </html>
        """
        pdf_out = io.BytesIO()
        pisa_status = pisa.CreatePDF(io.BytesIO(html.encode("utf-8")), dest=pdf_out)
        if pisa_status.err:
            return jsonify({"error": "Failed to generate PDF"}), 500
        content_data = pdf_out.getvalue()
        filename = f"orders_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        mimetype = 'application/pdf'
    else:
        # Generate CSV
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["S.No.", "Order ID", "Date", "Customer Name", "Customer Phone", "Total Amount", "Payment Mode", "Order Status", "Items"])
        for i, o in enumerate(orders, 1):
            cust = o.get("customer", {})
            items_str = " | ".join([f"{item.get('name')} (x{item.get('quantity', item.get('qty', 1))})" for item in o.get('items', [])])
            created_at = o.get('created_at', '')
            if isinstance(created_at, datetime):
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                ist_time = created_at.astimezone(timezone(timedelta(hours=5, minutes=30)))
                created_at = ist_time.strftime('%Y-%m-%d %H:%M:%S')
                
            writer.writerow([
                i,
                o.get('order_id', ''),
                created_at,
                cust.get('name', ''),
                cust.get('phone', ''),
                o.get('total', o.get('total_amount', 0)),
                o.get('payment_mode', o.get('payment_method', 'COD')),
                o.get('order_status', o.get('status', '')),
                items_str
            ])
        content_data = output.getvalue().encode('utf-8')
        filename = f"orders_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        mimetype = 'text/csv'

    if action == 'email':
        if not email_addr:
            return jsonify({"error": "Email address required"}), 400
        
        sender_mail = os.getenv("SENDER_EMAIL", "noreply@greennaturals.store")
        html_msg = f"<p>Hello Admin,</p><p>Please find the requested orders export ({format_type.upper()}) attached to this email.</p><p>Regards,<br>Green Naturals System</p>"
        success = send_email("Green Naturals - Orders Export", html_msg, email_addr, "Admin", sender_mail, attachment_data=content_data, attachment_filename=filename)
        
        if success:
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Failed to send email"}), 500
    else:
        return Response(content_data, mimetype=mimetype, headers={"Content-Disposition": f"attachment; filename={filename}"})

# ---------- API: Get Orders (Updated fields) ----------
@app.route('/admin/api/orders', methods=['GET'])
def admin_get_orders():
    print(f"[DEBUG] Admin API Access - Session logged_in: {session.get('logged_in')}")
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    status = request.args.get('status')   
    search = request.args.get('search')   
    try:
        limit = int(request.args.get('limit', 50))
    except:
        limit = 50

    query = {}

    if status and status != "all":
        if status == "returns":
            query["return_requested"] = True
        else:
            query["order_status"] = status.lower()

    if search:
        query["$or"] = [
            {"customer.phone": {"$regex": search, "$options": "i"}},
            {"order_id": {"$regex": search, "$options": "i"}},
            {"customer.name": {"$regex": search, "$options": "i"}}
        ]

    total_count = orders_collection.count_documents(query)
    orders = list(orders_collection.find(query).sort("created_at", -1).limit(limit))

    for o in orders:
        o["_id"] = str(o["_id"])
        uid = o.get("user_id")
        o["user_id"] = str(uid) if uid else ""
        
        # Backend fetch for email if not in order
        if not o.get("customer", {}).get("email") and uid:
            try:
                user = users_collection.find_one({"_id": ObjectId(uid)})
                if user and user.get("email"):
                    if "customer" not in o: o["customer"] = {}
                    o["customer"]["email"] = user["email"]
            except: pass

        # Address ko short karo table ke liye
        o["short_address"] = f"{o.get('customer', {}).get('city', '-')}, {o.get('customer', {}).get('state', '-')} - {o.get('customer', {}).get('pincode', '-')}"

    return jsonify({
        "orders": orders,
        "total_count": total_count
    })

# ---------- API: Single Order Detail ----------
@app.route('/admin/api/orders/<order_id>', methods=['GET'])
def admin_get_order_detail(order_id):
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        order = orders_collection.find_one({"_id": ObjectId(order_id)})
        if not order:
            return jsonify({"error": "Order not found"}), 404

        order["_id"] = str(order["_id"])
        uid = order.get("user_id")
        order["user_id"] = str(uid) if uid else ""
        
        # Backend fetch for email if not in order detail
        if not order.get("customer", {}).get("email") and uid:
            try:
                user = users_collection.find_one({"_id": ObjectId(uid)})
                if user and user.get("email"):
                    if "customer" not in order: order["customer"] = {}
                    order["customer"]["email"] = user["email"]
            except: pass
            
        # Fetch return request if exists
        ret_doc = returns_collection.find_one({"order_id": order.get("order_id")})
        if ret_doc:
            ret_doc["_id"] = str(ret_doc["_id"])
            ret_doc["user_id"] = str(ret_doc["user_id"])
            order["return_detail"] = ret_doc

            
        return jsonify(order)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ---------- Admin Invoice Page (Full Payment Detail) ----------
@app.route('/admin/invoice/<order_id>')
def admin_invoice_page(order_id):
    if not session.get('logged_in'):
        safe_print("DEBUG: Admin Invoice access denied. Session 'logged_in' not found.")
        return redirect(url_for('admin_login'))

    try:
        from bson import ObjectId
        from datetime import datetime, timezone, timedelta
        
        safe_print(f"DEBUG: Admin Invoice requested for ID: {order_id}")
        
        # 1. Fetch Order from DB (Try both ObjectId and String for compatibility)
        raw_order = None
        try:
            raw_order = orders_collection.find_one({"_id": ObjectId(order_id)})
        except: pass
        
        if not raw_order:
            raw_order = orders_collection.find_one({"_id": order_id})
            
        if not raw_order:
            # Try searching by order_id field if _id lookup fails
            raw_order = orders_collection.find_one({"order_id": order_id})

        if not raw_order:
            safe_print(f"DEBUG: Order {order_id} NOT FOUND in DB (Tried ObjectId and String)")
            flash("Order not found", "error")
            return redirect(url_for('admin_orders_page'))

        safe_print(f"DEBUG: Order {order_id} found. Processing...")

        # 1.5. Backend fetch for customer info if not in order detail
        uid = raw_order.get("user_id")
        if uid:
            try:
                from bson import ObjectId
                # Handle both string and ObjectId formats for user_id
                user_id_obj = ObjectId(uid) if isinstance(uid, str) and len(uid) == 24 else uid
                user = users_collection.find_one({"_id": user_id_obj})
                
                if user:
                    if "customer" not in raw_order: raw_order["customer"] = {}
                    # Only fill if missing
                    if not raw_order["customer"].get("email") and user.get("email"):
                        raw_order["customer"]["email"] = user["email"]
                    if not raw_order["customer"].get("phone") and user.get("phone"):
                        raw_order["customer"]["phone"] = user["phone"]
                    if not raw_order["customer"].get("name") and user.get("username"):
                        raw_order["customer"]["name"] = user["username"]
            except Exception as e:
                safe_print(f"DEBUG: User Fetch Error in Admin Invoice: {e}")

        # 2. Process Order Data for Template (Robustness)
        # Handle created_at
        created_at = raw_order.get('created_at')
        if isinstance(created_at, str):
            try: created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            except: created_at = datetime.now()
        elif not created_at:
            created_at = datetime.now()
            
        # Convert to IST for display
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        ist_order_time = created_at.astimezone(timezone(timedelta(hours=5, minutes=30)))

        # Process Items
        processed_items = []
        subtotal = 0.0
        for item in raw_order.get('items', []):
            if not isinstance(item, dict):
                safe_print(f"DEBUG: Skipping invalid item: {item}")
                continue
            try:
                price = float(item.get('price', 0))
                qty = int(item.get('qty', item.get('quantity', 1)))
                line_total = price * qty
                subtotal += line_total
                processed_items.append({
                    'name': item.get('name', 'Unknown Product'),
                    'category': item.get('category', 'General'),
                    'price': price,
                    'qty': qty,
                    'line_total': line_total,
                    'image': item.get('image', '/static/images/official_brand_logo.png')
                })
            except Exception as item_err:
                safe_print(f"DEBUG: Item processing error: {item_err}")
                continue

        total = float(raw_order.get('total', raw_order.get('total_amount', subtotal)))
        shipping = float(raw_order.get('shipping', 0))
        handling_fee = float(raw_order.get('handling_fee', 0))
        
        # Prepare Order Object for Template
        order_display = {
            'order_id': raw_order.get('order_id', 'N/A'),
            'created_at': ist_order_time,
            'customer': raw_order.get('customer', {}),
            'items': processed_items,
            'subtotal': subtotal,
            'shipping': shipping,
            'handling_fee': handling_fee,
            'round_off': raw_order.get('round_off', 0),
            'total': total,
            'payment_mode': raw_order.get('payment_mode', 'COD'),
            'payment_id': raw_order.get('payment_id')
        }

        # 3. Fetch Razorpay Details if applicable
        rp_details = None
        ist_payment_time = "N/A"
        payment_id = raw_order.get('payment_id')
        
        if raw_order.get('payment_mode') != 'COD' and payment_id and payment_id != 'COD_ORDER':
            try:
                # Fetch full payment object from Razorpay
                safe_print(f"DEBUG: Fetching Razorpay payment {payment_id}")
                rp_details = razorpay_client.payment.fetch(payment_id)
                
                # Convert payment timestamp to IST
                if rp_details and 'created_at' in rp_details:
                    ts = rp_details['created_at']
                    dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
                    dt_ist = dt_utc.astimezone(timezone(timedelta(hours=5, minutes=30)))
                    ist_payment_time = dt_ist.strftime('%d %b %Y, %I:%M %p')
            except Exception as rp_err:
                safe_print(f"DEBUG: Razorpay Fetch Error for {payment_id}: {rp_err}")

        safe_print(f"DEBUG: Rendering template for {order_id}")
        # Fetch payment config settings
        settings = settings_collection.find_one({"type": "payment_config"})
        fetch_fee = settings.get('fetch_razorpay_fee', True) if settings else True
        charge_cod_fee = settings.get('charge_cod_fee', True) if settings else True

        return render_template('admin/invoice.html', 
                               order=order_display, 
                               rp_details=rp_details, 
                               ist_payment_time=ist_payment_time,
                               fetch_fee=fetch_fee,
                               charge_cod_fee=charge_cod_fee)

    except Exception as e:
        import traceback
        err_msg = f"Admin Invoice Error: {str(e)}"
        safe_print(f"DEBUG: {err_msg}")
        safe_print(traceback.format_exc())
        flash(err_msg, "error")
        return redirect(url_for('admin_orders_page'))

# ---------- API: Update Order ----------
@app.route('/admin/api/orders/<order_id>', methods=['PATCH'])
def admin_update_order(order_id):
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    update_fields = {}

    # Allowed fields (exact aapke schema ke according)
    allowed = ["order_status", "payment_status", "notes"]
    for f in allowed:
        if f in data:
            update_fields[f] = data[f]
            # Sync legacy status field
            if f == "order_status":
                update_fields["status"] = data[f]

    if not update_fields:
        return jsonify({"error": "No fields to update"}), 400

    update_fields["updated_at"] = datetime.now(timezone.utc)

    try:
        # Fetch current order to check for status changes
        old_order = orders_collection.find_one({"_id": ObjectId(order_id)})
        if not old_order:
            return jsonify({"error": "Order not found"}), 404

        update_query = {"$set": update_fields}
        status_changed = False
        
        # Agar status update ho raha hai, aur wo purane status se alag hai, toh tracking me record daalo
        if "order_status" in update_fields:
            new_status = update_fields["order_status"].lower().strip()
            old_status = str(old_order.get("order_status", old_order.get("status", ""))).lower().strip()
            safe_print(f"[STATUS] Comparing: old='{old_status}' vs new='{new_status}' => changed={new_status != old_status}")
            
            if new_status != old_status:
                status_changed = True
                status_config = {
                    'confirmed': {'title': 'Order Confirmed', 'message': 'Your order has been confirmed and is being processed.'},
                    'shipped': {'title': 'Shipped', 'message': 'Your order is on its way!'},
                    'out_for_delivery': {'title': 'Out for Delivery', 'message': 'Rider heading to you.'},
                    'delivered': {'title': 'Delivered', 'message': 'Order delivered successfully!'},
                    'cancelled': {'title': 'Cancelled', 'message': 'Order has been cancelled.'}
                }
                conf = status_config.get(new_status, {'title': 'Status Updated', 'message': f'Order status updated to {new_status}'})
                
                update_query["$push"] = {
                    "tracking": {
                        "status": new_status,
                        "title": conf['title'],
                        "message": conf['message'],
                        "location": "Warehouse",
                        "timestamp": datetime.now(timezone.utc)
                    }
                }

        res = orders_collection.update_one(
            {"_id": ObjectId(order_id)},
            update_query
        )
        
        # 🚀 SEND EMAIL NOTIFICATION ONLY IF STATUS ACTUALLY CHANGED
        if status_changed:
            try:
                order = old_order # Use already fetched order data
                new_status = update_fields["order_status"].lower().strip()
                to_email = None
                to_name = "Valued Customer"
                
                if order:
                    cust = order.get('customer', {})
                    to_name = cust.get('name') or "Valued Customer"
                    
                    # Prioritize user's current profile email for updates
                    if order.get('user_id'):
                        try:
                            user = users_collection.find_one({"_id": ObjectId(order['user_id'])})
                            if user and user.get('email'):
                                to_email = user.get('email')
                                to_name = user.get('username') or to_name
                        except:
                            pass
                    
                    # Fallback to email stored in order if no user account or user email not found
                    if not to_email:
                        to_email = cust.get('email')
                            
                if to_email:
                    subject = f"Order {new_status.capitalize()} - Green Naturals"
                    
                    # Generate Email-Safe Stepper HTML
                    refund_message = ""
                    if new_status == 'cancelled':
                        statuses = ['confirmed', 'cancelled']
                        labels = ['Confirmed', 'Cancelled']
                        current_idx = 1
                        
                        # Add refund note for prepaid orders
                        if order.get('payment_mode', '').lower() != 'cod' and order.get('payment_status', '').lower() == 'paid':
                            refund_message = """
                            <div style="background: #fff1f2; border: 1px solid #fecaca; border-radius: 16px; padding: 20px; margin-bottom: 30px; text-align: center;">
                                <p style="margin: 0; font-size: 14px; color: #991b1b; line-height: 1.5;">
                                    <strong>Refund Note:</strong> Since this was a prepaid order, a refund has been initiated to your original payment method. It will reflect in your account within 5-7 business days.
                                </p>
                            </div>
                            """
                    else:
                        statuses = ['confirmed', 'shipped', 'out_for_delivery', 'delivered']
                        labels = ['Confirmed', 'Shipped', 'On the Way', 'Delivered']
                        try:
                            current_idx = statuses.index(new_status)
                        except ValueError:
                            current_idx = 0
                        
                    # Determine status colors and icons
                    status_theme = {
                        'confirmed': {'bg': 'linear-gradient(135deg, #10b981, #059669)', 'icon': '✅'},
                        'shipped': {'bg': 'linear-gradient(135deg, #3b82f6, #1d4ed8)', 'icon': '🚚'},
                        'out_for_delivery': {'bg': 'linear-gradient(135deg, #f59e0b, #d97706)', 'icon': '📦'},
                        'delivered': {'bg': 'linear-gradient(135deg, #10b981, #047857)', 'icon': '🎉'},
                        'cancelled': {'bg': 'linear-gradient(135deg, #ef4444, #b91c1c)', 'icon': '❌'}
                    }
                    theme = status_theme.get(new_status, status_theme['confirmed'])
                    
                    # Vertical Stepper Generation
                    stepper_rows = ""
                    for i, label in enumerate(labels):
                        is_current = (i == current_idx)
                        is_past = (i < current_idx)
                        is_cancelled_step = (new_status == 'cancelled' and i == 1)
                        
                        circle_color = "#ef4444" if is_cancelled_step else ("#10b981" if (is_current or is_past) else "#e2e8f0")
                        text_color = "#991b1b" if is_cancelled_step else ("#111827" if (is_current or is_past) else "#94a3b8")
                        line_color = "#10b981" if is_past else "#e2e8f0"
                        
                        icon = "✕" if is_cancelled_step else ("✓" if is_past else ("•" if is_current else i+1))
                        
                        status_desc = conf["message"] if is_current else ""
                        if is_cancelled_step: status_desc = "Order has been cancelled."

                        stepper_rows += f"""
                        <tr>
                            <td width="30" align="center" valign="top" style="padding-bottom: 0;">
                                <div style="background-color: {circle_color}; width: 26px; height: 26px; border-radius: 50%; color: #fff; font-size: 13px; line-height: 26px; font-weight: bold; text-align: center; margin: 0 auto; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                    {icon}
                                </div>
                                {f'<div style="width: 2px; height: 40px; background-color: {line_color}; margin: 4px auto;"></div>' if i < len(labels)-1 else '<div style="height:20px;"></div>'}
                            </td>
                            <td valign="top" style="padding-left: 15px; padding-top: 2px;">
                                <div style="font-size: 15px; color: {text_color}; font-weight: 700; font-family: sans-serif;">{label}</div>
                                {f'<div style="font-size: 13px; color: #6b7280; margin-top: 4px; line-height: 1.4;">{status_desc}</div>' if status_desc else ''}
                            </td>
                        </tr>"""

                    html_content = f"""
                    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e2e8f0; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.05); background: #ffffff;">
                        <!-- Top Logo Header -->
                        <div style="padding: 25px 0 15px; text-align: center; background: #ffffff;">
                            <img src="https://greennaturals.store/static/images/official_brand_logo.png" alt="Green Naturals" style="width: 50px; height: 50px; object-fit: contain;">
                            <p style="margin: 8px 0 0; font-size: 10px; font-weight: 900; text-transform: uppercase; letter-spacing: 0.3em; color: #064e3b;">Green Naturals</p>
                        </div>

                        <!-- Main Status Banner -->
                        <div style="background: {theme['bg']}; padding: 35px 20px; text-align: center; color: white;">
                            <div style="font-size: 40px; margin-bottom: 10px;">{theme['icon']}</div>
                            <h1 style="margin: 0; font-size: 26px; font-weight: 800; letter-spacing: -0.5px;">Order {new_status.replace('_', ' ').capitalize()}</h1>
                            <p style="margin: 8px 0 0; opacity: 0.9; font-size: 14px; font-weight: 500;">Order #{order.get('order_id', 'N/A')}</p>
                        </div>

                        <div style="padding: 35px 30px;">
                            <p style="font-size: 17px; color: #111827; margin-top: 0; font-weight: 600;">Hello {to_name},</p>
                            <p style="font-size: 15px; color: #4b5563; line-height: 1.6; margin-bottom: 30px;">Great news! Your order status has been updated. Here's a quick look at where your items are in the journey.</p>
                            
                            <!-- Vertical Stepper Section -->
                            <div style="padding: 30px 25px; background: #f8fafc; border-radius: 16px; border: 1px solid #f1f5f9; margin-bottom: 30px;">
                                <table width="100%" border="0" cellpadding="0" cellspacing="0">
                                    {stepper_rows}
                                </table>
                            </div>
                            
                            {refund_message}

                            <!-- Order Summary Box -->
                            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px; margin-bottom: 30px;">
                                <table width="100%" style="font-size: 14px; color: #4b5563;">
                                    <tr>
                                        <td style="padding-bottom: 8px;"><strong>Subtotal:</strong></td>
                                        <td style="text-align: right; padding-bottom: 8px; color: #111827;">₹{(float(order.get('total', 0)) - float(order.get('shipping', 0)) - float(order.get('handling_fee', 0)) - float(order.get('round_off', 0))):.2f}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding-bottom: 8px;"><strong>Shipping:</strong></td>
                                        <td style="text-align: right; padding-bottom: 8px; color: #10b981; font-weight: 700;">{f"₹{float(order.get('shipping', 0)):.2f}" if float(order.get('shipping', 0)) > 0 else "FREE"}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding-bottom: 8px;"><strong>Handling:</strong></td>
                                        <td style="text-align: right; padding-bottom: 8px; color: #10b981; font-weight: 700;">{f"₹{float(order.get('handling_fee', 0)):.2f}" if float(order.get('handling_fee', 0)) > 0 else "FREE"}</td>
                                    </tr>
                                    {f'<tr><td style="padding-bottom: 8px;"><strong>Round Off:</strong></td><td style="text-align: right; padding-bottom: 8px; color: #4b5563; font-style: italic;">+ ₹{float(order.get("round_off", 0)):.2f}</td></tr>' if float(order.get('round_off', 0)) > 0.001 else ''}
                                    <tr>
                                        <td style="padding-bottom: 8px; border-top: 1px solid #e2e8f0; padding-top: 10px;"><strong>Grand Total:</strong></td>
                                        <td style="text-align: right; padding-bottom: 8px; border-top: 1px solid #e2e8f0; padding-top: 10px; color: #111827; font-weight: 800; font-size: 16px;">₹{float(order.get('total', order.get('total_amount', 0))):.2f}</td>
                                    </tr>
                                    <tr>
                                        <td><strong>Payment Mode:</strong></td>
                                        <td style="text-align: right; color: #111827;">{str(order.get('payment_mode', 'N/A')).upper()}</td>
                                    </tr>
                                </table>
                            </div>

                            <!-- CTA Button -->
                            <div style="text-align: center; margin: 35px 0;">
                                <a href="https://greennaturals.store/my-orders" style="background: #111827; color: #ffffff; padding: 16px 32px; text-decoration: none; border-radius: 12px; font-weight: 700; font-size: 15px; display: inline-block; box-shadow: 0 4px 12px rgba(0,0,0,0.15);">Track Your Package</a>
                            </div>

                            <!-- Footer Section -->
                            <div style="border-top: 1px solid #f1f5f9; padding-top: 30px; margin-top: 10px; text-align: center;">
                                <p style="font-size: 13px; color: #64748b; margin: 0; line-height: 1.5;">Thank you for trusting <strong>Green Naturals</strong> 🌱<br>We bring the purity of nature to your doorstep.</p>
                                <div style="margin-top: 20px;">
                                    <a href="https://greennaturals.store" style="color: #10b981; text-decoration: none; font-size: 12px; font-weight: 600; margin: 0 10px;">Website</a>
                                    <span style="color: #e2e8f0;">|</span>
                                    <a href="https://greennaturals.store/contact" style="color: #10b981; text-decoration: none; font-size: 12px; font-weight: 600; margin: 0 10px;">Support</a>
                                </div>
                                <p style="font-size: 11px; color: #94a3b8; margin-top: 25px;">&copy; 2026 Green Naturals - Pure Herbal Excellence</p>
                            </div>
                        </div>
                    </div>
                    """
                    
                    # Send async so it doesn't block the UI
                    from threading import Thread
                    def send_async_email(s, h, e, n, order_data, is_delivered):
                        try:
                            safe_print(f"[DEBUG] send_async_email started for {e}. is_delivered: {is_delivered}")
                            sender_mail = os.getenv("SENDER_EMAIL", "noreply@greennaturals.store")
                            pdf_data = None
                            pdf_name = None
                            
                            # Generate Invoice PDF for delivered orders
                            if is_delivered and order_data:
                                safe_print(f"[DEBUG] Generating PDF for Order {order_data.get('order_id')}")
                                pdf_data = generate_invoice_pdf(order_data)
                                if pdf_data:
                                    pdf_name = f"Invoice_{order_data.get('order_id', 'GN')}.pdf"
                                    safe_print(f"[OK] Delivery invoice PDF ready ({len(pdf_data)} bytes) for {e}")
                                else:
                                    safe_print(f"[ERROR] PDF Generation returned None for {e}")
                            
                            send_email(s, h, e, n, sender_mail, "Green Naturals Orders",
                                      attachment_data=pdf_data, attachment_filename=pdf_name)
                            safe_print(f"[OK] Status email sent to {e}")
                        except Exception as err:
                            safe_print(f"[ERROR] send_async_email: {err}")
                            
                    Thread(target=send_async_email, args=(subject, html_content, to_email, to_name, order, new_status == 'delivered')).start()
            except Exception as e:
                print(f"Error preparing status email: {e}")

        return jsonify({"message": "Updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ---------- API: Cancel Order ----------
@app.route('/admin/api/orders/<order_id>/cancel', methods=['POST'])
def admin_cancel_order(order_id):
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    reason = request.get_json().get("reason", "Cancelled by admin")

    try:
        orders_collection.update_one(
            {"_id": ObjectId(order_id)},
            {"$set": {
                "order_status": "cancelled",
                "notes": f"{reason} - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        return jsonify({"message": "Order cancelled"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ---------- API: Delete Order (Soft Delete) ----------
@app.route('/admin/api/orders/<order_id>', methods=['DELETE'])
def admin_delete_order(order_id):
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        res = orders_collection.update_one(
            {"_id": ObjectId(order_id)},
            {"$set": {
                "order_status": "deleted",
                "status": "DELETED",
                "deleted_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        if res.matched_count == 0:
            return jsonify({"error": "Order not found"}), 404
        return jsonify({"message": "Order marked as deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

















from datetime import datetime, timezone, timedelta
from bson import ObjectId
from flask import flash, redirect, url_for, render_template, jsonify, request, session, send_file
from io import BytesIO
import os

# 🔥 ULTRA SAFE ORDER PROCESSOR
def _process_safe_order(order):
    """100% FAIL-PROOF - Handles ALL edge cases and status mapping"""
    now = datetime.now(timezone.utc)
    
    # Create CLEAN copy
    safe_order = {}
    if isinstance(order, dict):
        safe_order = dict(order)
    
    # ObjectId to string FIRST
    safe_order['_id'] = str(safe_order.get('_id', ''))
    
    # Helper to convert to IST
    def to_ist(dt):
        if not isinstance(dt, datetime):
            return dt
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt + timedelta(hours=5, minutes=30)

    # Date defaults - SAFE
    created_at = safe_order.get('created_at')
    if isinstance(created_at, datetime):
        safe_order['created_at'] = created_at
    else:
        try:
            if isinstance(created_at, str):
                safe_order['created_at'] = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            else:
                safe_order['created_at'] = now
        except:
            safe_order['created_at'] = now
    
    safe_order['created_at'] = to_ist(safe_order['created_at'])
    
    # Expected Delivery safety
    expected_delivery = safe_order.get('expected_delivery')
    if not isinstance(expected_delivery, datetime):
        safe_order['expected_delivery'] = to_ist(now + timedelta(days=3))
    else:
        safe_order['expected_delivery'] = to_ist(expected_delivery)
    
    # Status defaults - Normalize to lowercase for CSS
    # Check all possible status fields: current_status > order_status > status
    raw_status = (
        safe_order.get('current_status') or
        safe_order.get('order_status') or
        safe_order.get('status') or
        'confirmed'
    )
    raw_status = str(raw_status).lower().strip()
    # Map 'pending', 'PENDING', and 'processing' to 'confirmed' for UI consistency
    if raw_status in ('pending', 'new', '', 'processing'):
        raw_status = 'confirmed'
    # Normalize known statuses
    valid_statuses = {'confirmed', 'shipped', 'out_for_delivery', 'delivered', 'cancelled'}
    if raw_status not in valid_statuses:
        raw_status = 'confirmed'
    
    # Standardize ALL status fields for template consistency
    safe_order['current_status'] = raw_status
    safe_order['status'] = raw_status
    safe_order['status_class'] = raw_status
    safe_order['status_label'] = raw_status.replace('_', ' ').title()

    # (Return override moved to end of function to avoid being overwritten)
    safe_order['is_returning'] = False

    
    # Numeric defaults
    safe_order['total'] = float(safe_order.get('total', 0) or 0)
    
    # 🔥 CRITICAL ITEMS FIX
    items_raw = safe_order.get('items')
    if isinstance(items_raw, list):
        normalized_items = []
        running_total = 0.0

        for raw_item in items_raw:
            if not isinstance(raw_item, dict):
                continue

            qty = raw_item.get('quantity', raw_item.get('qty', 1))
            price = raw_item.get('price', 0)
            subtotal = raw_item.get('subtotal')

            try:
                qty = int(qty)
            except:
                qty = 1
            qty = max(qty, 1)

            try:
                price = float(price)
            except:
                price = 0.0

            if subtotal is not None:
                try:
                    line_total = float(subtotal)
                except:
                    line_total = round(price * qty, 2)
            else:
                line_total = round(price * qty, 2)

            running_total += line_total
            normalized_items.append({
                "name": raw_item.get("name", "Product"),
                "quantity": qty,
                "price": price,
                "line_total": line_total,
                "image": raw_item.get("image", raw_item.get("image_url", ""))
            })

        safe_order['items'] = normalized_items
        safe_order['subtotal'] = round(running_total, 2)

        if safe_order['total'] <= 0 and running_total > 0:
            safe_order['total'] = round(running_total, 2)
            
        # Use DB-stored shipping & handling_fee if available (set during checkout)
        # Only fallback to calculation for legacy orders missing these fields
        db_shipping = safe_order.get('shipping')
        db_handling = safe_order.get('handling_fee')

        if db_shipping is not None:
            try:
                safe_order['shipping'] = round(float(db_shipping), 2)
            except:
                safe_order['shipping'] = 0.0
        else:
            # Legacy fallback: estimate shipping from total difference
            diff = safe_order['total'] - safe_order['subtotal']
            safe_order['shipping'] = round(diff, 2) if diff > 0.01 else 0.0

        if db_handling is not None:
            try:
                safe_order['handling_fee'] = round(float(db_handling), 2)
            except:
                safe_order['handling_fee'] = 0.0
        else:
            safe_order['handling_fee'] = 0.0

        # Round Off Logic
        db_round_off = safe_order.get('round_off')
        if db_round_off is not None:
            try:
                safe_order['round_off'] = float(db_round_off)
            except:
                safe_order['round_off'] = 0.0
        else:
            # Fallback for legacy: total - (subtotal + shipping + handling)
            calc_round = safe_order['total'] - (safe_order['subtotal'] + safe_order['shipping'] + safe_order['handling_fee'])
            safe_order['round_off'] = round(calc_round, 2) if calc_round > 0 else 0.0

    else:
        safe_order['items'] = []
        safe_order['subtotal'] = safe_order['total']
        safe_order['shipping'] = 0.0
        safe_order['handling_fee'] = 0.0
        safe_order['round_off'] = 0.0
    
    # 🔥 TRACKING SAFETY
    tracking_raw = safe_order.get('tracking')
    
    # Extract Payment Method
    pm = safe_order.get('payment_method') or safe_order.get('payment_mode') or 'online'
    safe_order['payment_method'] = str(pm).strip().upper()
    
    if isinstance(tracking_raw, list) and len(tracking_raw) > 0:
        safe_tracking = []
        for t in tracking_raw:
            if not isinstance(t, dict):
                continue
            ts = t.get('timestamp')
            if not isinstance(ts, datetime):
                try:
                    ts = datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
                except Exception:
                    ts = safe_order['created_at']
            safe_tracking.append({
                "status": t.get('status', safe_order['current_status']),
                "title": t.get('title', 'Update'),
                "message": t.get('message', ''),
                "location": t.get('location', 'Warehouse'),
                "timestamp": to_ist(ts)
            })
        # Ensure 'confirmed' is always the first step if missing
        if not any(t.get('status') in ('confirmed', 'pending', 'new') for t in safe_tracking):
            safe_tracking.insert(0, {
                "status": "confirmed",
                "title": "Order Confirmed",
                "message": "Your order has been confirmed and is being processed.",
                "location": "Warehouse",
                "timestamp": safe_order['created_at']
            })
        safe_order['tracking'] = safe_tracking
    else:
        # Dynamically generate tracking history up to current_status if DB lacks it
        status_flow = ['confirmed', 'shipped', 'out_for_delivery', 'delivered']
        status_config = {
            'confirmed': {'title': 'Order Confirmed', 'message': 'Your order has been confirmed and is being processed.'},
            'shipped': {'title': 'Shipped', 'message': 'Your order is on its way!'},
            'out_for_delivery': {'title': 'Out for Delivery', 'message': 'Rider heading to you.'},
            'delivered': {'title': 'Delivered', 'message': 'Order delivered successfully!'},
            'cancelled': {'title': 'Cancelled', 'message': 'Order has been cancelled.'}
        }
        
        generated_tracking = []
        current_status = safe_order['current_status']
        
        if current_status == 'cancelled':
            generated_tracking.append({
                "status": "cancelled",
                "title": status_config['cancelled']['title'],
                "message": status_config['cancelled']['message'],
                "timestamp": safe_order['created_at'],
                "location": "System"
            })
        else:
            time_offsets = {'confirmed': 0, 'shipped': 24, 'out_for_delivery': 48, 'delivered': 54}
            for st in status_flow:
                generated_tracking.append({
                    "status": st,
                    "title": status_config.get(st, {}).get('title', 'Update'),
                    "message": status_config.get(st, {}).get('message', ''),
                    "timestamp": safe_order['created_at'] + timedelta(hours=time_offsets.get(st, 0)),
                    "location": "Warehouse"
                })
                if st == current_status:
                    break
        safe_order['tracking'] = generated_tracking
    
    # Formatted fields
    safe_order['date_formatted'] = safe_order['created_at'].strftime('%d %b %Y')
    safe_order['status_label'] = safe_order['current_status'].replace('_', ' ').title()

    # (Return override moved to absolute end of function)
    safe_order['status_class'] = safe_order['current_status'].replace('_', '-')
    
    # Order ID fallback
    if not safe_order.get('order_id'):
        order_id_str = safe_order['_id']
        safe_order['order_id'] = f"GN-{order_id_str[-6:] if len(order_id_str) >= 6 else order_id_str}"
    
    # 🔥 REVIEW DATA PRESERVATION
    safe_order['rating'] = safe_order.get('rating')
    safe_order['review'] = safe_order.get('review', '')

    # --- FINAL RETURN/EXCHANGE STATUS OVERRIDE ---
    # This must stay at the VERY end to override standard formatting
    ret_stat = str(safe_order.get('return_status', '')).strip().title()
    if safe_order.get('return_requested') and ret_stat == 'Approved':
        step = int(safe_order.get('return_step', 1))
        r_type = str(safe_order.get('return_type', 'return')).strip().title()
        
        ret_labels = {
            1: f'{r_type} Approved', 
            2: 'Item Picked Up', 
            3: f'{r_type} Processing', 
            4: f'{r_type} Completed'
        }
        safe_order['status_label'] = ret_labels.get(step, f'{r_type} In Progress')
        safe_order['status_class'] = 'return-active'
        safe_order['is_returning'] = True
    
    return safe_order

def _user_order_query():
    """Handle legacy user_id formats and customer-based fallbacks."""
    session_user_id = str(session.get('user_id', '')).strip()
    if not session_user_id:
        return {"user_id": "GUEST_SESSION_NONE"}

    query_list = []
    
    # 1. Direct User ID (String and ObjectId)
    query_list.append({"user_id": session_user_id})
    if ObjectId.is_valid(session_user_id):
        query_list.append({"user_id": ObjectId(session_user_id)})

    # 2. Fetch user details for fallbacks
    try:
        current_user = users_collection.find_one({"_id": ObjectId(session_user_id) if ObjectId.is_valid(session_user_id) else session_user_id})
        if current_user:
            phone = str(current_user.get("phone", "")).strip()
            email = str(current_user.get("email", "")).strip().lower()

            # Separate queries for linked vs unlinked orders
            fallback_list = []
            if phone:
                fallback_list.append({"customer.phone": phone})
                digits = re.sub(r"\D", "", phone)
                if len(digits) >= 10:
                    last10 = digits[-10:]
                    fallback_list.append({"customer.phone": last10})
                    fallback_list.append({"customer.phone": "+91" + last10})
                    fallback_list.append({"customer.phone": "91" + last10})
            if email:
                fallback_list.append({"customer.email": email})
                fallback_list.append({"email": email})

            # The query should be: 
            # (order.user_id == current_user_id) 
            # OR 
            # (order.user_id does not exist AND (phone match OR email match))
            
            final_query = {
                "$or": [
                    {"user_id": session_user_id},
                    {"user_id": ObjectId(session_user_id) if ObjectId.is_valid(session_user_id) else session_user_id},
                    {
                        "$and": [
                            {"user_id": {"$in": [None, "", False]}},
                            {"$or": fallback_list}
                        ]
                    },
                    {
                        "$and": [
                            {"user_id": {"$exists": False}},
                            {"$or": fallback_list}
                        ]
                    }
                ]
            }
            return final_query
    except Exception as e:
        print(f"Query Fallback Error: {e}")

    return {"$or": query_list}

# 🔥 MY ORDERS ROUTES - COMPLETE
def _debug_agent_log(run_id, hypothesis_id, location, message, data=None):
    try:
        payload = {
            "sessionId": "9364df",
            "runId": run_id,
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data or {},
            "timestamp": int(time.time() * 1000)
        }
        with open("debug-9364df.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, default=str) + "\n")
    except Exception:
        pass

@app.route('/my-orders')
@app.route('/my-orders/<order_id>')
def my_orders(order_id=None):
    if 'user_id' not in session:
        flash("Please login to view orders", "info")
        return redirect(url_for('login'))
    
    try:
        user_query = _user_order_query()
        print(f"[DEBUG my_orders] session user_id: {session.get('user_id')}")
        print(f"[DEBUG my_orders] user_query: {user_query}")

        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '').strip()
        per_page = 5
        total_pages = 1

        # Fetch suggestions for datalist
        all_orders_for_suggestions = orders_collection.find(_user_order_query(), {"order_id": 1, "items.name": 1})
        suggestions = set()
        for o in all_orders_for_suggestions:
            if o.get("order_id"):
                suggestions.add(o["order_id"])
            for item in o.get("items", []):
                if isinstance(item, dict) and item.get("name"):
                    suggestions.add(item["name"])
        suggestions = sorted(list(suggestions))

        if search:
            search_query = {
                "$or": [
                    {"order_id": {"$regex": search, "$options": "i"}},
                    {"items.name": {"$regex": search, "$options": "i"}}
                ]
            }
            user_query = {"$and": [user_query, search_query]}

        if order_id:
            order = orders_collection.find_one({
                "$and": [
                    {"order_id": order_id},
                    user_query
                ]
            })
            
            if not order:
                flash(f"Order '{order_id}' not found!", "error")
                return redirect(url_for('my_orders'))
            
            safe_orders = [_process_safe_order(dict(order))]
        else:
            total_orders = orders_collection.count_documents(user_query)
            total_pages = max((total_orders + per_page - 1) // per_page, 1)
            page = max(1, min(page, total_pages))
            skip = (page - 1) * per_page

            # Fetch and process
            user_orders = list(orders_collection.find(user_query).sort("created_at", -1).skip(skip).limit(per_page))
            
            safe_orders = []
            for idx, order in enumerate(user_orders):
                try:
                    processed = _process_safe_order(dict(order))
                    safe_orders.append(processed)
                except Exception as e:
                    continue
            
        # Fetch payment config for FREE display logic
        settings = settings_collection.find_one({"type": "payment_config"})
        fetch_fee = settings.get('fetch_razorpay_fee', True) if settings else True
        charge_cod_fee = settings.get('charge_cod_fee', True) if settings else True

        # Fetch return settings
        return_config = settings_collection.find_one({"type": "return_settings"})
        return_settings = return_config if return_config else {"allow_return": True, "allow_exchange": True}

        return render_template('my_orders.html', 
                               orders=safe_orders, 
                               highlight_order_id=order_id, 
                               page=page, 
                               total_pages=total_pages, 
                               search=search, 
                               suggestions=suggestions,
                               fetch_fee=fetch_fee,
                               charge_cod_fee=charge_cod_fee,
                               return_settings=return_settings,
                               now=datetime.now(timezone.utc))
        
    except Exception as e:
        print(f"[DEBUG my_orders] ROUTE ERROR: {e}")
        import traceback
        traceback.print_exc()
        return render_template('my_orders.html', 
                               orders=[], 
                               suggestions=[], 
                               fetch_fee=True, 
                               charge_cod_fee=True,
                               page=1,
                               total_pages=1,
                               search="")

# TEMPORARY DEBUG ENDPOINT
@app.route('/api/debug-orders')
def debug_orders_api():
    info = {"session_user_id": session.get('user_id', 'NOT_SET'), "logged_in": 'user_id' in session}
    if 'user_id' not in session:
        return jsonify(info)
    try:
        user_query = _user_order_query()
        info["query"] = str(user_query)
        raw = list(orders_collection.find(user_query).sort("created_at", -1).limit(5))
        info["raw_count"] = len(raw)
        if raw:
            f = raw[0]
            info["first"] = {"order_id": f.get("order_id"), "uid": str(f.get("user_id")), "uid_type": type(f.get("user_id")).__name__, "status": f.get("status")}
        processed = []
        errs = []
        for i, o in enumerate(raw):
            try:
                p = _process_safe_order(dict(o))
                processed.append({"order_id": p.get("order_id"), "status": p.get("current_status"), "items": len(p.get("items", []))})
            except Exception as e:
                errs.append({"i": i, "err": str(e)})
        info["processed"] = len(processed)
        info["sample"] = processed[:3]
        info["errors"] = errs
    except Exception as e:
        info["error"] = str(e)
        import traceback
        info["tb"] = traceback.format_exc()
    return jsonify(info)

# 🔥 REVIEW SUBMISSION API
@app.route('/api/submit-review', methods=['POST'])
def submit_review():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Login required"}), 401
    
    try:
        data = request.json
        order_id = data.get('order_id')
        rating = data.get('rating')
        review = data.get('review')

        if not order_id or not rating:
            return jsonify({"success": False, "error": "Order ID and Rating are required"}), 400

        # Check if order belongs to user and is delivered (using robust status detection)
        user_query = _user_order_query()
        order = orders_collection.find_one({"$and": [user_query, {"order_id": order_id}]})
        
        if not order:
            return jsonify({"success": False, "error": "Order not found"}), 404
        
        # Consistent with _process_safe_order logic
        current_status = str(order.get('current_status') or order.get('order_status') or order.get('status') or '').lower().strip()
        if current_status != 'delivered':
            return jsonify({"success": False, "error": f"Can only review delivered orders (Current: {current_status})"}), 400

        # Update order with rating and review
        result = orders_collection.update_one(
            {"$and": [user_query, {"order_id": order_id}]},
            {"$set": {
                "rating": int(rating),
                "review": review,
                "reviewed_at": datetime.now(timezone.utc)
            }}
        )

        if result.modified_count > 0:
            safe_print(f"?? [SUCCESS] Review saved for Order {order_id}")
            return jsonify({"success": True, "message": "Review submitted successfully"})
        else:
            safe_print(f"?? [WARN] Review not saved - Order might already have same review or ID mismatch")
            # If matched but not modified, it's still a success (already reviewed)
            if result.matched_count > 0:
                return jsonify({"success": True, "message": "Review already exists"})
            return jsonify({"success": False, "error": "Could not save review. Please try again."}), 400
    except Exception as e:
        safe_print(f"Review Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
        
    except Exception as e:
        print(f"🚨 REVIEW ERROR: {e}")
        return jsonify({"error": "Server error"}), 500

# 🔥 INVOICE DOWNLOAD (HTML - NO PDF LIBRARY NEEDED)
@app.route('/invoice/<order_id>')
def download_invoice(order_id):
    try:
        order = orders_collection.find_one({"order_id": order_id})
        if not order:
            flash("Invoice not found", "error")
            return redirect(url_for('my_orders'))
        
        safe_order = _process_safe_order(dict(order))
        
        # Calculate totals
        subtotal = 0
        total_items = 0
        for item in safe_order.get('items', []):
            qty = item.get('quantity', 1)
            price = item.get('price', 0)
            subtotal += price * qty
            total_items += qty
        
        invoice_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Invoice #{safe_order['order_id']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Arial', sans-serif; max-width: 800px; margin: 40px auto; padding: 40px; background: #f8f9fa; }}
        .invoice-container {{ background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 3px solid #28a745; padding-bottom: 25px; margin-bottom: 35px; }}
        .header h1 {{ color: #28a745; font-size: 36px; margin-bottom: 10px; }}
        .header h2 {{ color: #333; font-size: 24px; margin: 15px 0; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; padding: 20px; background: #f8f9fa; border-radius: 8px; }}
        .info-item {{ padding: 10px; }}
        .info-label {{ font-weight: bold; color: #666; font-size: 12px; text-transform: uppercase; }}
        .info-value {{ color: #333; font-size: 16px; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 25px 0; }}
        thead {{ background: #28a745; color: white; }}
        th {{ padding: 15px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 12px; }}
        td {{ padding: 15px; border-bottom: 1px solid #e9ecef; }}
        .total-row {{ background: #f8f9fa; font-weight: bold; font-size: 18px; }}
        .total-amount {{ color: #28a745; font-size: 24px; }}
        .footer {{ margin-top: 40px; padding: 25px; background: #e9f7ef; border-radius: 8px; text-align: center; }}
        .status-badge {{ display: inline-block; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; background: #28a745; color: white; }}
        @media print {{ body {{ margin: 0; padding: 20px; background: white; }} .invoice-container {{ box-shadow: none; }} }}
    </style>
</head>
<body>
    <div class="invoice-container">
        <div class="header">
            <h1>🟢 GREEN NATURALS</h1>
            <p style="color: #666; margin: 10px 0;">Pure. Natural. Healthy.</p>
            <h2>INVOICE</h2>
        </div>
        
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">Invoice Number</div>
                <div class="info-value">#{safe_order['order_id']}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Invoice Date</div>
                <div class="info-value">{safe_order['date_formatted']}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Customer Contact</div>
                <div class="info-value">
                    {safe_order.get('customer', {}).get('phone', 'N/A')}
                    {f" / {safe_order.get('customer', {}).get('alt_phone')}" if safe_order.get('customer', {}).get('alt_phone') else ""}
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">Order Status</div>
                <div class="info-value"><span class="status-badge">{safe_order['current_status'].replace('_', ' ').title()}</span></div>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>ITEM DESCRIPTION</th>
                    <th style="text-align: center;">QUANTITY</th>
                    <th style="text-align: right;">UNIT PRICE</th>
                    <th style="text-align: right;">TOTAL</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for idx, item in enumerate(safe_order.get('items', []), 1):
            qty = item.get('quantity', 1)
            price = item.get('price', 0)
            name = item.get('name', 'Product')
            item_total = price * qty
            invoice_html += f"""
                <tr>
                    <td>{idx}. {name}</td>
                    <td style="text-align: center;">{qty}</td>
                    <td style="text-align: right;">₹{price:.2f}</td>
                    <td style="text-align: right;">₹{item_total:.2f}</td>
                </tr>
"""
        
        invoice_html += "</tbody>"
        
        # Calculate actual items subtotal for proper math
        item_subtotal = sum(float(item.get('price', 0)) * int(item.get('quantity', 1)) for item in safe_order.get('items', []))
        shipping = float(safe_order.get('shipping', 0))
        effective_handling = float(safe_order['total']) - item_subtotal - shipping

        invoice_html += f"""
            <tfoot>
                <tr>
                    <td colspan="3" style="text-align: right; border: none; padding: 5px 15px;">Subtotal</td>
                    <td style="text-align: right; border: none; padding: 5px 15px;">₹{item_subtotal:.2f}</td>
                </tr>
                <tr>
                    <td colspan="3" style="text-align: right; border: none; padding: 5px 15px;">Shipping</td>
                    <td style="text-align: right; border: none; padding: 5px 15px; color: #28a745;">{f"₹{shipping:.2f}" if shipping > 0 else "FREE"}</td>
                </tr>
                <tr>
                    <td colspan="3" style="text-align: right; border: none; padding: 5px 15px;">Handling Fee</td>
                    <td style="text-align: right; border: none; padding: 5px 15px; color: #28a745;">{f"₹{effective_handling:.2f}" if effective_handling > 0.01 else "FREE"}</td>
                </tr>
                <tr class="total-row">
                    <td colspan="3" style="text-align: right;">GRAND TOTAL ({total_items} items)</td>
                    <td style="text-align: right;" class="total-amount">₹{float(safe_order['total']):.2f}</td>
                </tr>
            </tfoot>
        </table>
        
        <div class="footer">
            <p style="font-size: 18px; font-weight: bold; color: #28a745; margin-bottom: 15px;">
                Thank you for choosing Green Naturals! 🌿
            </p>
            <p>For support: noreply@greennaturals.store | +91-XXXXXXXXXX</p>
            <p style="font-size: 12px; margin-top: 15px; color: #999;">
                This is a computer-generated invoice. No signature required.
            </p>
        </div>
    </div>
</body>
</html>
        """
        
        return send_file(
            BytesIO(invoice_html.encode('utf-8')),
            as_attachment=True,
            download_name=f"invoice-{safe_order['order_id']}.html",
            mimetype='text/html'
        )
        
    except Exception as e:
        print(f"🚨 INVOICE ERROR: {e}")
        flash("Error generating invoice", "error")
        return redirect(url_for('my_orders'))

# 🔥 ADMIN TRACKING UPDATE API
@app.route('/admin/api/update-tracking/<order_id>', methods=['POST'])
def update_tracking(order_id):
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json() or {}
        new_status = data.get('status')
        tracking_number = data.get('tracking_number', '')
        location = data.get('location', 'Warehouse')
        delivery_partner = data.get('delivery_partner', 'Green Naturals')
        
        status_config = {
            'confirmed': {'title': 'Order Confirmed ✅', 'message': 'Your order is confirmed & processing.'},
            'shipped': {'title': 'Shipped 🚚', 'message': 'Your order is on its way!'},
            'out_for_delivery': {'title': 'Out for Delivery 📦', 'message': 'Rider heading to you.'},
            'delivered': {'title': 'Delivered 🎉', 'message': 'Order delivered successfully!'},
            'cancelled': {'title': 'Cancelled ❌', 'message': 'Order has been cancelled.'}
        }
        
        if new_status not in status_config:
            return jsonify({"error": "Invalid status"}), 400
        
        result = orders_collection.update_one(
            {"_id": ObjectId(order_id)},
            {
                "$set": {
                    "current_status": new_status,
                    "tracking_number": tracking_number,
                    "delivery_partner": delivery_partner,
                    "expected_delivery": datetime.now(timezone.utc) + timedelta(days=2),
                    "updated_at": datetime.now(timezone.utc)
                },
                "$push": {
                    "tracking": {
                        "status": new_status,
                        "title": status_config[new_status]['title'],
                        "message": status_config[new_status]['message'],
                        "location": location,
                        "timestamp": datetime.now(timezone.utc)
                    }
                }
            }
        )
        
        return jsonify({
            "success": True, 
            "status": new_status,
            "message": "✅ Tracking updated successfully!"
        }) if result.modified_count > 0 else jsonify({"error": "Order not found"}), 404
        
    except Exception as e:
        print(f"🚨 TRACKING UPDATE ERROR: {e}")
        return jsonify({"error": "Server error"}), 500


# --- Privacy Policy Page ---
@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')


# --- Global Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', 
                           title="Page Not Found", 
                           heading="Lost in the Woods?", 
                           message="The page you are looking for doesn't exist or has been moved to another location.",
                           code="404"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', 
                           title="Server Error", 
                           heading="Our System is Wilting", 
                           message="Something went wrong on our end. Our team has been notified and we are working to fix it.",
                           code="500"), 500


@app.route('/api/submit-return', methods=['POST'])
def submit_return():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        order_id = request.form.get('order_id')
        request_type = request.form.get('type') # 'return' or 'exchange'
        problem = request.form.get('problem')
        notes = request.form.get('notes', '').strip()
        items_json = request.form.get('items') # JSON string of selected items [{name, price, qty, line_total}]
        total_amount = float(request.form.get('total_amount', 0))
        
        # Validation
        if not order_id or not request_type or not problem or not items_json:
            return jsonify({"success": False, "error": "Missing required fields"}), 400
            
        import json
        items = json.loads(items_json)
        if not items:
            return jsonify({"success": False, "error": "No items selected"}), 400

        # Verify order belongs to user
        order = orders_collection.find_one({"order_id": order_id, "user_id": ObjectId(session['user_id'])})
        if not order:
            return jsonify({"success": False, "error": "Order not found"}), 404

        photo_urls = []
        if 'photos' in request.files:
            files = [f for f in request.files.getlist('photos') if f and f.filename != '']
            if files:
                from concurrent.futures import ThreadPoolExecutor, as_completed
                
                def upload_photo(file_obj):
                    res = cloudinary.uploader.upload(file_obj, folder="return_requests")
                    return res.get('secure_url')
                
                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [executor.submit(upload_photo, f) for f in files]
                    for future in as_completed(futures):
                        try:
                            url = future.result()
                            if url:
                                photo_urls.append(url)
                        except Exception as e:
                            print(f"Cloudinary concurrent upload error: {e}")
                            return jsonify({"success": False, "error": "One or more image uploads failed. Please try again."}), 500

        return_data = {
            "order_id": order_id,
            "user_id": ObjectId(session['user_id']),
            "type": request_type,
            "problem": problem,
            "notes": notes,
            "items": items,
            "total_amount": total_amount,
            "photo_urls": photo_urls,
            "status": "Pending",
            "created_at": datetime.now(timezone.utc)
        }

        returns_collection.insert_one(return_data)
        
        # Also tag the order with request info and items immediately
        orders_collection.update_one(
            {"_id": order["_id"]}, 
            {"$set": {
                "return_requested": True, 
                "return_type": request_type,
                "returned_items": items,
                "return_status": "Pending"
            }}
        )

        # Send Notification Emails
        try:
            user = db.users.find_one({"_id": ObjectId(session['user_id'])})
            if user and user.get('email'):
                user_email = user['email']
                user_name = user.get('name', 'Customer')
                admin_email = os.getenv("ADMIN_GMAIL", "support@greennaturals.store")
                
                req_title = request_type.capitalize()
                items_str = "".join([f"<li>{i['name']} (Qty: {i.get('qty', 1)})</li>" for i in items])
                
                user_subject = f"Your {req_title} Request is Submitted - Green Naturals"
                user_html = f"""
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; border: 1px solid #eee; border-radius: 10px; overflow: hidden;">
                    <div style="background-color: #f8fafc; padding: 20px; text-align: center; border-bottom: 1px solid #eee;">
                        <h2 style="color: #0f172a; margin: 0;">{req_title} Request Submitted</h2>
                    </div>
                    <div style="padding: 30px;">
                        <p>Hi {user_name},</p>
                        <p>We have received your {request_type} request for Order <strong>#{order_id}</strong>.</p>
                        <p><strong>Reason:</strong> {problem}</p>
                        <p><strong>Items:</strong></p>
                        <ul>{items_str}</ul>
                        <p style="margin-top: 20px; padding: 15px; background-color: #f0fdf4; color: #166534; border-radius: 8px;">
                            <strong>Note:</strong> Your request is currently under review. It will be processed only after it is approved by our team.
                        </p>
                        <p>We will notify you once the status is updated.</p>
                        <p>Best Regards,<br>Green Naturals Team</p>
                    </div>
                </div>
                """
                
                admin_subject = f"New {req_title} Request - Order #{order_id}"
                admin_html = f"""
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; border: 1px solid #eee; border-radius: 10px; overflow: hidden;">
                    <div style="background-color: #fff1f2; padding: 20px; text-align: center; border-bottom: 1px solid #eee;">
                        <h2 style="color: #be123c; margin: 0;">Action Required: New {req_title} Request</h2>
                    </div>
                    <div style="padding: 30px;">
                        <p><strong>Customer:</strong> {user_name} ({user_email})</p>
                        <p><strong>Order ID:</strong> {order_id}</p>
                        <p><strong>Reason:</strong> {problem}</p>
                        <p><strong>Notes:</strong> {notes or 'None'}</p>
                        <p><strong>Total Value:</strong> ₹{total_amount}</p>
                        <p><strong>Items:</strong></p>
                        <ul>{items_str}</ul>
                        <p style="margin-top: 20px;">
                            Please check your Admin Dashboard under "Returns & Exchanges" to review the request photos and approve or reject it.
                        </p>
                    </div>
                </div>
                """
                
                import threading
                def send_async_emails(u_sub, u_html, u_em, u_name, a_sub, a_html, a_em):
                    sender_email = "noreply@greennaturals.store"
                    with app.app_context():
                        # To User
                        send_email(u_sub, u_html, u_em, u_name, sender_email, "Green Naturals")
                        # To Admin
                        send_email(a_sub, a_html, a_em, "Admin", sender_email, "Green Naturals System")
                
                threading.Thread(target=send_async_emails, args=(user_subject, user_html, user_email, user_name, admin_subject, admin_html, admin_email)).start()
                
        except Exception as e:
            print(f"Error initiating return emails: {e}")

        return jsonify({"success": True, "message": "Pending Approval. Your return & exchange will proceed."})
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/admin/api/return-requests', methods=['GET'])
def admin_get_returns():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        req_type = request.args.get('type', 'return')
        requests_cursor = returns_collection.find({"type": req_type}).sort("created_at", -1)
        
        # Get counts for the UI badges
        return_count = returns_collection.count_documents({"type": "return", "status": "Pending"})
        exchange_count = returns_collection.count_documents({"type": "exchange", "status": "Pending"})
        
        requests_list = []
        from datetime import timedelta
        for r in requests_cursor:
            r['_id'] = str(r['_id'])
            r['user_id'] = str(r['user_id'])
            if 'created_at' in r:
                # Convert UTC to IST (UTC + 5:30)
                ist_time = r['created_at'] + timedelta(hours=5, minutes=30)
                r['created_at'] = ist_time.strftime('%d %b %Y, %I:%M %p')
            requests_list.append(r)
            
        return jsonify({
            "success": True, 
            "requests": requests_list,
            "return_count": return_count,
            "exchange_count": exchange_count
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/admin/api/update-return-status', methods=['POST'])
def admin_update_return_status():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        data = request.json
        req_id = data.get('id')
        status = data.get('status')
        admin_notes = data.get('admin_notes', '')
        
        if not req_id or not status:
            return jsonify({"success": False, "error": "Missing data"}), 400
            
        # Get request details before update for email
        req_doc = returns_collection.find_one({"_id": ObjectId(req_id)})
        if not req_doc:
            return jsonify({"success": False, "error": "Request not found"}), 404

        update_payload = {"status": status}
        if admin_notes:
            update_payload["admin_notes"] = admin_notes

        result = returns_collection.update_one(
            {"_id": ObjectId(req_id)},
            {"$set": update_payload}
        )
        
        # Also sync status to the order document for easy display in my_orders
        order_update_result = orders_collection.update_one(
            {"order_id": req_doc['order_id']},
            {"$set": {
                "return_status": status,
                "return_admin_notes": admin_notes,
                "returned_items": req_doc.get('items', []),
                "return_step": 1 if status == 'Approved' else 0
            }}
        )
        print(f"[DEBUG] Admin Status Update - Request ID: {req_id}, Order ID: {req_doc['order_id']}")
        print(f"[DEBUG] Order Update Result - Matched: {order_update_result.matched_count}, Modified: {order_update_result.modified_count}")
        
        if result.modified_count == 1:
            # Notify User via Email
            try:
                user = db.users.find_one({"_id": ObjectId(req_doc['user_id'])})
                if user and user.get('email'):
                    user_email = user['email']
                    user_name = user.get('name', 'Customer')
                    order_id = req_doc['order_id']
                    req_type = req_doc.get('type', 'return').capitalize()
                    
                    subject = f"Update on your {req_type} Request - Order #{order_id}"
                    
                    status_color = "#057857" if status == "Approved" else "#b91c1c"
                    
                    html_content = f"""
                    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; border: 1px solid #eee; border-radius: 10px; overflow: hidden;">
                        <div style="background-color: {status_color}; padding: 20px; text-align: center; color: white;">
                            <h2 style="margin: 0;">{req_type} Request {status}</h2>
                        </div>
                        <div style="padding: 30px;">
                            <p>Hi {user_name},</p>
                            <p>Your {req_type.lower()} request for Order <strong>#{order_id}</strong> has been <strong>{status.lower()}</strong>.</p>
                            
                            {f'<div style="background: #f9fafb; padding: 15px; border-radius: 8px; border-left: 4px solid {status_color}; margin: 20px 0;"><p style="margin:0; font-weight: bold; color: #374151;">Admin Notes:</p><p style="margin:5px 0 0 0; color: #6b7280;">{admin_notes}</p></div>' if admin_notes else ''}
                            
                            <p>You can check the status of your order in your account history.</p>
                            <p>Best Regards,<br>Green Naturals Team</p>
                        </div>
                    </div>
                    """
                    
                    import threading
                    def send_status_email():
                        sender_email = "noreply@greennaturals.store"
                        with app.app_context():
                            send_email(subject, html_content, user_email, user_name, sender_email, "Green Naturals")
                    
                    threading.Thread(target=send_status_email).start()
            except Exception as e:
                print(f"Error sending status email: {e}")

            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Not updated"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/admin/api/update-return-step', methods=['POST'])
def admin_update_return_step():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        data = request.json
        order_id = data.get('order_id')
        step = data.get('step') # 1, 2, 3, or 4
        
        if not order_id or step is None:
            return jsonify({"success": False, "error": "Missing data"}), 400
            
        # Fetch order to get user details for notification
        order = orders_collection.find_one({"order_id": order_id})
        if not order:
            return jsonify({"success": False, "error": "Order not found"}), 404
            
        labels = {1: 'Return Approved', 2: 'Item Picked Up', 3: 'Return Processing', 4: 'Return Completed'}
        current_label = labels.get(int(step), 'Return Updated')
        
        result = orders_collection.update_one(
            {"order_id": order_id},
            {
                "$set": {"return_step": int(step)},
                "$push": {
                    "tracking": {
                        "status": f"return_step_{step}",
                        "title": current_label,
                        "message": f"Your {order.get('return_type', 'return')} request has reached the step: {current_label}",
                        "timestamp": datetime.now(timezone.utc)
                    }
                }
            }
        )
        
        if result.modified_count > 0:
            # --- Send Notification Email ---
            try:
                user_email = order.get('customer', {}).get('email')
                user_name = order.get('customer', {}).get('name', 'Customer')
                
                # Fetch from user profile if not in order
                if not user_email and order.get('user_id'):
                    user = users_collection.find_one({"_id": ObjectId(order['user_id'])})
                    if user:
                        user_email = user.get('email')
                        if not user_name or user_name == 'Customer':
                            user_name = user.get('name', 'Customer')
                
                if user_email:
                    labels = {1: 'Approved', 2: 'Picked Up', 3: 'Processing', 4: 'Completed'}
                    current_label = labels.get(int(step), 'Updated')
                    req_type = order.get('return_type', 'Return/Exchange').capitalize()
                    
                    subject = f"Update: Your {req_type} Request is now {current_label}"
                    
                    html_content = f"""
                    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; border: 1px solid #eee; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
                        <div style="background-color: #f0fdf4; padding: 30px; text-align: center; border-bottom: 1px solid #dcfce7;">
                            <h2 style="color: #166534; margin: 0; font-size: 24px;">{req_type} Update</h2>
                        </div>
                        <div style="padding: 40px; line-height: 1.6;">
                            <p style="font-size: 16px;">Hello <strong>{user_name}</strong>,</p>
                            <p style="font-size: 15px;">Your {req_type.lower()} request for Order <strong>#{order_id}</strong> has been updated.</p>
                            
                            <div style="margin: 30px 0; padding: 20px; background-color: #f8fafc; border-radius: 8px; border-left: 4px solid #10b981;">
                                <p style="margin: 0; font-size: 14px; color: #64748b; text-transform: uppercase; font-weight: bold; letter-spacing: 1px;">Current Status</p>
                                <p style="margin: 5px 0 0 0; font-size: 20px; color: #0f172a; font-weight: 800;">{current_label}</p>
                            </div>
                            
                            <p style="font-size: 15px;">You can track the live progress in real-time by visiting the <strong>'My Orders'</strong> section in your account.</p>
                            
                            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; font-size: 13px; color: #94a3b8; text-align: center;">
                                Thank you for choosing <strong>Green Naturals</strong>.
                            </div>
                        </div>
                    </div>
                    """
                    
                    sender_email = "noreply@greennaturals.store"
                    threading.Thread(target=send_email, args=(subject, html_content, user_email, user_name, sender_email, "Green Naturals")).start()
            except Exception as notify_err:
                print(f"Notification Error: {notify_err}")

            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Order not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Main Entry ---

# --- ADMIN: OTP STATS API ---
@app.route('/admin/api/otp-stats')
def get_otp_stats():
    # Admin security check
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
        
    # Use IST for "Today" and "Yesterday"
    now_ist = datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
    today_date = now_ist.strftime("%Y-%m-%d")
    yesterday_date = (now_ist - timedelta(days=1)).strftime("%Y-%m-%d")
    this_month = now_ist.strftime("%Y-%m")
    
    # Filter for all Twilio/SMS related types (including legacy and resends)
    sms_filter = {"type": {"$in": ["login_sms", "login_otp", "signup_sms", "resend_sms", "forgot_password_sms"]}}
    
    today_count = otp_logs.count_documents({"$and": [sms_filter, {"date": today_date}]})
    yesterday_count = otp_logs.count_documents({"$and": [sms_filter, {"date": yesterday_date}]})
    month_count = otp_logs.count_documents({"$and": [sms_filter, {"date": {"$regex": f"^{this_month}"}}]})
    total_count = otp_logs.count_documents(sms_filter)
    
    # Weekly breakdown
    last_7_days = []
    for i in range(7):
        date_str = (now_ist - timedelta(days=i)).strftime("%Y-%m-%d")
        count = otp_logs.count_documents({"$and": [sms_filter, {"date": date_str}]})
        last_7_days.append({"date": date_str, "count": count})
    
    return jsonify({
        "today": today_count,
        "yesterday": yesterday_count,
        "month": month_count,
        "total": total_count,
        "weekly": last_7_days
    })

@app.route('/admin/api/otp-logs')
def get_all_otp_logs():
    # Admin security check
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
        
    now_ist = datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
    today_date = now_ist.strftime("%Y-%m-%d")
    
    # Filter for all Twilio/SMS related types (including legacy and resends)
    sms_filter = {"type": {"$in": ["login_sms", "login_otp", "signup_sms", "resend_sms", "forgot_password_sms"]}}
    
    # Fetch today's SMS logs, sorted by most recent
    logs = list(otp_logs.find({"$and": [sms_filter, {"date": today_date}]}).sort("timestamp", -1).limit(50))
    
    # Process for JSON
    for log in logs:
        log['_id'] = str(log['_id'])
        if 'timestamp' in log:
            # Convert UTC timestamp to IST for display
            ist_time = log['timestamp'] + timedelta(hours=5, minutes=30)
            log['time'] = ist_time.strftime("%I:%M:%S %p")
            # Include date for clarity
            log['display_date'] = ist_time.strftime("%d %b")
            del log['timestamp']
            
    return jsonify({
        "logs": logs,
        "server_time": now_ist.strftime("%I:%M %p"),
        "server_date": today_date
    })

@app.route('/diag-time')
def diag_time():
    now_utc = datetime.now(timezone.utc)
    now_ist = now_utc + timedelta(hours=5, minutes=30)
    return jsonify({
        "utc": str(now_utc),
        "ist": str(now_ist),
        "ist_date": now_ist.strftime("%Y-%m-%d"),
        "today_logic": datetime.now(timezone.utc).strftime("%Y-%m-%d")
    })

if __name__ == '__main__':
    # Debug mode development ke liye best hai
    app.run(debug=True, host='0.0.0.0', port=5000)