"""
Sri Vengamamba Food Court - POS System Backend
Flask API for handling billing, analytics, and inventory management
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient, ReturnDocument
from bson.objectid import ObjectId
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
import logging
import bcrypt
import re
from uuid import uuid4
import threading
import time

# Configure logging FIRST (before MongoDB)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Business timezone for day-boundary bill reset (12:00 AM IST)
BUSINESS_TZ = timezone(timedelta(hours=5, minutes=30))


def business_now():
    """Return current datetime in business timezone."""
    return datetime.now(BUSINESS_TZ)


def build_bill_identifier_query(token_value, created_at_iso=None):
    """Match bills stored with either legacy billNo/token and optionally the exact bill timestamp."""
    token_str = str(token_value).strip()
    token_int = int(token_str)
    query = {
        "$or": [
            {"token": token_int},
            {"token": token_str},
            {"billNo": token_int},
            {"billNo": token_str},
        ]
    }

    if created_at_iso:
        query["$and"] = [{"createdAtISO": created_at_iso}]

    return query

# Load environment variables FIRST
load_dotenv()

# MongoDB connection (lazy & correct)
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI not found in .env")

client = MongoClient(MONGO_URI)
db = client["svfc_pos"]
bills_col = db["bills"]
counter_col = db["counters"]
users_col = db["users"]
custom_items_col = db["custom_items"]
custom_categories_col = db["custom_categories"]

logger.info("✅ MongoDB client initialized")
# ============ AUTHENTICATION HELPERS ============

def hash_password(password):
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, hashed):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# ============ INITIALIZE DEFAULT USERS ============

def initialize_default_users():
    """Create or update default user accounts"""
    try:
        default_users = [
            {
                "username": "admin",
                "email": "admin@svfc.com",
                "password": "admin@256",
                "role": "admin"
            },
            {
                "username": "casher1",
                "email": "casher1@svfc.com",
                "password": "casher1@123",
                "role": "cashier"
            },
            {
                "username": "casher2",
                "email": "casher2@svfc.com",
                "password": "casher2@123",
                "role": "cashier"
            }
        ]

        allowed_emails = [user["email"] for user in default_users]
        users_col.delete_many({"email": {"$nin": allowed_emails}})

        for user in default_users:
            users_col.update_one(
                {"email": user["email"]},
                {
                    "$set": {
                        "username": user["username"],
                        "password": hash_password(user["password"]),
                        "role": user["role"]
                    },
                    "$setOnInsert": {"createdAt": datetime.now()}
                },
                upsert=True
            )

        logger.info("✅ Default accounts ensured:")
        logger.info("   👔 Admin: admin@svfc.com (password: admin@256)")
        logger.info("   💰 Casher 1: casher1@svfc.com (password: casher1@123)")
        logger.info("   💰 Casher 2: casher2@svfc.com (password: casher2@123)")
        
    except Exception as e:
        logger.error(f"Error initializing users: {str(e)}")

# Initialize users on startup
initialize_default_users()

# ============ DATA RETENTION & CLEANUP ============

def normalize_bill_datetime(raw_value):
    """Convert a bill date value (datetime or string) into a naive UTC datetime."""
    if not raw_value:
        return None

    if isinstance(raw_value, datetime):
        if raw_value.tzinfo is not None:
            return raw_value.astimezone(timezone.utc).replace(tzinfo=None)
        return raw_value

    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return None

        # Handle ISO strings ending with Z.
        normalized = text.replace("Z", "+00:00") if text.endswith("Z") else text
        try:
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except ValueError:
            pass

        # Fallback formats used by legacy rows.
        for fmt in ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue

    return None


def generate_unique_bill_no(now_utc):
    """Create a DB-only globally unique bill identifier."""
    return f"UBN-{now_utc.strftime('%Y%m%d%H%M%S%f')}-{uuid4().hex[:8].upper()}"


def sanitize_bill_for_client(bill):
    """Remove internal-only fields before sending bill data to clients."""
    if not isinstance(bill, dict):
        return bill

    sanitized = dict(bill)
    sanitized.pop("uniqueBillNo", None)
    return sanitized

def cleanup_old_bills():
    """Delete bills older than 6 months automatically"""
    try:
        # Calculate cutoff date (strictly 6 months ~= 180 days)
        cutoff_date = datetime.utcnow() - timedelta(days=180)

        old_bill_ids = []
        cursor = bills_col.find({}, {"_id": 1, "createdAt": 1, "createdAtISO": 1, "date": 1})
        for bill in cursor:
            bill_dt = (
                normalize_bill_datetime(bill.get("createdAt"))
                or normalize_bill_datetime(bill.get("createdAtISO"))
                or normalize_bill_datetime(bill.get("date"))
            )

            if bill_dt and bill_dt < cutoff_date:
                old_bill_ids.append(bill["_id"])

        if not old_bill_ids:
            return 0

        result = bills_col.delete_many({"_id": {"$in": old_bill_ids}})
        logger.info(
            f"🗑️ Cleanup: Deleted {result.deleted_count} bills older than 6 months "
            f"(before {cutoff_date.date()})"
        )
        return result.deleted_count
    
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        return 0

def check_and_cleanup():
    """Always enforce 6-month retention for bills."""
    try:
        cleanup_old_bills()
    
    except Exception as e:
        logger.warning(f"Could not perform automatic cleanup check: {str(e)}")


def daily_cleanup_scheduler():
    """Background thread: runs the 6-month bill cleanup every 24 hours."""
    while True:
        time.sleep(24 * 60 * 60)  # wait 24 hours
        logger.info("⏰ Scheduled daily cleanup starting...")
        try:
            cleanup_old_bills()
        except Exception as e:
            logger.error(f"Scheduled cleanup error: {str(e)}")

# App setup
app = Flask(__name__, static_folder=".", static_url_path="")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]}})

@app.errorhandler(404)
def not_found(error):
    # Only return JSON for API routes
    if request.path.startswith('/api/'):
        return jsonify({"success": False, "error": "Not Found"}), 404
    # For HTML files, return a simple HTML error page
    return "<h1>404 - Page Not Found</h1><p>The page you are looking for does not exist.</p>", 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    return jsonify({"success": False, "error": "Internal Server Error"}), 500

def validate_bill_data(data):
    """Validate bill data before saving to database"""
    if not isinstance(data, dict):
        return False, "Invalid request format"
    
    if not isinstance(data.get("items"), list):
        return False, "Items must be an array"
    
    total = data.get("total", 0)
    if not isinstance(total, (int, float)) or total < 0:
        return False, "Invalid total amount"
    
    payment = data.get("payment", "").strip()
    # Accept both individual and combined payment methods (updated to match frontend)
    valid_payments = ["Cash", "Card", "UPI", "Cash / UPI", "Cash/UPI"]
    if payment and payment not in valid_payments:
        return False, f"Invalid payment method: {payment}"
    
    order_type = data.get("orderType", "").strip()
    # Accept both individual and combined order types (updated to match frontend)
    valid_order_types = ["Dine-in", "Take Out", "Dine-in / Take Out", "Zomato", "Swiggy", "Swiggy / Zomato"]
    if order_type and order_type not in valid_order_types:
        return False, f"Invalid order type: {order_type}"
    
    return True, ""

# ============ FRONTEND ROUTES ============

@app.route("/")
def home():
    """Serve main POS system"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        frontend_path = os.path.join(base_dir, "frontend")
        return send_from_directory(frontend_path, "index.html")
    except Exception as e:
        logger.error(f"Error serving index.html: {str(e)}")
        return jsonify({"error": "Could not load POS system"}), 500

@app.route("/index.html")
def index_html():
    """Serve main POS system (alternative route)"""
    return home()

@app.route("/analytics.html")
def analytics():
    """Serve analytics dashboard"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        frontend_path = os.path.join(base_dir, "frontend")
        return send_from_directory(frontend_path, "analytics.html")
    except Exception as e:
        logger.error(f"Error serving analytics.html: {str(e)}")
        return jsonify({"error": "Could not load analytics"}), 500

@app.route("/analytics")
def analytics_route():
    """Serve analytics dashboard (alternative route)"""
    return analytics()

@app.route("/index")
def index_route():
    """Serve main POS system (alternative route without .html)"""
    return home()

@app.route("/login.html")
def serve_login():
    """Serve login page"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        frontend_path = os.path.join(base_dir, "frontend")
        file_path = os.path.join(frontend_path, "login.html")
        return send_from_directory(frontend_path, "login.html")
    except Exception as e:
        logger.error(f"Error serving login.html: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({"error": "Could not load login page", "detail": str(e)}), 500

@app.route("/login")
def login():
    """Serve login page (alternative route)"""
    return serve_login()

# ============ AUTHENTICATION ============

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({"success": False, "error": "Email and password required"}), 400
        
        # Find user by email
        user = users_col.find_one({"email": data['email'].lower()})
        
        if not user:
            return jsonify({"success": False, "error": "Invalid credentials"}), 401
        
        # Verify password
        if not verify_password(data['password'], user['password']):
            return jsonify({"success": False, "error": "Invalid credentials"}), 401
        
        # Create access token
        access_token = create_access_token(identity=str(user['_id']))
        
        logger.info(f"✅ User logged in: {user['username']}")
        return jsonify({
            "success": True,
            "message": "Login successful",
            "token": access_token,
            "user": {
                "id": str(user['_id']),
                "username": user['username'],
                "email": user['email'],
                "role": user.get('role', 'staff')
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"success": False, "error": "Login failed"}), 500

@app.route("/api/auth/verify", methods=["GET"])
@jwt_required()
def verify_token():
    """Verify if token is valid"""
    try:
        user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        return jsonify({
            "success": True,
            "user": {
                "id": str(user['_id']),
                "username": user['username'],
                "email": user['email'],
                "role": user.get('role', 'staff')
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return jsonify({"success": False, "error": "Invalid token"}), 401

def check_and_reset_daily_counter():
    """Reset the next bill number to 1 when calendar day changes at 12:00 AM (business timezone)."""
    try:
        now_local = business_now()

        # Get or initialize counter from database
        counter = counter_col.find_one({"_id": "token"})
        
        if not counter:
            # Initialize new counter
            counter_col.insert_one({
                "_id": "token",
                "value": 1,
                "lastReset": now_local
            })
            return 1, False

        # Reset when date changes (midnight boundary in business timezone)
        last_reset = counter.get("lastReset", now_local)
        if isinstance(last_reset, datetime):
            if last_reset.tzinfo is None:
                # Mongo often returns naive UTC datetimes
                last_reset = last_reset.replace(tzinfo=timezone.utc)
            last_reset_local = last_reset.astimezone(BUSINESS_TZ)
        else:
            last_reset_local = now_local

        if last_reset_local.date() < now_local.date():
            counter_col.update_one(
                {"_id": "token"},
                {"$set": {"value": 1, "lastReset": now_local}}
            )
            logger.info("♻️ Midnight Bill Counter Reset - Next Bill #1 (12:00 AM day rollover)")
            return 1, True
        
        # Return current value and reset status
        return counter.get("value", 1), False
        
    except Exception as e:
        logger.error(f"Error in counter reset check: {str(e)}")
        return 0, False

@app.route("/api/token", methods=["GET"])
def get_token():
    """Fetch and increment bill token from database"""
    try:
        # Check and reset if 24 hours have passed
        _, was_reset = check_and_reset_daily_counter()
        
        # If just reset, return 1 without incrementing
        if was_reset:
            logger.info(f"Bill counter reset detected - Returning Bill #1")
            return jsonify({
                "success": True,
                "token": 1
            }), 200
        
        # Return the current bill number and advance the stored counter for the next bill
        token_doc = counter_col.find_one_and_update(
            {"_id": "token"},
            {"$inc": {"value": 1}},
            return_document=ReturnDocument.BEFORE,
            upsert=True
        )
        
        if not token_doc or "value" not in token_doc:
            raise ValueError("Failed to fetch token from database")
        
        bill_number = token_doc["value"]
        logger.debug(f"Bill #{bill_number} generated from database counter")
        
        return jsonify({
            "success": True,
            "token": bill_number
        }), 200
    
    except Exception as e:
        logger.error(f"Error generating token: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to generate token"
        }), 500

@app.route("/api/token/current", methods=["GET"])
def get_current_token():
    """Fetch the next bill token from database without incrementing"""
    try:
        # Check and reset if 24 hours have passed
        _, was_reset = check_and_reset_daily_counter()
        
        # If just reset, return 1
        if was_reset:
            return jsonify({
                "success": True,
                "token": 1
            }), 200
        
        # Fetch current value from database (this is the next bill number to use)
        token_doc = counter_col.find_one({"_id": "token"})
        
        if not token_doc:
            token_doc = {"value": 1}
        
        current_bill_number = token_doc.get("value", 1)
        
        logger.debug(f"Current Next Bill: #{current_bill_number}")
        
        return jsonify({
            "success": True,
            "token": current_bill_number
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching current token: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to fetch current token"
        }), 500

# ============ BILL MANAGEMENT ============

@app.route("/api/bill", methods=["POST"])
def save_bill():
    """Save a new bill to the database"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "error": "No data provided"
            }), 400
        
        # Validate bill data
        is_valid, error_msg = validate_bill_data(data)
        if not is_valid:
            return jsonify({
                "success": False,
                "error": error_msg
            }), 400
        
        # Generate/assign a unique bill token server-side and advance the stored next number
        now_utc = datetime.now(timezone.utc)
        try:
            # Ensure daily reset if required
            check_and_reset_daily_counter()
            token_doc = counter_col.find_one({"_id": "token"}) or {"value": 1}
            bill_number = int(token_doc.get("value", 1))
            counter_col.update_one(
                {"_id": "token"},
                {"$set": {"value": bill_number + 1, "lastReset": business_now()}},
                upsert=True
            )
        except Exception:
            # Fallback to safe value
            bill_number = int(data.get("token", 0)) or 0

        bill = {
            "items": data.get("items", []),
            "total": float(data.get("total", 0)),
            "payment": data.get("payment", "Unknown").strip(),
            "orderType": data.get("orderType", "Unknown").strip(),
            "token": int(bill_number),
            "uniqueBillNo": generate_unique_bill_no(now_utc),
            "createdAt": now_utc,
            "createdAtISO": now_utc.isoformat()
        }
        
        # Save to database
        result = bills_col.insert_one(bill)
        
        logger.info(f"✅ Bill saved - Token: {bill['token']}, Total: ₹{bill['total']}, Items: {len(bill['items'])}")
        
        return jsonify({
            "success": True,
            "message": "Bill saved successfully",
            "billId": str(result.inserted_id),
            "token": bill["token"]
        }), 201
    
    except Exception as e:
        logger.error(f"Error saving bill: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to save bill"
        }), 500

@app.route("/api/bills", methods=["GET"])
def get_bills():
    """Retrieve all bills with optional filters"""
    try:
        # Check and cleanup old bills on each analytics page load
        check_and_cleanup()
        
        # Optional query parameters
        days = request.args.get("days", type=int, default=None)
        payment = request.args.get("payment", default=None)
        order_type = request.args.get("orderType", default=None)
        limit = request.args.get("limit", type=int, default=1000)
        include_deleted = request.args.get("includeDeleted", default="false").lower() == "true"
        
        # Build filter
        filter_query = {}
        
        if days:
            cutoff_date = datetime.now() - timedelta(days=days)
            filter_query["createdAt"] = {"$gte": cutoff_date}
        
        if payment:
            filter_query["payment"] = payment
        
        if order_type:
            filter_query["orderType"] = order_type
        
        # Exclude soft-deleted bills unless specifically requested
        if not include_deleted:
            filter_query["deleted"] = {"$ne": True}
        
        # Fetch and return bills (sort by token number descending to show latest bills first)
        bills = list(
            bills_col.find(filter_query, {"_id": 0})
            .sort([("createdAt", -1), ("token", -1)])
            .limit(limit)
        )
        
        # Convert datetime objects to ISO format strings for JSON serialization
        for bill in bills:
            if isinstance(bill.get('createdAt'), datetime):
                bill['createdAt'] = bill['createdAt'].isoformat()
            if isinstance(bill.get('createdAtISO'), str):
                # Already a string, keep it
                pass

        bills = [sanitize_bill_for_client(bill) for bill in bills]
        
        logger.debug(f"Fetching bills: Found {len(bills)} bills")
        return jsonify(bills), 200
    
    except Exception as e:
        logger.error(f"Error fetching bills: {str(e)}")
        # Return empty array on database error instead of error response
        return jsonify([]), 200

@app.route("/api/bill/<token>", methods=["GET"])
def get_bill(token):
    """Get a specific bill by token number"""
    try:
        bill = bills_col.find_one(
            {"token": int(token)},
            {"_id": 0}
        )

        if bill:
            # When bill numbers repeat after midnight reset, return the newest match.
            bill = bills_col.find(
                {"token": int(token)},
                {"_id": 0}
            ).sort("createdAt", -1).limit(1)
            bill = next(bill, None)
        
        if not bill:
            return jsonify({
                "success": False,
                "error": "Bill not found"
            }), 404
        
        return jsonify({
            "success": True,
            "bill": sanitize_bill_for_client(bill)
        }), 200
    
    except ValueError:
        return jsonify({
            "success": False,
            "error": "Invalid token"
        }), 400
    
    except Exception as e:
        logger.error(f"Error fetching bill: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to fetch bill"
        }), 500

@app.route("/api/bill/<token>/delete", methods=["PUT"])
@jwt_required()
def delete_bill(token):
    """Soft-delete a bill (mark as deleted instead of permanent removal)"""
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(current_user_id)})
        
        # Check if user is admin
        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403
        
        token_int = int(token)
        body = request.get_json(silent=True) or {}
        created_at_iso = (body.get("createdAtISO") or request.args.get("createdAtISO") or request.args.get("createdAt") or "").strip()
        bill_query = build_bill_identifier_query(token, created_at_iso or None)
        result = bills_col.update_one(
            bill_query,
            {"$set": {"deleted": True}}
        )
        
        if result.matched_count == 0:
            return jsonify({
                "success": False,
                "error": "Bill not found"
            }), 404
        
        logger.info(f"✅ Bill marked as deleted - Token: {token_int}")
        
        return jsonify({
            "success": True,
            "message": "Bill marked as deleted"
        }), 200
    
    except ValueError:
        return jsonify({
            "success": False,
            "error": "Invalid token"
        }), 400
    
    except Exception as e:
        logger.error(f"Error deleting bill: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to delete bill"
        }), 500

@app.route("/api/bill/<token>/restore", methods=["PUT"])
@jwt_required()
def restore_bill(token):
    """Restore a soft-deleted bill (unhide)"""
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(current_user_id)})
        
        # Check if user is admin
        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403
        
        token_int = int(token)
        body = request.get_json(silent=True) or {}
        created_at_iso = (body.get("createdAtISO") or request.args.get("createdAtISO") or request.args.get("createdAt") or "").strip()
        bill_query = build_bill_identifier_query(token, created_at_iso or None)
        result = bills_col.update_one(
            bill_query,
            {"$set": {"deleted": False}}
        )
        
        if result.matched_count == 0:
            return jsonify({
                "success": False,
                "error": "Bill not found"
            }), 404
        
        logger.info(f"✅ Bill restored - Token: {token_int}")
        
        return jsonify({
            "success": True,
            "message": "Bill restored successfully"
        }), 200
    
    except ValueError:
        return jsonify({
            "success": False,
            "error": "Invalid token"
        }), 400
    
    except Exception as e:
        logger.error(f"Error restoring bill: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to restore bill"
        }), 500

@app.route("/api/bill/<token>/permanent-delete", methods=["DELETE"])
@jwt_required()
def permanent_delete_bill(token):
    """Permanently delete a bill from database (admin only)"""
    try:
        # Get current user
        current_user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(current_user_id)})
        
        # Check if user is admin
        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403
        token_int = int(token)
        request_data = request.get_json(silent=True) or {}
        created_at_iso = str(request_data.get("createdAtISO") or request.args.get("createdAtISO") or request.args.get("createdAt") or "").strip()

        bill_query = build_bill_identifier_query(token, created_at_iso or None)
        result = bills_col.delete_one(bill_query)
        
        if result.deleted_count == 0:
            return jsonify({
                "success": False,
                "error": "Bill not found"
            }), 404
        
        logger.warning(f"⚠️ Bill permanently deleted - Token: {token_int}")
        
        return jsonify({
            "success": True,
            "message": "Bill permanently deleted"
        }), 200
    
    except ValueError:
        return jsonify({
            "success": False,
            "error": "Invalid token"
        }), 400
    
    except Exception as e:
        logger.error(f"Error permanently deleting bill: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to permanently delete bill"
        }), 500

# ============ ANALYTICS ENDPOINTS ============

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    try:
        client.admin.command('ping')
        return jsonify({
            "success": True,
            "status": "healthy",
            "database": "connected"
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            "success": False,
            "status": "unhealthy",
            "database": "disconnected"
        }), 500

# ============ CUSTOM MENU ITEMS ============

@app.route("/api/custom-items", methods=["GET"])
@jwt_required()
def get_custom_items():
    """Get all custom menu items"""
    try:
        items = list(custom_items_col.find({}, {"_id": 0}))
        return jsonify({
            "success": True,
            "items": items
        }), 200
    except Exception as e:
        logger.error(f"Error fetching custom items: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to fetch custom items"
        }), 500

@app.route("/api/custom-items", methods=["POST"])
@jwt_required()
def add_custom_item():
    """Add a new custom menu item"""
    try:
        data = request.get_json()
        
        if not data or not data.get("name") or not data.get("price"):
            return jsonify({
                "success": False,
                "error": "Name and price are required"
            }), 400
        
        item = {
            "name": data["name"].strip(),
            "price": float(data["price"]),
            "category": data.get("category", "Custom").strip(),
            "imageUrl": (data.get("imageUrl") or "").strip(),
            "createdAt": datetime.now(),
            "createdBy": get_jwt_identity()
        }
        
        # Check if item already exists
        existing = custom_items_col.find_one({"name": item["name"]})
        if existing:
            return jsonify({
                "success": False,
                "error": "Item with this name already exists"
            }), 400
        
        custom_items_col.insert_one(item)
        
        logger.info(f"✅ Custom item added: {item['name']} - ₹{item['price']}")
        
        return jsonify({
            "success": True,
            "message": "Custom item added successfully",
            "item": {
                "name": item["name"],
                "price": item["price"],
                "category": item["category"],
                "imageUrl": item["imageUrl"]
            }
        }), 201
    except Exception as e:
        logger.error(f"Error adding custom item: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to add custom item"
        }), 500

@app.route("/api/custom-items/<name>", methods=["DELETE"])
@jwt_required()
def delete_custom_item(name):
    """Delete a custom menu item (Admin only)"""
    try:
        # Get current user from JWT (identity is user id)
        current_user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(current_user_id)})
        
        # Check if user is admin
        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403
        
        result = custom_items_col.delete_one({"name": name})
        
        if result.deleted_count == 0:
            return jsonify({
                "success": False,
                "error": "Item not found"
            }), 404
        
        logger.info(f"✅ Custom item deleted: {name}")
        
        return jsonify({
            "success": True,
            "message": "Custom item deleted successfully"
        }), 200
    except Exception as e:
        logger.error(f"Error deleting custom item: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to delete custom item"
        }), 500

@app.route("/api/custom-items/<name>", methods=["PUT"])
@jwt_required()
def update_custom_item(name):
    """Update a custom menu item (Admin only)"""
    try:
        current_user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(current_user_id)})

        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403

        payload = request.get_json() or {}
        old_name = (name or "").strip()
        new_name = (payload.get("name") or "").strip()
        category = (payload.get("category") or "Custom").strip()
        image_url = (payload.get("imageUrl") or "").strip()

        if not old_name:
            return jsonify({"success": False, "error": "Item name is required"}), 400

        if not new_name:
            return jsonify({"success": False, "error": "New item name is required"}), 400

        if payload.get("price") is None:
            return jsonify({"success": False, "error": "Price is required"}), 400

        try:
            price = float(payload.get("price"))
            if price <= 0:
                raise ValueError()
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Price must be a positive number"}), 400

        source_query = {
            "name": {
                "$regex": f"^{re.escape(old_name)}$",
                "$options": "i"
            }
        }
        existing_item = custom_items_col.find_one(source_query)
        if not existing_item:
            return jsonify({"success": False, "error": "Item not found"}), 404

        if existing_item.get("name", "").lower() != new_name.lower():
            duplicate_query = {
                "name": {
                    "$regex": f"^{re.escape(new_name)}$",
                    "$options": "i"
                }
            }
            duplicate_item = custom_items_col.find_one(duplicate_query)
            if duplicate_item:
                return jsonify({"success": False, "error": "Another item with this name already exists"}), 400

        custom_items_col.update_one(
            {"_id": existing_item["_id"]},
            {
                "$set": {
                    "name": new_name,
                    "price": price,
                    "category": category or "Custom",
                    "imageUrl": image_url,
                    "updatedAt": datetime.now(),
                    "updatedBy": str(user.get("email", current_user_id))
                }
            }
        )

        logger.info(f"✅ Custom item updated: {existing_item.get('name')} -> {new_name}")
        return jsonify({
            "success": True,
            "message": "Custom item updated successfully",
            "item": {
                "name": new_name,
                "price": price,
                "category": category or "Custom",
                "imageUrl": image_url
            }
        }), 200
    except Exception as e:
        logger.error(f"Error updating custom item: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to update custom item"
        }), 500

@app.route("/api/custom-categories", methods=["GET"])
@jwt_required()
def get_custom_categories():
    """Get all custom categories"""
    try:
        categories = list(custom_categories_col.find({}, {"_id": 0, "name": 1}).sort("name", 1))
        return jsonify({
            "success": True,
            "categories": [c["name"] for c in categories if c.get("name")]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching custom categories: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to fetch custom categories"
        }), 500

@app.route("/api/custom-categories", methods=["POST"])
@jwt_required()
def add_custom_category():
    """Add a new custom category (Admin only)"""
    try:
        user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(user_id)})
        if not user or user.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin access required"}), 403

        data = request.get_json() or {}
        category_name = (data.get("name") or "").strip()

        if not category_name:
            return jsonify({"success": False, "error": "Category name is required"}), 400

        existing = custom_categories_col.find_one({
            "name": {
                "$regex": f"^{re.escape(category_name)}$",
                "$options": "i"
            }
        })
        if existing:
            return jsonify({"success": False, "error": "Category already exists"}), 400

        custom_categories_col.insert_one({
            "name": category_name,
            "createdAt": datetime.now(),
            "createdBy": str(user.get("email", user_id))
        })

        logger.info(f"✅ Custom category added: {category_name}")
        return jsonify({
            "success": True,
            "message": "Category added successfully",
            "category": category_name
        }), 201
    except Exception as e:
        logger.error(f"Error adding custom category: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to add custom category"
        }), 500

@app.route("/api/custom-categories/<name>", methods=["DELETE"])
@jwt_required()
def delete_custom_category(name):
    """Delete a custom category (Admin only)"""
    try:
        user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(user_id)})
        if not user or user.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin access required"}), 403

        category_name = (name or "").strip()
        if not category_name:
            return jsonify({"success": False, "error": "Category name is required"}), 400

        category_query = {
            "name": {
                "$regex": f"^{re.escape(category_name)}$",
                "$options": "i"
            }
        }

        existing = custom_categories_col.find_one(category_query)
        if not existing:
            return jsonify({"success": False, "error": "Category not found"}), 404

        custom_categories_col.delete_one({"_id": existing["_id"]})
        removed_items = custom_items_col.delete_many({"category": existing.get("name", category_name)}).deleted_count

        logger.info(f"✅ Custom category deleted: {existing.get('name', category_name)} (removed {removed_items} linked item(s))")
        return jsonify({
            "success": True,
            "message": "Category deleted successfully",
            "deletedCategory": existing.get("name", category_name),
            "removedItems": removed_items
        }), 200
    except Exception as e:
        logger.error(f"Error deleting custom category: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Failed to delete custom category"
        }), 500

# ============ ERROR HANDLING ============

@app.before_request
def log_request():
    """Log incoming requests"""
    logger.debug(f"{request.method} {request.path}")

@app.after_request
def log_response(response):
    """Log outgoing responses"""
    logger.debug(f"Response status: {response.status_code}")
    return response

# ============ SERVER START ============

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("DEBUG", "True").lower() == "true"
    
    logger.info(f"🚀 Starting Flask server on port {port} (Debug: {debug_mode})")
    logger.info("📊 Analytics available at http://localhost:{}/analytics.html".format(port))
    logger.info("💳 POS System available at http://localhost:{}/".format(port))
    
    # Run cleanup immediately on startup
    check_and_cleanup()

    # Start background daily cleanup scheduler (runs every 24 hours)
    cleanup_thread = threading.Thread(target=daily_cleanup_scheduler, daemon=True, name="DailyCleanup")
    cleanup_thread.start()
    logger.info("🔄 Daily cleanup scheduler started (runs every 24 hours)")
    
    app.run(
        debug=debug_mode,
        port=port,
        host="0.0.0.0",
        use_reloader=False
    )
