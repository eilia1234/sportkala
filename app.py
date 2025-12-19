# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import requests
import os
from dotenv import load_dotenv
import json
import re

# ---------------- init ----------------


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "eilia_secret_key_2025")

basedir = os.path.abspath(os.path.dirname(__file__))
# use instance/e.db (create instance dir if missing)
instance_dir = os.path.join(basedir, "e")
if not os.path.isdir(instance_dir):
    os.makedirs(instance_dir, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(instance_dir, 'e.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.debug = True  # dev mode

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------- models ----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), nullable=False)
    messages = db.Column(db.Text, nullable=False)  # JSON

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

# ---------------- helpers ----------------
def load_products():
    try:
        with open("products.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def find_product_by_message(message):
    products = load_products()
    code_match = re.search(r"\b\d{2,5}\b", message)
    if code_match:
        code = code_match.group(0)
        if code in products:
            return products[code]

    message_lower = message.lower()
    for product in products.values():
        name = product.get("name", "").lower()
        keywords = [kw.lower() for kw in product.get("keywords", [])]
        brand = product.get("brand", "").lower()
        if any(kw in message_lower for kw in [name, brand] + keywords):
            return product
    return None

# ---------------- routes ----------------
@app.route("/")
@app.route("/index")
def home():
    return render_template("index.html", user=current_user)

@app.route("/m")
def store():
    return render_template("m.html", user=current_user)

@app.route("/h")
def about():
    return render_template("h.html", user=current_user)

@app.route("/call with us")
def call():
    return render_template("callwithus.html", user=current_user)

@app.route("/index3")
def shoes():
    return render_template("index3.html", user=current_user)

@app.route("/index4")
def ball():
    return render_template("index4.html", user=current_user)

@app.route("/index5")
def domble():
    return render_template("index5.html", user=current_user)

@app.route("/index6")
def bag():
    return render_template("index6.html", user=current_user)

@app.route("/index7")
def bottle():
    return render_template("index7.html", user=current_user)

@app.route("/index8")
def ract():
    return render_template("index8.html", user=current_user)

@app.route("/index9")
def kitb():
    return render_template("index9.html", user=current_user)

@app.route("/index10")
def swach():
    return render_template("index10.html", user=current_user)

@app.route("/index11")
def shoes2():
    return render_template("index11.html", user=current_user)

@app.route("/index12")
def ball2():
    return render_template("index12.html", user=current_user)

@app.route("/index13")
def tshirt4():
    return render_template("index13.html", user=current_user)

@app.route("/index14")
def bwater6():
    return render_template("index14.html", user=current_user)

@app.route("/index15")
def cboard():
    return render_template("index15.html", user=current_user)



@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not email or not password:
            flash("لطفاً همه فیلدها را پر کنید", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(username=username).first():
            flash("نام کاربری قبلاً ثبت شده", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("ایمیل قبلاً ثبت شده", "danger")
            return redirect(url_for("signup"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, email=email, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.exception("Signup DB error")
            flash(f"خطا در ثبت نام: {e}", "danger")
            return redirect(url_for("signup"))

        login_user(new_user)
        flash("ثبت‌نام موفق بود، خوش آمدید!", "success")
        return redirect(url_for("home"))

    return render_template("signup.html", user=current_user)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if not user:
            app.logger.debug(f"Login failed: user {username} not found")
            flash("نام کاربری یا رمز عبور اشتباه است", "danger")
            return redirect(url_for("login"))

        try:
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                flash("ورود موفقیت‌آمیز بود", "success")
                return redirect(url_for("home"))
            else:
                app.logger.debug(f"Login failed: wrong password for {username}")
                flash("نام کاربری یا رمز عبور اشتباه است", "danger")
                return redirect(url_for("login"))
        except Exception as e:
            app.logger.exception("Error while checking password")
            flash("خطا در بررسی رمز عبور", "danger")
            return redirect(url_for("login"))

    return render_template("login.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("با موفقیت خارج شدید", "info")
    return redirect(url_for("login"))

from openai import OpenAI

# --- کلاینت AvalAI ---
avalai_client = OpenAI(
    api_key="aa-aIx1xu6DsSRLL9Xna9CriR0OWCYo8gNGY6FJgBAz5f9Fhdxa",
    base_url="https://api.avalai.ir/v1"
)

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json() or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"reply": "هیچ پیامی دریافت نشد 😅"})

    # شناسایی کاربر
    if current_user.is_authenticated:
        user_id = str(current_user.id)
    else:
        # برای کاربران لاگین نشده از IP یا session استفاده کن
        user_id = request.remote_addr

    # ---------------- Load or create conversation ----------------
    conv = Conversation.query.filter_by(user_id=user_id).first()
    history = []
    if conv and conv.messages:
        try:
            history = json.loads(conv.messages)
            if not isinstance(history, list):
                history = []
        except Exception:
            history = []

    # فقط پیام‌های درست با role و content
    cleaned_history = [msg for msg in history if isinstance(msg, dict) and "role" in msg and "content" in msg]

    # ---------------- System prompt کلی ----------------
    system_prompt = {
        "role": "system",
        "content": (
            "تو دستیار هوشمند فروشگاه اسپرت کالا هستی به نام سیریا. "
            "همیشه با لحن دوستانه، دقیق و فارسی طبیعی پاسخ بده. "
            "هدف تو توضیح و تجزیه و تحیل محصولی که کاربر نام یا کد ان را وارد میکند است تو نباید اطلاعات آن محصول را کپی و برای کاربر ارسال کنی تو باید ان محصول را تحلیل کنی و به کاربر نتیجه رو به کاربر بگویی "
            "اگر درباره شخصی  یا چیزی اطلاعات نداری حتما بگو : (درباره آن اطلاعاتی ندارم)"
            "هیچ وقت خودت را ChatGPT معرفی نکن و همیشه خودت را سیریا بدان. "
            "تو باید برنامه نویسی هم انجام بدی"
            "تو توسط ایلیا ساخته شدی و همیشه به نفع اسپرت کالا پاسخ می‌دهی."
        )
    }

    # پیام‌ها برای ارسال به AI
    payload_messages = [system_prompt] + cleaned_history[-30:]
    payload_messages.append({"role": "user", "content": message})

    # ---------------- بررسی محصول ----------------
    product = find_product_by_message(message)
    assistant_reply = None

    if product:
        keywords = {
            "price": ["قیمت", "چنده", "price", "چقدر"],
            "features": ["ویژگی", "خصوصیت", "کاربرد", "مزایا"],
            "material": ["جنس", "متریال", "ساخت"],
            "category": ["دسته", "نوع", "رنگ", "مدل"]
        }

        msg_lower = message.lower()
        if any(k in msg_lower for k in keywords["price"]):
            assistant_reply = f"💰 قیمت محصول '{product['name']}' {product['price']} تومان است."
        elif any(k in msg_lower for k in keywords["features"]):
            features = ", ".join(product.get("features", []))
            assistant_reply = f"⚡ ویژگی‌ها و کاربردهای محصول '{product['name']}': {features}"
        elif any(k in msg_lower for k in keywords["material"]):
            material = product.get("material", "اطلاعات موجود نیست")
            assistant_reply = f"🧵 جنس محصول '{product['name']}' از {material} ساخته شده است."
        elif any(k in msg_lower for k in keywords["category"]):
            category = product.get("category", "نامشخص")
            assistant_reply = f"🏷️ دسته‌بندی محصول '{product['name']}': {category}"
        else:
            product_context = {
                "name": product.get("name"),
                "brand": product.get("brand"),
                "category": product.get("category"),
                "features": product.get("features", []),
                "price": product.get("price"),
                "material": product.get("material", "نامشخص")
            }
            payload_messages.append({
                "role": "system",
                "content": (
                    "اطلاعات محصول زیر برای تجزیه و تحلیل است. لطفاً آن را تحلیل و توضیح بده، "
                    "ویژگی‌ها، کاربردها و نکات مثبت محصول را به شکل دوستانه و مفصل بیان کن، "
                    "و فقط متن محصول را کپی نکن.\n\n"
                    f"{json.dumps(product_context, ensure_ascii=False, indent=2)}"
                )
            })

    # ---------------- ارسال به AvalAI ----------------
    if assistant_reply is None:
        try:
            completion = avalai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=payload_messages,
                temperature=0.7
            )
            assistant_reply = completion.choices[0].message.content.strip()
        except Exception as e:
            print("❌ خطا در ارتباط با AvalAI:", e)
            assistant_reply = "مشکلی در ارتباط با سرور هوش مصنوعی پیش آمد."

    # ---------------- ذخیره مکالمه ----------------
    try:
        new_entries = [
            {"role": "user", "content": message},
            {"role": "assistant", "content": assistant_reply},
        ]
        cleaned_history.extend(new_entries)
        # فقط 60 پیام آخر را ذخیره می‌کنیم
        if conv:
            conv.messages = json.dumps(cleaned_history[-60:], ensure_ascii=False)
        else:
            conv = Conversation(user_id=user_id, messages=json.dumps(cleaned_history[-60:], ensure_ascii=False))
            db.session.add(conv)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("❌ خطا در ذخیره حافظه:", e)

    return jsonify({"reply": assistant_reply})





from datetime import datetime, timedelta

@app.route("/offer-timer")
def offer_timer():
    iran_now = datetime.utcnow() + timedelta(hours=3, minutes=30)

    PERIOD = 48 * 60 * 60  # ۴۸ ساعت

    # نیمه‌شب امروز ایران
    midnight = iran_now.replace(hour=0, minute=0, second=0, microsecond=0)

    elapsed = int((iran_now - midnight).total_seconds())

    # اگر بیشتر از ۴۸ ساعت گذشته، وارد دوره بعدی می‌شویم
    elapsed %= PERIOD

    remaining = PERIOD - elapsed

    return jsonify({
        "remaining": remaining
    })


# ---------------- run ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run( port=5000, debug=True)
    
