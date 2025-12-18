# =========================
# app.py
# =========================

import os
import json
import re
import requests
from dotenv import load_dotenv

from flask import (
    Flask, render_template, request,
    jsonify, redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, UserMixin, current_user
)

from openai import OpenAI

# ---------------- load env ----------------
load_dotenv()

# ---------------- init app ----------------
app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "eilia_secret_key_2025")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "e")

os.makedirs(INSTANCE_DIR, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(INSTANCE_DIR, 'e.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.debug = True

# ---------------- extensions ----------------
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# =========================
# Models
# =========================
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
    




# =========================
# Helpers
# =========================
def load_products():
    try:
        with open("products.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def find_product_by_message(message: str):
    products = load_products()

    code_match = re.search(r"\b\d{2,5}\b", message)
    if code_match:
        code = code_match.group(0)
        if code in products:
            return products[code]

    msg = message.lower()

    for product in products.values():
        name = product.get("name", "").lower()
        brand = product.get("brand", "").lower()
        keywords = [k.lower() for k in product.get("keywords", [])]

        if any(k in msg for k in [name, brand] + keywords):
            return product

    return None


# =========================
# Routes (Pages)
# =========================
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



# =========================
# Auth
# =========================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not all([username, email, password]):
            flash("لطفاً همه فیلدها را پر کنید", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(username=username).first():
            flash("نام کاربری قبلاً ثبت شده", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("ایمیل قبلاً ثبت شده", "danger")
            return redirect(url_for("signup"))

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(username=username, email=email, password=hashed)

        try:
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash("خطا در ثبت نام", "danger")
            return redirect(url_for("signup"))

        login_user(user)
        flash("ثبت‌نام موفق بود 🎉", "success")
        return redirect(url_for("home"))

    return render_template("signup.html", user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            flash("نام کاربری یا رمز عبور اشتباه است", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash("ورود موفقیت‌آمیز بود", "success")
        return redirect(url_for("home"))

    return render_template("login.html", user=current_user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("با موفقیت خارج شدید", "info")
    return redirect(url_for("login"))


# =========================
# AI Client (AvalAI)
# =========================
avalai_client = OpenAI(
    api_key="aa-eNwB0IrzyDFqu1vGYqtFERnsf0YUoGEu8Pw1GXiLvDVw87Ky",
    base_url="https://api.avalai.ir/v1"
)


# =========================
# Chat API
# =========================
@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"reply": "هیچ پیامی دریافت نشد 😅"})

    user_id = str(current_user.id) if current_user.is_authenticated else "guest"

    conv = Conversation.query.filter_by(user_id=user_id).first()
    history = []

    if conv:
        try:
            history = json.loads(conv.messages)
        except Exception:
            history = []

    history = [m for m in history if isinstance(m, dict) and "role" in m and "content" in m]

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

    messages = [system_prompt] + history[-30:]
    messages.append({"role": "user", "content": message})

    product = find_product_by_message(message)
    assistant_reply = None

    if product:
        context = {
            "name": product.get("name"),
            "brand": product.get("brand"),
            "category": product.get("category"),
            "features": product.get("features", []),
            "price": product.get("price"),
            "material": product.get("material", "نامشخص")
        }

        messages.append({
            "role": "system",
            "content": f"اطلاعات محصول:\n{json.dumps(context, ensure_ascii=False, indent=2)}"
        })

    try:
        res = avalai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.7
        )
        assistant_reply = res.choices[0].message.content.strip()
    except Exception:
        assistant_reply = "مشکلی در ارتباط با سرور هوش مصنوعی پیش آمد."

    new_history = history + [
        {"role": "user", "content": message},
        {"role": "assistant", "content": assistant_reply}
    ]

    try:
        if conv:
            conv.messages = json.dumps(new_history[-60:], ensure_ascii=False)
        else:
            conv = Conversation(
                user_id=user_id,
                messages=json.dumps(new_history[-60:], ensure_ascii=False)
            )
            db.session.add(conv)

        db.session.commit()
    except Exception:
        db.session.rollback()

    return jsonify({"reply": assistant_reply})




# =========================
# Run
# =========================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(port=5000, debug=True)
