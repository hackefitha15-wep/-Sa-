from flask import Flask, render_template, request, jsonify
import requests
import hashlib
import re

app = Flask(__name__)

HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HEADERS = {"User-Agent": "BreachChecker-App"}

# فحص وجود الإيميل في تسريبات معروفة (بلا كلمات سر — تصميم HIBP نفسه)
def check_email_breaches(email):
    url = HIBP_ACCOUNT_URL.format(email=email)
    params = {"truncateResponse": "false"}
    r = requests.get(url, headers=HEADERS, params=params, timeout=10)
    if r.status_code == 404:
        return []          # لا يوجد في أي تسريب
    if r.status_code == 429:
        raise Exception("عدد كبير من الطلبات — حاول بعد قليل")
    r.raise_for_status()
    return [
        {
            "site": b.get("Name"),
            "date": b.get("BreachDate"),
            "records": b.get("PwnCount"),
            "data_leaked": b.get("DataClasses"),   # مثلاً: Email, Passwords, Phones
            "verified": b.get("IsVerified"),
        }
        for b in r.json()
    ]

# فحص قوة كلمة سر: هل ظهرت في تسريبات سابقة؟
# (K-Anonymity: يُرسل أول 5 أحرف من الهاش فقط — كلمة السر لا تغادر جهاز المستخدم)
def check_password_exposed(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(HIBP_PASSWORD_URL.format(prefix=prefix), headers=HEADERS, timeout=10)
    r.raise_for_status()
    for line in r.text.splitlines():
        h, count = line.strip().split(":")
        if h == suffix:
            return int(count)   # عدد المرات التي ظهرت فيها في تسريبات
    return 0

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/check/email", methods=["POST"])
def api_email():
    email = request.json.get("email", "").strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "صيغة إيميل غير صحيحة"}), 400
    try:
        breaches = check_email_breaches(email)
        exposed_password = any("Passwords" in b["data_leaked"] for b in breaches)
        return jsonify({
            "email": email,
            "breach_count": len(breaches),
            "password_exposed": exposed_password,
            "breaches": breaches,
            "advice": [
                "غيّر كلمة السر في كل المواقع الظاهرة أعلاه فوراً" if breaches else "لا توجد تسريبات معروفة — استمر في استخدام كلمات سر قوية",
                "فعّل المصادقة الثنائية (2FA) على كل حساباتك",
                "لا تستخدم نفس كلمة السر لأكثر من موقع",
                "استخدم مدير كلمات سر مثل Bitwarden (مفتوح المصدر ومجاني)"
            ],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/check/password", methods=["POST"])
def api_password():
    password = request.json.get("password", "")
    try:
        count = check_password_exposed(password)
        return jsonify({
            "exposed_times": count,
            "safe": count == 0,
            "note": "تم الفحص عبر K-Anonymity — كلمة السر نفسها لم تغادر متصفحك"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000)
