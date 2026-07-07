from flask import Flask, render_template, request
from utils.auditor import audit_password
import re

app = Flask(__name__)

# ---------------------------------------
# Home Page
# ---------------------------------------
@app.route("/")

def home():
    return render_template("index.html")

# ---------------------------------------
# Analyze Password
# ---------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():

    username = request.form.get("username", "").strip()

    password = request.form.get("password", "")

    if not username:

        return render_template(
            "report.html",
            result={
                "result": "FAIL",
                "score": 0,
                "security_rating": "Invalid",
                "username": "",
                "length": 0,
                "estimated_crack_time": "N/A",
                "entropy": 0,
                "has_uppercase": False,
                "has_lowercase": False,
                "has_digit": False,
                "has_special": False,
                "is_common": False,
                "sql_injection_detected": False,
                "nist_compliant": False,
                "owasp_compliant": False,
                "remarks": ["Username cannot be empty."],
                "recommendations": ["Enter a valid username."],
                "security_observation": ""
            }
        )

    result = audit_password(username, password)

    return render_template(
        "report.html",
        result=result
    )

# ---------------------------------------
# Run Application
# ---------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
