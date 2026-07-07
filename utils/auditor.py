import sqlite3
import bcrypt
import re
import math

# ============================================================
# Password Policy Compliance Auditor
# utils/auditor.py
# ============================================================

DATABASE = "database/passwords.db"

# ============================================================
# Common Weak Patterns
# ============================================================

KEYBOARD_PATTERNS = [
    "qwerty",
    "asdf",
    "zxcv",
    "qwertyui",
    "asdfgh",
    "zxcvbn"
]

ALPHABET_PATTERNS = [
    "abcdef",
    "bcdefg",
    "cdefgh",
    "uvwxyz"
]

NUMBER_PATTERNS = [
    "123456",
    "12345",
    "1234",
    "987654",
    "98765",
    "654321"
]

SQLI_PATTERNS = [
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "union select",
    "drop table",
    "--",
    ";--",
    "/*",
    "*/",
    "xp_cmdshell",
    "information_schema",
    "sleep(",
    "benchmark("
]

# ============================================================
# Helper Functions
# ============================================================

def contains_repeated_characters(password):

    """
    Detects repeated characters like:
    aaaaaaaa
    11111111
    $$$$$$$$
    """

    return re.search(r"(.)\1{3,}", password) is not None


def contains_keyboard_pattern(password):

    password = password.lower()

    for pattern in KEYBOARD_PATTERNS:

        if pattern in password:
            return True

    return False


def contains_alphabet_pattern(password):

    password = password.lower()

    for pattern in ALPHABET_PATTERNS:

        if pattern in password:
            return True

    return False


def contains_number_pattern(password):

    for pattern in NUMBER_PATTERNS:

        if pattern in password:
            return True

    return False


def contains_username(username, password):

    if not username:
        return False

    return username.lower() in password.lower()


# ============================================================
# SQL Injection Recognition
# ============================================================

def detect_sql_payload(password):

    lower = password.lower()

    for payload in SQLI_PATTERNS:

        if payload in lower:
            return True

    return False


# ============================================================
# Password Entropy
# ============================================================

def calculate_entropy(password):

    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26

    if re.search(r"[A-Z]", password):
        charset += 26

    if re.search(r"\d", password):
        charset += 10

    if re.search(r"[^A-Za-z0-9]", password):
        charset += 33

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)

    return round(entropy, 2)


# ============================================================
# Crack Time Estimation
# ============================================================

def estimate_crack_time(entropy):

    if entropy < 28:
        return "Less than 1 second"

    elif entropy < 36:
        return "A few minutes"

    elif entropy < 50:
        return "Several hours"

    elif entropy < 60:
        return "Several days"

    elif entropy < 70:
        return "Several months"

    elif entropy < 80:
        return "Several years"

    elif entropy < 100:
        return "Centuries"

    else:
        return "Practically impossible with current technology"


# ============================================================
# Security Rating
# ============================================================

def security_rating(score):

    if score >= 90:
        return "Excellent"

    elif score >= 75:
        return "Strong"

    elif score >= 60:
        return "Moderate"

    elif score >= 40:
        return "Weak"

    else:
        return "Very Weak"


# ============================================================
# Compliance
# ============================================================

def check_nist(result):

    return (
        result["length"] >= 8
        and not result["is_common"]
    )


def check_owasp(result):

    return (

        result["length"] >= 12

        and result["has_uppercase"]

        and result["has_lowercase"]

        and result["has_digit"]

        and result["has_special"]

        and not result["is_common"]

    )


# ============================================================
# Common Password Check
# ============================================================

def is_common_password(password):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(

        "SELECT 1 FROM common_passwords WHERE password=?",

        (password,)

    )

    exists = cursor.fetchone() is not None

    connection.close()

    return exists

# ============================================================
# Save Audit Log
# ============================================================

def save_audit(result):

    try:

        connection = sqlite3.connect(DATABASE)

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO audit_logs
            (
                username,
                password_hash,
                password_length,
                has_uppercase,
                has_lowercase,
                has_digit,
                has_special,
                is_common,
                compliance_score,
                result,
                remarks,
                audit_time
            )

            VALUES
            (
                ?,?,?,?,?,?,?,?,?,?,?,datetime('now')
            )
            """,
            (
                result["username"],
                result["password_hash"],
                result["length"],
                int(result["has_uppercase"]),
                int(result["has_lowercase"]),
                int(result["has_digit"]),
                int(result["has_special"]),
                int(result["is_common"]),
                result["score"],
                result["result"],
                ", ".join(result["remarks"])
            )
        )

        connection.commit()

    except sqlite3.Error as e:

        print("Database Error :", e)

    finally:

        connection.close()


# ============================================================
# Main Password Audit
# ============================================================

def audit_password(username, password):

    username = username.strip()

    password = password.strip()

    result = {}

    result["username"] = username
    result["length"] = len(password)

    remarks = []
    recommendations = []

    score = 0

    # --------------------------------------------------------
    # Length
    # --------------------------------------------------------

    if len(password) >= 16:

        score += 25

    elif len(password) >= 12:

        score += 20

    elif len(password) >= 8:

        score += 15

    else:

        remarks.append("Password is shorter than the recommended minimum length.")

        recommendations.append(
            "Use a password of at least 12 characters."
        )

    # --------------------------------------------------------
    # Maximum Length
    # --------------------------------------------------------

    if len(password) > 128:

        remarks.append(
            "Password exceeds the supported maximum length."
        )

        recommendations.append(
            "Keep the password within 128 characters."
        )

    # --------------------------------------------------------
    # Uppercase
    # --------------------------------------------------------

    if re.search(r"[A-Z]", password):

        result["has_uppercase"] = True

        score += 10

    else:

        result["has_uppercase"] = False

        remarks.append("Uppercase letter missing.")

        recommendations.append(
            "Add at least one uppercase letter."
        )

    # --------------------------------------------------------
    # Lowercase
    # --------------------------------------------------------

    if re.search(r"[a-z]", password):

        result["has_lowercase"] = True

        score += 10

    else:

        result["has_lowercase"] = False

        remarks.append("Lowercase letter missing.")

        recommendations.append(
            "Add at least one lowercase letter."
        )

    # --------------------------------------------------------
    # Digit
    # --------------------------------------------------------

    if re.search(r"\d", password):

        result["has_digit"] = True

        score += 10

    else:

        result["has_digit"] = False

        remarks.append("Numeric digit missing.")

        recommendations.append(
            "Include at least one numeric digit."
        )

    # --------------------------------------------------------
    # Special Character
    # --------------------------------------------------------

    if re.search(r"[^A-Za-z0-9]", password):

        result["has_special"] = True

        score += 10

    else:

        result["has_special"] = False

        remarks.append("Special character missing.")

        recommendations.append(
            "Include at least one special character."
        )

    # --------------------------------------------------------
    # Common Password
    # --------------------------------------------------------

    result["is_common"] = is_common_password(password)

    if result["is_common"]:

        remarks.append(
            "Password exists in the common password database."
        )

        recommendations.append(
            "Choose a unique password that has not appeared in public breaches."
        )

    else:

        score += 15

    # --------------------------------------------------------
    # Username Detection
    # --------------------------------------------------------

    if contains_username(username, password):

        score -= 10

        remarks.append(
            "Password contains the username."
        )

        recommendations.append(
            "Avoid including your username in the password."
        )

    # --------------------------------------------------------
    # Repeated Characters
    # --------------------------------------------------------

    if contains_repeated_characters(password):

        score -= 10

        remarks.append(
            "Repeated character sequence detected."
        )

        recommendations.append(
            "Avoid repeated characters."
        )

    # --------------------------------------------------------
    # Number Sequence
    # --------------------------------------------------------

    if contains_number_pattern(password):

        score -= 10

        remarks.append(
            "Sequential numbers detected."
        )

        recommendations.append(
            "Avoid predictable numeric sequences."
        )

    # --------------------------------------------------------
    # Alphabet Sequence
    # --------------------------------------------------------

    if contains_alphabet_pattern(password):

        score -= 10

        remarks.append(
            "Alphabetical sequence detected."
        )

        recommendations.append(
            "Avoid alphabetical sequences."
        )

    # --------------------------------------------------------
    # Keyboard Pattern
    # --------------------------------------------------------

    if contains_keyboard_pattern(password):

        score -= 10

        remarks.append(
            "Keyboard pattern detected."
        )

        recommendations.append(
            "Avoid keyboard patterns like qwerty or asdf."
        )

    # --------------------------------------------------------
    # SQL Injection Detection
    # --------------------------------------------------------

    sql_detected = detect_sql_payload(password)

    result["sql_injection_detected"] = sql_detected

    if sql_detected:

        remarks.append(
            "SQL Injection style payload detected."
        )

        recommendations.append(
            "Use a normal password instead of SQL keywords or injection payloads."
        )

        result["security_observation"] = (
            "SQL Injection patterns were detected in the submitted password. "
            "Our password auditing system securely handled the input and the "
            "application remained protected. Better luck next time."
        )

        score -= 5

    else:

        result["security_observation"] = (
            "No SQL Injection indicators were detected."
        )

    # --------------------------------------------------------
    # Password Entropy
    # --------------------------------------------------------

    entropy = calculate_entropy(password)

    result["entropy"] = entropy

    result["estimated_crack_time"] = estimate_crack_time(entropy)

    if entropy >= 80:

        score += 10

    elif entropy >= 60:

        score += 5

    else:

        remarks.append(
            "Password entropy is relatively low."
        )

        recommendations.append(
            "Increase randomness by using unrelated words, numbers and symbols."
        )

    # --------------------------------------------------------
    # Score Normalization
    # --------------------------------------------------------

    if score < 0:
        score = 0

    if score > 100:
        score = 100

    result["score"] = score

    # --------------------------------------------------------
    # Security Rating
    # --------------------------------------------------------

    result["security_rating"] = security_rating(score)

    # --------------------------------------------------------
    # Compliance
    # --------------------------------------------------------

    result["nist_compliant"] = check_nist(result)

    result["owasp_compliant"] = check_owasp(result)

    # --------------------------------------------------------
    # Overall Result
    # --------------------------------------------------------

    if score >= 85:

        result["result"] = "PASS"

    elif score >= 60:

        result["result"] = "WARNING"

    else:

        result["result"] = "FAIL"

    # --------------------------------------------------------
    # Default Recommendation
    # --------------------------------------------------------

    if len(recommendations) == 0:

        recommendations.append(
            "Excellent password. Continue using unique passwords and enable Multi-Factor Authentication wherever possible."
        )

    # --------------------------------------------------------
    # bcrypt Hash
    # --------------------------------------------------------

    password_hash = bcrypt.hashpw(

        password.encode("utf-8"),

        bcrypt.gensalt()

    ).decode("utf-8")

    result["password_hash"] = password_hash

    # --------------------------------------------------------
    # Store Findings
    # --------------------------------------------------------

    result["remarks"] = remarks

    result["recommendations"] = recommendations

    # --------------------------------------------------------
    # Save Audit
    # --------------------------------------------------------

    save_audit(result)

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return result
