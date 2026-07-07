// ==========================================
// PASSWORD POLICY COMPLIANCE AUDITOR
// script.js
// ==========================================

const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");
const strengthBar = document.getElementById("strengthBar");
const strengthText = document.getElementById("strengthText");
const analyzeBtn = document.getElementById("analyzeBtn");

const lengthCheck = document.getElementById("lengthCheck");
const upperCheck = document.getElementById("upperCheck");
const lowerCheck = document.getElementById("lowerCheck");
const digitCheck = document.getElementById("digitCheck");
const specialCheck = document.getElementById("specialCheck");

// ==========================================
// PASSWORD SHOW / HIDE
// ==========================================

if (togglePassword) {

    togglePassword.addEventListener("click", function () {

        if (passwordInput.type === "password") {

            passwordInput.type = "text";
            togglePassword.innerHTML =
                '<i class="fa-solid fa-eye-slash"></i>';

        } else {

            passwordInput.type = "password";
            togglePassword.innerHTML =
                '<i class="fa-solid fa-eye"></i>';

        }

    });

}

// ==========================================
// UPDATE CHECKLIST
// ==========================================

function updateCheck(element, status, text) {

    if (!element) return;

    if (status) {

        element.innerHTML = "✅ " + text;
        element.style.color = "#22C55E";

    } else {

        element.innerHTML = "❌ " + text;
        element.style.color = "#EF4444";

    }

}

// ==========================================
// PASSWORD STRENGTH
// ==========================================

if (passwordInput) {

    passwordInput.addEventListener("input", function () {

        const password = passwordInput.value.trim();

        let score = 0;

        const hasLength = password.length >= 8;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasDigit = /\d/.test(password);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>_\-+=/\\[\]]/.test(password);

        updateCheck(lengthCheck, hasLength, "Minimum 8 Characters");
        updateCheck(upperCheck, hasUpper, "Uppercase Letter");
        updateCheck(lowerCheck, hasLower, "Lowercase Letter");
        updateCheck(digitCheck, hasDigit, "Numeric Digit");
        updateCheck(specialCheck, hasSpecial, "Special Character");

        if (hasLength) score += 20;
        if (hasUpper) score += 20;
        if (hasLower) score += 20;
        if (hasDigit) score += 20;
        if (hasSpecial) score += 20;

        strengthBar.style.width = score + "%";

        if (score <= 20) {

            strengthBar.style.background = "#EF4444";
            strengthText.innerHTML = "Weak Password";
            strengthText.style.color = "#EF4444";

        } else if (score <= 40) {

            strengthBar.style.background = "#F97316";
            strengthText.innerHTML = "Fair Password";
            strengthText.style.color = "#F97316";

        } else if (score <= 60) {

            strengthBar.style.background = "#FACC15";
            strengthText.innerHTML = "Moderate Password";
            strengthText.style.color = "#FACC15";

        } else if (score <= 80) {

            strengthBar.style.background = "#3B82F6";
            strengthText.innerHTML = "Strong Password";
            strengthText.style.color = "#3B82F6";

        } else {

            strengthBar.style.background = "#22C55E";
            strengthText.innerHTML = "Excellent Password";
            strengthText.style.color = "#22C55E";

        }

    });

}

// ==========================================
// BUTTON LOADING
// ==========================================

const form = document.getElementById("auditForm");

if (form && analyzeBtn) {

    form.addEventListener("submit", function () {

        analyzeBtn.disabled = true;

        analyzeBtn.innerHTML =
            '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...';

    });

}

// ==========================================
// CARD HOVER
// ==========================================

document.querySelectorAll(".card,.feature-card").forEach(function(card){

    card.addEventListener("mouseenter",function(){

        card.style.transform="translateY(-8px) scale(1.02)";

    });

    card.addEventListener("mouseleave",function(){

        card.style.transform="translateY(0px) scale(1)";

    });

});

// ==========================================
// SCORE ANIMATION
// ==========================================

const scoreNumber = document.querySelector(".score-number");

if (scoreNumber) {

    const finalScore = parseInt(scoreNumber.textContent);

    if (!isNaN(finalScore)) {

        let current = 0;

        const timer = setInterval(function () {

            current++;

            scoreNumber.innerHTML = current + "/100";

            if (current >= finalScore) {

                clearInterval(timer);

            }

        }, 15);

    }

}

// ==========================================
// FADE IN
// ==========================================

window.addEventListener("load", function () {

    document.body.style.opacity = "1";

});

// ==========================================
// END
// ==========================================