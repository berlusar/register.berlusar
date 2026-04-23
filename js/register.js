// ============================================
// LANGUAGE SYSTEM
// ============================================
let currentLang = localStorage.getItem('lang') || 'en';

function setLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('lang', lang);

    // Update buttons
    const langEN = document.getElementById('langEN');
    const langAR = document.getElementById('langAR');
    if (langEN) langEN.classList.toggle('active', lang === 'en');
    if (langAR) langAR.classList.toggle('active', lang === 'ar');

    // RTL support for Arabic
    document.body.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
    document.documentElement.setAttribute('lang', lang === 'ar' ? 'ar' : 'en');

    // Update all elements with data-lang attributes
    document.querySelectorAll('[data-lang-en]').forEach(el => {
        const text = el.getAttribute('data-lang-' + lang);
        if (text) el.innerHTML = text;
    });

    // Update placeholders
    document.querySelectorAll('[data-placeholder-en]').forEach(el => {
        const placeholder = el.getAttribute('data-placeholder-' + lang);
        if (placeholder) el.placeholder = placeholder;
    });
}

function showToast(title, message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'error') icon = 'exclamation-triangle';
    if (type === 'warning') icon = 'exclamation-circle';

    toast.innerHTML = `
      <i class="fas fa-${icon} toast-icon"></i>
      <div class="toast-content">
        <span class="toast-title">${title}</span>
        <span class="toast-message">${message}</span>
      </div>
    `;

    container.appendChild(toast);
    setTimeout(() => toast.classList.add('active'), 10);

    setTimeout(() => {
      toast.classList.remove('active');
      setTimeout(() => toast.remove(), 500);
    }, 5000);
}

// Initialize language on load
document.addEventListener('DOMContentLoaded', () => {
    setLanguage(currentLang);
});

// ============================================
// SECURE SESSION SYSTEM
// ============================================
let sessionData = null;
let captchaToken = null;

function checkTermsAccepted() {
    const accepted = localStorage.getItem('terms_accepted');
    const termsOverlay = document.getElementById('termsOverlay');
    const registerContainer = document.querySelector('.register-container');

    if (!accepted) {
        if (termsOverlay) termsOverlay.classList.remove('hidden');
        if (registerContainer) registerContainer.classList.add('form-blocked');
    } else {
        if (termsOverlay) termsOverlay.classList.add('hidden');
    }
}

function toggleAcceptButton() {
    const checkbox = document.getElementById('termsCheckbox');
    const btn = document.getElementById('btnAcceptTerms');
    if (btn && checkbox) btn.disabled = !checkbox.checked;
}

function acceptTerms() {
    localStorage.setItem('terms_accepted', 'true');
    const termsOverlay = document.getElementById('termsOverlay');
    const registerContainer = document.querySelector('.register-container');
    if (termsOverlay) termsOverlay.classList.add('hidden');
    if (registerContainer) registerContainer.classList.remove('form-blocked');
}

function declineTerms() {
    window.location.href = 'https://google.com';
}

function getFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('fp', 2, 2);
    const fp = canvas.toDataURL().slice(-50);
    const nav = navigator.userAgent + navigator.language + screen.width + screen.height + new Date().getTimezoneOffset();
    return CryptoJS.SHA256(fp + nav).toString().substring(0, 32);
}

function generateNonce() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

async function initSecureSession() {
    const loadingOverlay = document.getElementById('loadingOverlay');
    if (loadingOverlay) loadingOverlay.style.display = 'flex';

    try {
        const fp = getFingerprint();
        const response = await fetch('/api/session/init', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fingerprint: fp, action: 'register' })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.message || 'Failed to init session');
        }

        sessionData = await response.json();
        if (!sessionData.session_id || !sessionData.key) {
            throw new Error('Invalid session data');
        }
        console.log('Secure session initialized');
        showToast('Secure Connection', 'Session initialized successfully', 'success');
    } catch (error) {
        console.error('Session error:', error);
        const msg = currentLang === 'ar' ? 'خطأ في الجلسة. يرجى إعادة التحميل.' : 'Session error. ' + error.message;
        showToast('Security Error', error.message, 'error');
        const errorEl = document.getElementById('errorMessage');
        if (errorEl) {
            errorEl.textContent = msg;
            errorEl.style.display = 'block';
        }
        const submitBtn = document.getElementById('submitBtn');
        if (submitBtn) submitBtn.disabled = true;
    } finally {
        if (loadingOverlay) loadingOverlay.style.display = 'none';
    }
}

function encryptData(data) {
    if (!sessionData || !sessionData.key) {
        throw new Error('Session not initialized');
    }
    const nonce = generateNonce();
    const iv = CryptoJS.lib.WordArray.random(16);
    const key = CryptoJS.enc.Base64.parse(sessionData.key);
    const encrypted = CryptoJS.AES.encrypt(data, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return iv.toString(CryptoJS.enc.Base64) + ':' + encrypted.toString() + ':' + nonce;
}

function decryptResponse(encryptedData) {
    if (!sessionData || !sessionData.key) throw new Error('Session not initialized');
    const parts = encryptedData.split(':');
    if (parts.length < 2) throw new Error('Invalid response format');
    const iv = CryptoJS.enc.Base64.parse(parts[0]);
    const encrypted = CryptoJS.enc.Base64.parse(parts[1]);
    const key = CryptoJS.enc.Base64.parse(sessionData.key);
    const decrypted = CryptoJS.AES.decrypt({ ciphertext: encrypted }, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
}

function onCaptchaSuccess(token) {
    captchaToken = token;
    const submitBtn = document.getElementById('submitBtn');
    if (sessionData && submitBtn) submitBtn.disabled = false;
}

function onCaptchaExpired() {
    captchaToken = null;
    const submitBtn = document.getElementById('submitBtn');
    if (submitBtn) submitBtn.disabled = true;
}

const registerForm = document.getElementById('registerForm');
if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const captchaMsg = currentLang === 'ar' ? 'يرجى إكمال التحقق' : 'Complete the captcha';
        const sessionMsg = currentLang === 'ar' ? 'انتهت الجلسة. أعد التحميل.' : 'Session expired. Reload.';
        const passwordMsg = currentLang === 'ar' ? 'كلمتا المرور غير متطابقتين' : 'Passwords do not match';

        const errorEl = document.getElementById('errorMessage');

        if (!captchaToken) {
            showToast('Captcha Required', captchaMsg, 'warning');
            return;
        }
        if (!sessionData) {
            await initSecureSession();
            if (!sessionData) {
                showToast('Session Required', sessionMsg, 'error');
                return;
            }
        }

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const key = document.getElementById('key').value.trim();

        if (password !== confirmPassword) {
            if (errorEl) {
                errorEl.textContent = passwordMsg;
                errorEl.style.display = 'block';
            }
            return;
        }

        const submitBtn = document.getElementById('submitBtn');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.textContent = currentLang === 'ar' ? 'جارٍ التسجيل...' : 'Registering...';
        }

        try {
            const payload = JSON.stringify({
                username,
                password,
                key,
                captcha_token: captchaToken,
                timestamp: Date.now(),
                fingerprint: getFingerprint()
            });
            const encryptedPayload = encryptData(payload);

            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': sessionData.session_id
                },
                body: JSON.stringify({ payload: encryptedPayload })
            });

            const data = await response.json();

            let finalData = data;
            if (data.encrypted && data.payload) {
                try {
                    finalData = decryptResponse(data.payload);
                } catch (e) {
                    console.error("Decryption error:", e);
                    throw new Error("Response security failure");
                }
            }

            if (response.status === 429) {
                const msg = currentLang === 'ar' ? (finalData.message || 'محاولات كثيرة. انتظر.') : (finalData.message || 'Too many attempts. Wait.');
                if (errorEl) {
                    errorEl.textContent = msg;
                    errorEl.style.display = 'block';
                }
                if (submitBtn) submitBtn.style.display = 'none';
                const reloadHint = document.getElementById('reloadHint');
                if (reloadHint) reloadHint.style.display = 'block';
                return;
            }

            if (finalData.success) {
                const successMsg = currentLang === 'ar' ? 'تم إنشاء الحساب بنجاح!' : 'Account created successfully!';
                const successEl = document.getElementById('successMessage');
                if (successEl) {
                    const loginLink = currentLang === 'ar' ? 'سجل دخولك من هنا' : 'Login here';
                    successEl.innerHTML = `
                        ✅ ${successMsg}<br>
                        <strong>UID: ${finalData.uid}</strong><br>
                        <div style="margin-top:15px;">
                            <a href="https://login-berlusar.vercel.app" class="btn-register" style="text-decoration:none; display:inline-block; padding:10px 20px;">${loginLink}</a>
                        </div>
                    `;
                    successEl.style.display = 'block';
                }
                if (errorEl) errorEl.style.display = 'none';
                if (submitBtn) submitBtn.style.display = 'none';
                sessionData = null;
            } else {
                const errorMsg = currentLang === 'ar' ? (finalData.message || 'خطأ في التسجيل') : (finalData.message || 'Registration error');
                if (errorEl) {
                    errorEl.textContent = errorMsg;
                    errorEl.style.display = 'block';
                }
                if (submitBtn) submitBtn.style.display = 'none';
                const reloadHint = document.getElementById('reloadHint');
                if (reloadHint) reloadHint.style.display = 'block';
            }
        } catch (error) {
            console.error('Error:', error);
            const msg = currentLang === 'ar' ? 'خطأ في الاتصال' : 'Connection error';
            if (errorEl) {
                errorEl.textContent = msg;
                errorEl.style.display = 'block';
            }
            if (submitBtn) submitBtn.style.display = 'none';
            const reloadHint = document.getElementById('reloadHint');
            if (reloadHint) reloadHint.style.display = 'block';
        }
    });
}

window.addEventListener('load', () => {
    checkCookieConsent();
    checkTermsAccepted();
    initSecureSession();
});

function checkCookieConsent() {
    const consent = document.cookie.split('; ').find(c => c.startsWith('cookie_consent='));
    const cookieConsent = document.getElementById('cookieConsent');
    const registerForm = document.getElementById('registerForm');

    if (consent && consent.split('=')[1] === 'accepted') {
        if (cookieConsent) cookieConsent.classList.add('hidden');
        if (registerForm) registerForm.classList.remove('form-blocked');
    } else {
        if (registerForm) registerForm.classList.add('form-blocked');
    }
}

async function acceptCookies() {
    try {
        await fetch("/api/cookies/accept", { method: "POST" });
    } catch (e) { }

    localStorage.setItem("cookiesAccepted", "true");
    document.cookie = 'cookie_consent=accepted; path=/; max-age=' + (365 * 24 * 60 * 60) + '; SameSite=Strict';
    const cookieConsent = document.getElementById('cookieConsent');
    const registerForm = document.getElementById('registerForm');
    if (cookieConsent) cookieConsent.classList.add('hidden');
    if (registerForm) registerForm.classList.remove('form-blocked');
}
