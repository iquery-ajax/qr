// ===== Global Variables =====
let currentSecret = '';
let timerInterval = null;

// ===== Mobile Menu =====
function toggleMobileMenu() {
    const menu = document.getElementById('mobileMenu');
    menu.classList.toggle('active');
}

// ===== Tabs =====
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        // Remove active from all tabs
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        // Add active to clicked tab
        tab.classList.add('active');
        const tabId = tab.dataset.tab + '-tab';
        document.getElementById(tabId).classList.add('active');
    });
});

// ===== File Upload =====
const uploadArea = document.getElementById('uploadArea');
const qrFileInput = document.getElementById('qrFileInput');

if (uploadArea) {
    uploadArea.addEventListener('click', () => qrFileInput.click());
    
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) {
            handleQRFile(file);
        }
    });
    
    qrFileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            handleQRFile(file);
        }
    });
}

// ===== TOTP Generation (Client-side) =====
function base32Decode(encoded) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let result = [];
    
    encoded = encoded.replace(/\s/g, '').toUpperCase().replace(/=+$/, '');
    
    for (let char of encoded) {
        const val = alphabet.indexOf(char);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }
    
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        result.push(parseInt(bits.substr(i, 8), 2));
    }
    
    return new Uint8Array(result);
}

async function hmacSha1(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
    return new Uint8Array(signature);
}

async function generateTOTP(secret, timeStep = 30, digits = 6) {
    try {
        const key = base32Decode(secret);
        const time = Math.floor(Date.now() / 1000 / timeStep);
        
        const timeBuffer = new ArrayBuffer(8);
        const timeView = new DataView(timeBuffer);
        timeView.setUint32(4, time, false);
        
        const hmac = await hmacSha1(key, new Uint8Array(timeBuffer));
        const offset = hmac[hmac.length - 1] & 0x0f;
        
        const code = (
            ((hmac[offset] & 0x7f) << 24) |
            ((hmac[offset + 1] & 0xff) << 16) |
            ((hmac[offset + 2] & 0xff) << 8) |
            (hmac[offset + 3] & 0xff)
        ) % Math.pow(10, digits);
        
        return code.toString().padStart(digits, '0');
    } catch (error) {
        console.error('TOTP generation error:', error);
        return null;
    }
}

function getRemainingSeconds() {
    return 30 - (Math.floor(Date.now() / 1000) % 30);
}

// ===== Generate from Secret =====
async function generateFromSecret() {
    const secretInput = document.getElementById('secretInput');
    const secret = secretInput.value.trim().replace(/\s/g, '');
    
    if (!secret) {
        showToast('Please enter a secret key', 'error');
        return;
    }
    
    currentSecret = secret;
    await showResult(secret);
}

// ===== Generate from QR Code =====
function handleQRFile(file) {
    const reader = new FileReader();
    reader.onload = async (e) => {
        const imageData = e.target.result;
        await decodeQRAndGenerate(imageData);
    };
    reader.readAsDataURL(file);
}

async function generateFromQR() {
    const file = qrFileInput.files[0];
    if (!file) {
        showToast('Please select a QR code image', 'error');
        return;
    }
    handleQRFile(file);
}

async function generateFromBase64() {
    const base64Input = document.getElementById('base64Input');
    const base64 = base64Input.value.trim();
    
    if (!base64) {
        showToast('Please paste a base64 image', 'error');
        return;
    }
    
    await decodeQRAndGenerate(base64);
}

async function decodeQRAndGenerate(imageData) {
    try {
        const img = new Image();
        img.src = imageData;
        
        await new Promise((resolve, reject) => {
            img.onload = resolve;
            img.onerror = reject;
        });
        
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        
        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imgData.data, imgData.width, imgData.height);
        
        if (code) {
            const otpData = parseOtpAuthUrl(code.data);
            if (otpData && otpData.secret) {
                currentSecret = otpData.secret;
                await showResult(otpData.secret, otpData.issuer, otpData.account);
            } else {
                showToast('Invalid QR code format', 'error');
            }
        } else {
            showToast('Could not decode QR code', 'error');
        }
    } catch (error) {
        console.error('QR decode error:', error);
        showToast('Error decoding QR code', 'error');
    }
}

function parseOtpAuthUrl(url) {
    try {
        if (!url.startsWith('otpauth://')) {
            return { secret: url };
        }
        
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.search);
        const pathParts = decodeURIComponent(urlObj.pathname).split(':');
        
        return {
            secret: params.get('secret'),
            issuer: params.get('issuer') || (pathParts[0] ? pathParts[0].replace('//', '').replace('/', '') : ''),
            account: pathParts[1] || ''
        };
    } catch (error) {
        return null;
    }
}


// ===== Show Result =====
async function showResult(secret, issuer = '', account = '') {
    const resultArea = document.getElementById('resultArea');
    const codeDisplay = document.getElementById('codeDisplay');
    const resultInfo = document.getElementById('resultInfo');
    
    // Generate code
    const code = await generateTOTP(secret);
    if (!code) {
        showToast('Invalid secret key', 'error');
        return;
    }
    
    // Show result area
    resultArea.classList.add('active');
    codeDisplay.textContent = code;
    
    // Show info
    let infoHtml = `<p><strong>Secret:</strong> ${formatSecret(secret)}</p>`;
    if (issuer) infoHtml += `<p><strong>Issuer:</strong> ${issuer}</p>`;
    if (account) infoHtml += `<p><strong>Account:</strong> ${account}</p>`;
    resultInfo.innerHTML = infoHtml;
    
    // Start timer
    startTimer(secret);
    
    // Scroll to result
    resultArea.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function formatSecret(secret) {
    return secret.match(/.{1,4}/g).join(' ');
}

function startTimer(secret) {
    // Clear existing timer
    if (timerInterval) {
        clearInterval(timerInterval);
    }
    
    const timerCircle = document.getElementById('timerCircle');
    const timerText = document.getElementById('timerText');
    const codeDisplay = document.getElementById('codeDisplay');
    
    async function updateTimer() {
        const remaining = getRemainingSeconds();
        const progress = (remaining / 30) * 113; // 113 is the circumference
        
        timerCircle.style.strokeDashoffset = 113 - progress;
        timerText.textContent = remaining;
        
        // Regenerate code when timer resets
        if (remaining === 30) {
            const code = await generateTOTP(secret);
            if (code) {
                codeDisplay.textContent = code;
            }
        }
    }
    
    updateTimer();
    timerInterval = setInterval(updateTimer, 1000);
}

// ===== Copy Functions =====
function copyCode() {
    const code = document.getElementById('codeDisplay').textContent;
    if (code && code !== '------') {
        navigator.clipboard.writeText(code);
        showToast('Code copied!', 'success');
    }
}

function copySecret() {
    if (currentSecret) {
        navigator.clipboard.writeText(currentSecret);
        showToast('Secret copied!', 'success');
    }
}

// ===== Toast Notification =====
function showToast(message, type = 'info') {
    // Remove existing toast
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

// ===== Try API =====
async function tryApi() {
    const secret = document.getElementById('tryApiSecret').value.trim();
    const resultEl = document.getElementById('tryApiResult');
    
    if (!secret) {
        resultEl.innerHTML = '<pre><code>// Please enter a secret key</code></pre>';
        return;
    }
    
    resultEl.innerHTML = '<pre><code>// Loading...</code></pre>';
    
    try {
        const response = await fetch(`https://qr.thsite.top/api.php?action=getcode`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ secret })
        });
        
        const data = await response.json();
        resultEl.innerHTML = `<pre><code>${JSON.stringify(data, null, 2)}</code></pre>`;
    } catch (error) {
        // Fallback to client-side generation
        const code = await generateTOTP(secret);
        const remaining = getRemainingSeconds();
        
        const result = {
            success: true,
            secret: secret,
            code: code,
            remaining: remaining,
            note: "Generated client-side (API not available)"
        };
        
        resultEl.innerHTML = `<pre><code>${JSON.stringify(result, null, 2)}</code></pre>`;
    }
}

// ===== Smooth Scroll for Navigation =====
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// ===== Navbar Background on Scroll =====
window.addEventListener('scroll', () => {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.style.background = 'rgba(10, 10, 15, 0.95)';
    } else {
        navbar.style.background = 'rgba(10, 10, 15, 0.8)';
    }
});
