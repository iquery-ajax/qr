// ===== Global Variables =====
let currentSecret = '';
let timerInterval = null;

// ===== Mobile Menu =====
function toggleMobileMenu() {
    const menu = document.getElementById('mobileMenu');
    menu.classList.toggle('active');
}

// ===== Tabs =====
function initializeTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            // Use closest to handle clicks on text inside button
            const clickedTab = e.currentTarget;
            const tabName = clickedTab.dataset.tab;
            if (!tabName) return;

            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            clickedTab.classList.add('active');
            const targetContent = document.getElementById(tabName + '-tab');
            if (targetContent) {
                targetContent.classList.add('active');
            }
        });
    });
}

// Initialize tabs when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeTabs);
} else {
    initializeTabs();
}

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
        const response = await fetch(`/api?action=getcode`, {
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

// ===== Google Authenticator Migration Decoder =====

// Base64 decode with URL safety
function base64DecodeUrl(str) {
    // Add padding if needed
    while (str.length % 4) {
        str += '=';
    }
    // Replace URL-safe characters
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// Base32 encode for secrets
function base32Encode(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let result = '';
    let bits = 0;
    let value = 0;
    
    for (let i = 0; i < bytes.length; i++) {
        value = (value << 8) | bytes[i];
        bits += 8;
        
        while (bits >= 5) {
            result += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    
    if (bits > 0) {
        result += alphabet[(value << (5 - bits)) & 31];
    }
    
    return result;
}

// Read varint from protobuf
function readVarint(data, offset) {
    let result = 0;
    let shift = 0;
    
    while (offset < data.length) {
        const byte = data[offset++];
        result |= (byte & 0x7F) << shift;
        
        if ((byte & 0x80) === 0) {
            break;
        }
        shift += 7;
    }
    
    return { value: result, offset };
}

// Read length-delimited field from protobuf
function readLengthDelimited(data, offset) {
    const lengthResult = readVarint(data, offset);
    const length = lengthResult.value;
    offset = lengthResult.offset;
    
    return {
        data: data.slice(offset, offset + length),
        offset: offset + length
    };
}

// Parse OTP parameters from protobuf
function parseOtpParameters(data) {
    let offset = 0;
    const otp = {
        secret: new Uint8Array(),
        name: '',
        issuer: '',
        algorithm: 1, // SHA1
        digits: 1,    // 6 digits
        type: 2       // TOTP
    };
    
    while (offset < data.length) {
        const tagResult = readVarint(data, offset);
        const tag = tagResult.value;
        offset = tagResult.offset;
        
        const fieldNumber = tag >>> 3;
        const wireType = tag & 0x7;
        
        if (fieldNumber === 1 && wireType === 2) { // secret
            const result = readLengthDelimited(data, offset);
            otp.secret = result.data;
            offset = result.offset;
        } else if (fieldNumber === 2 && wireType === 2) { // name
            const result = readLengthDelimited(data, offset);
            otp.name = new TextDecoder().decode(result.data);
            offset = result.offset;
        } else if (fieldNumber === 3 && wireType === 2) { // issuer
            const result = readLengthDelimited(data, offset);
            otp.issuer = new TextDecoder().decode(result.data);
            offset = result.offset;
        } else if (fieldNumber === 4 && wireType === 0) { // algorithm
            const result = readVarint(data, offset);
            otp.algorithm = result.value;
            offset = result.offset;
        } else if (fieldNumber === 5 && wireType === 0) { // digits
            const result = readVarint(data, offset);
            otp.digits = result.value;
            offset = result.offset;
        } else if (fieldNumber === 6 && wireType === 0) { // type
            const result = readVarint(data, offset);
            otp.type = result.value;
            offset = result.offset;
        } else {
            // Skip unknown fields
            if (wireType === 0) {
                const result = readVarint(data, offset);
                offset = result.offset;
            } else if (wireType === 2) {
                const result = readLengthDelimited(data, offset);
                offset = result.offset;
            } else {
                break;
            }
        }
    }
    
    return otp;
}

// Parse migration payload
function parseMigrationPayload(data) {
    let offset = 0;
    const otpParameters = [];
    
    while (offset < data.length) {
        const tagResult = readVarint(data, offset);
        const tag = tagResult.value;
        offset = tagResult.offset;
        
        const fieldNumber = tag >>> 3;
        const wireType = tag & 0x7;
        
        if (fieldNumber === 1 && wireType === 2) { // otp_parameters
            const result = readLengthDelimited(data, offset);
            const otpParams = parseOtpParameters(result.data);
            otpParameters.push(otpParams);
            offset = result.offset;
        } else {
            // Skip other fields
            if (wireType === 0) {
                const result = readVarint(data, offset);
                offset = result.offset;
            } else if (wireType === 2) {
                const result = readLengthDelimited(data, offset);
                offset = result.offset;
            } else {
                break;
            }
        }
    }
    
    return otpParameters;
}

// Build otpauth URL from OTP parameters
function buildOtpAuthUrl(otp) {
    const algorithms = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512', 4: 'MD5' };
    const digitsMap = { 1: '6', 2: '8' };
    const types = { 1: 'hotp', 2: 'totp' };
    
    const otpType = types[otp.type] || 'totp';
    const algorithm = algorithms[otp.algorithm] || 'SHA1';
    const digits = digitsMap[otp.digits] || '6';
    
    const secretB32 = base32Encode(otp.secret);
    const name = encodeURIComponent(otp.name);
    
    const params = [`secret=${secretB32}`];
    
    if (otp.issuer) {
        params.push(`issuer=${encodeURIComponent(otp.issuer)}`);
    }
    if (algorithm !== 'SHA1') {
        params.push(`algorithm=${algorithm}`);
    }
    if (digits !== '6') {
        params.push(`digits=${digits}`);
    }
    
    return `otpauth://${otpType}/${name}?${params.join('&')}`;
}

// Decode migration data
function decodeMigrationData(dataB64) {
    try {
        // Decode URL component if needed
        dataB64 = decodeURIComponent(dataB64);
        
        // Decode base64
        const data = base64DecodeUrl(dataB64);
        
        // Parse protobuf
        const otpParameters = parseMigrationPayload(data);
        
        // Build URLs and extract secrets
        return otpParameters.map(otp => ({
            url: buildOtpAuthUrl(otp),
            secret: base32Encode(otp.secret),
            name: otp.name,
            issuer: otp.issuer,
            algorithm: otp.algorithm,
            digits: otp.digits,
            type: otp.type
        }));
    } catch (error) {
        console.error('Migration decode error:', error);
        throw new Error('Failed to decode migration data');
    }
}

// ===== Migration UI Handlers =====

// Migration upload area
const migrationUploadArea = document.getElementById('migrationUploadArea');
const migrationFileInput = document.getElementById('migrationFileInput');

if (migrationUploadArea) {
    migrationUploadArea.addEventListener('click', () => migrationFileInput.click());
    
    migrationUploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        migrationUploadArea.classList.add('dragover');
    });
    
    migrationUploadArea.addEventListener('dragleave', () => {
        migrationUploadArea.classList.remove('dragover');
    });
    
    migrationUploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        migrationUploadArea.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) {
            handleMigrationQRFile(file);
        }
    });
    
    migrationFileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            handleMigrationQRFile(file);
        }
    });
}

// Handle migration QR file
function handleMigrationQRFile(file) {
    const reader = new FileReader();
    reader.onload = async (e) => {
        const imageData = e.target.result;
        await decodeMigrationQRAndProcess(imageData);
    };
    reader.readAsDataURL(file);
}

// Decode migration QR and process
async function decodeMigrationQRAndProcess(imageData) {
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
        
        if (code && code.data.startsWith('otpauth-migration://')) {
            await processMigrationUrl(code.data);
        } else {
            showToast('Not a valid Google Authenticator export QR code', 'error');
        }
    } catch (error) {
        console.error('Migration QR decode error:', error);
        showToast('Error decoding migration QR code', 'error');
    }
}

// Process migration data (from URL or QR)
async function processMigrationData() {
    const urlInput = document.getElementById('migrationUrlInput');
    const url = urlInput.value.trim();
    
    if (!url) {
        showToast('Please paste a migration URL or upload a QR code', 'error');
        return;
    }
    
    await processMigrationUrl(url);
}

// Process migration URL
async function processMigrationUrl(url) {
    try {
        if (!url.startsWith('otpauth-migration://')) {
            showToast('Invalid migration URL format', 'error');
            return;
        }
        
        // Extract data parameter
        const urlObj = new URL(url);
        const dataParam = urlObj.searchParams.get('data');
        
        if (!dataParam) {
            showToast('No data found in migration URL', 'error');
            return;
        }
        
        // Decode migration data
        const accounts = decodeMigrationData(dataParam);
        
        if (accounts.length === 0) {
            showToast('No accounts found in migration data', 'error');
            return;
        }
        
        // Show results
        await showMigrationResults(accounts);
        showToast(`Successfully extracted ${accounts.length} account(s)!`, 'success');
        
    } catch (error) {
        console.error('Migration processing error:', error);
        showToast('Failed to process migration data', 'error');
    }
}

// Show migration results
async function showMigrationResults(accounts) {
    const migrationResults = document.getElementById('migrationResults');
    const accountsCount = document.getElementById('accountsCount');
    const accountsList = document.getElementById('accountsList');
    
    // Update count
    accountsCount.textContent = `${accounts.length} account${accounts.length > 1 ? 's' : ''} found`;
    
    // Clear previous results
    accountsList.innerHTML = '';
    
    // Create account cards
    for (let i = 0; i < accounts.length; i++) {
        const account = accounts[i];
        const code = await generateTOTP(account.secret);
        
        const accountCard = document.createElement('div');
        accountCard.className = 'account-card';
        accountCard.innerHTML = `
            <div class="account-header">
                <div class="account-info">
                    <h4>${account.name || 'Unknown Account'}</h4>
                    ${account.issuer ? `<p class="issuer">${account.issuer}</p>` : ''}
                </div>
            </div>
            <div class="account-code" id="accountCode${i}">${code || '------'}</div>
            <div class="account-secret">${formatSecret(account.secret)}</div>
            <div class="account-actions">
                <button class="btn btn-secondary" onclick="copyAccountCode(${i})">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                    </svg>
                    Copy Code
                </button>
                <button class="btn btn-secondary" onclick="copyAccountSecret('${account.secret}')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
                    </svg>
                    Copy Secret
                </button>
                <button class="btn btn-primary" onclick="useAccountSecret('${account.secret}', '${account.issuer}', '${account.name}')">
                    Use This
                </button>
            </div>
        `;
        
        accountsList.appendChild(accountCard);
    }
    
    // Show results area
    migrationResults.style.display = 'block';
    
    // Start timers for all accounts
    startMigrationTimers(accounts);
    
    // Scroll to results
    migrationResults.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// Start timers for migration accounts
function startMigrationTimers(accounts) {
    // Clear existing migration timer
    if (window.migrationTimerInterval) {
        clearInterval(window.migrationTimerInterval);
    }
    
    async function updateMigrationCodes() {
        const remaining = getRemainingSeconds();
        
        // Regenerate codes when timer resets
        if (remaining === 30) {
            for (let i = 0; i < accounts.length; i++) {
                const account = accounts[i];
                const code = await generateTOTP(account.secret);
                const codeElement = document.getElementById(`accountCode${i}`);
                if (codeElement && code) {
                    codeElement.textContent = code;
                }
            }
        }
    }
    
    updateMigrationCodes();
    window.migrationTimerInterval = setInterval(updateMigrationCodes, 1000);
}

// Copy account code
function copyAccountCode(index) {
    const codeElement = document.getElementById(`accountCode${index}`);
    if (codeElement && codeElement.textContent !== '------') {
        navigator.clipboard.writeText(codeElement.textContent);
        showToast('Code copied!', 'success');
    }
}

// Copy account secret
function copyAccountSecret(secret) {
    navigator.clipboard.writeText(secret);
    showToast('Secret copied!', 'success');
}

// Use account secret in main generator
async function useAccountSecret(secret, issuer, name) {
    // Switch to secret tab
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    document.querySelector('[data-tab="secret"]').classList.add('active');
    document.getElementById('secret-tab').classList.add('active');
    
    // Fill secret input
    document.getElementById('secretInput').value = secret;
    
    // Generate and show result
    currentSecret = secret;
    await showResult(secret, issuer, name);
    
    showToast('Account loaded in generator!', 'success');
}
// ===== ENHANCED UI INTERACTIONS =====

// Add loading states
function setLoadingState(element, isLoading) {
    if (isLoading) {
        element.classList.add('loading');
        element.disabled = true;
        const originalText = element.innerHTML;
        element.dataset.originalText = originalText;
        element.innerHTML = `
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="animate-spin">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            <span>Loading...</span>
        `;
    } else {
        element.classList.remove('loading');
        element.disabled = false;
        if (element.dataset.originalText) {
            element.innerHTML = element.dataset.originalText;
        }
    }
}

// Enhanced toast with better positioning and stacking
let toastCount = 0;
function showToast(message, type = 'info', duration = 3000) {
    // Remove existing toasts of same type
    document.querySelectorAll(`.toast.${type}`).forEach(toast => toast.remove());
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    // Position based on toast count
    toast.style.top = `${24 + (toastCount * 60)}px`;
    toastCount++;
    
    document.body.appendChild(toast);
    
    // Auto remove
    setTimeout(() => {
        toast.remove();
        toastCount = Math.max(0, toastCount - 1);
    }, duration);
    
    // Click to dismiss
    toast.addEventListener('click', () => {
        toast.remove();
        toastCount = Math.max(0, toastCount - 1);
    });
}

// Add ripple effect to buttons
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('btn')) {
        const button = e.target;
        const rect = button.getBoundingClientRect();
        const ripple = document.createElement('span');
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            transform: scale(0);
            animation: ripple 0.6s linear;
            pointer-events: none;
        `;
        
        button.appendChild(ripple);
        
        setTimeout(() => ripple.remove(), 600);
    }
});

// Add CSS for ripple animation
const style = document.createElement('style');
style.textContent = `
    @keyframes ripple {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
    
    @keyframes animate-spin {
        from {
            transform: rotate(0deg);
        }
        to {
            transform: rotate(360deg);
        }
    }
    
    .animate-spin {
        animation: animate-spin 1s linear infinite;
    }
`;
document.head.appendChild(style);

// Enhanced form validation
function validateInput(input, rules = {}) {
    const value = input.value.trim();
    let isValid = true;
    let message = '';
    
    if (rules.required && !value) {
        isValid = false;
        message = 'This field is required';
    } else if (rules.minLength && value.length < rules.minLength) {
        isValid = false;
        message = `Minimum ${rules.minLength} characters required`;
    } else if (rules.pattern && !rules.pattern.test(value)) {
        isValid = false;
        message = rules.message || 'Invalid format';
    }
    
    // Update UI
    const inputGroup = input.closest('.input-group');
    const existingError = inputGroup.querySelector('.error-message');
    
    if (existingError) {
        existingError.remove();
    }
    
    if (!isValid) {
        input.style.borderColor = 'var(--error)';
        const errorEl = document.createElement('div');
        errorEl.className = 'error-message';
        errorEl.style.cssText = `
            color: var(--error);
            font-size: var(--text-xs);
            margin-top: var(--space-xs);
        `;
        errorEl.textContent = message;
        inputGroup.appendChild(errorEl);
    } else {
        input.style.borderColor = '';
    }
    
    return isValid;
}

// Auto-save functionality for inputs
function setupAutoSave() {
    const inputs = document.querySelectorAll('input[type="text"], textarea');
    
    inputs.forEach(input => {
        const key = `miro_${input.id}`;
        
        // Load saved value
        const saved = localStorage.getItem(key);
        if (saved && !input.value) {
            input.value = saved;
        }
        
        // Save on change
        input.addEventListener('input', debounce(() => {
            if (input.value.trim()) {
                localStorage.setItem(key, input.value);
            } else {
                localStorage.removeItem(key);
            }
        }, 500));
    });
}

// Debounce utility
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Initialize enhanced features
document.addEventListener('DOMContentLoaded', () => {
    setupAutoSave();
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + Enter to generate
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            const activeTab = document.querySelector('.tab.active');
            if (activeTab) {
                const tabName = activeTab.dataset.tab;
                switch (tabName) {
                    case 'secret':
                        generateFromSecret();
                        break;
                    case 'qrcode':
                        generateFromQR();
                        break;
                    case 'migration':
                        processMigrationData();
                        break;
                    case 'base64':
                        generateFromBase64();
                        break;
                }
            }
        }
        
        // Escape to clear results
        if (e.key === 'Escape') {
            const resultArea = document.getElementById('resultArea');
            const migrationResults = document.getElementById('migrationResults');
            if (resultArea.classList.contains('active')) {
                resultArea.classList.remove('active');
            }
            if (migrationResults.style.display !== 'none') {
                migrationResults.style.display = 'none';
            }
        }
    });
});

// Enhanced error handling
window.addEventListener('error', (e) => {
    console.error('Application error:', e.error);
    showToast('An unexpected error occurred. Please try again.', 'error');
});

// Performance monitoring
if ('performance' in window) {
    window.addEventListener('load', () => {
        setTimeout(() => {
            const perfData = performance.getEntriesByType('navigation')[0];
            console.log('Page load time:', perfData.loadEventEnd - perfData.loadEventStart, 'ms');
        }, 0);
    });
}
// ===== ENHANCED UI INTERACTIONS =====

// Add keyboard navigation for tabs
document.addEventListener('keydown', (e) => {
    if (e.target.classList.contains('tab')) {
        const tabs = Array.from(document.querySelectorAll('.tab'));
        const currentIndex = tabs.indexOf(e.target);
        
        let nextIndex = currentIndex;
        
        switch (e.key) {
            case 'ArrowLeft':
                nextIndex = currentIndex > 0 ? currentIndex - 1 : tabs.length - 1;
                break;
            case 'ArrowRight':
                nextIndex = currentIndex < tabs.length - 1 ? currentIndex + 1 : 0;
                break;
            case 'Home':
                nextIndex = 0;
                break;
            case 'End':
                nextIndex = tabs.length - 1;
                break;
            default:
                return;
        }
        
        e.preventDefault();
        tabs[nextIndex].focus();
        tabs[nextIndex].click();
    }
});

// Add progress indicator for multi-step processes
function showProgress(steps, currentStep) {
    const progressHtml = `
        <div class="progress-indicator">
            ${steps.map((step, index) => `
                <div class="progress-step ${index < currentStep ? 'completed' : ''} ${index === currentStep ? 'active' : ''}">
                    <div class="step-number">${index + 1}</div>
                    <div class="step-label">${step}</div>
                </div>
            `).join('')}
        </div>
    `;
    
    // Add to current tab content
    const activeTab = document.querySelector('.tab-content.active');
    const existingProgress = activeTab.querySelector('.progress-indicator');
    
    if (existingProgress) {
        existingProgress.remove();
    }
    
    activeTab.insertAdjacentHTML('afterbegin', progressHtml);
}

// Enhanced validation with visual feedback
function validateInputWithFeedback(input, rules = {}) {
    const isValid = validateInput(input, rules);
    const inputGroup = input.closest('.input-group');
    
    // Add visual feedback
    if (isValid) {
        inputGroup.classList.add('valid');
        inputGroup.classList.remove('invalid');
    } else {
        inputGroup.classList.add('invalid');
        inputGroup.classList.remove('valid');
    }
    
    return isValid;
}

// Add CSS for validation states
const validationStyle = document.createElement('style');
validationStyle.textContent = `
    .input-group.valid input,
    .input-group.valid textarea {
        border-color: var(--success);
        box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
    }
    
    .input-group.invalid input,
    .input-group.invalid textarea {
        border-color: var(--error);
        box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1);
    }
    
    .progress-indicator {
        display: flex;
        justify-content: space-between;
        margin-bottom: var(--space-xl);
        padding: var(--space-lg);
        background: var(--bg-card);
        border-radius: var(--radius-md);
        border: 1px solid var(--border-primary);
    }
    
    .progress-step {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: var(--space-xs);
        flex: 1;
        position: relative;
    }
    
    .progress-step:not(:last-child)::after {
        content: '';
        position: absolute;
        top: 15px;
        left: calc(50% + 20px);
        right: calc(-50% + 20px);
        height: 2px;
        background: var(--border-primary);
        z-index: 1;
    }
    
    .progress-step.completed::after {
        background: var(--success);
    }
    
    .step-number {
        width: 30px;
        height: 30px;
        border-radius: 50%;
        background: var(--bg-secondary);
        border: 2px solid var(--border-primary);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: var(--text-sm);
        font-weight: var(--font-semibold);
        color: var(--text-secondary);
        z-index: 2;
        position: relative;
    }
    
    .progress-step.active .step-number {
        background: var(--accent-primary);
        border-color: var(--accent-primary);
        color: white;
    }
    
    .progress-step.completed .step-number {
        background: var(--success);
        border-color: var(--success);
        color: white;
    }
    
    .step-label {
        font-size: var(--text-xs);
        color: var(--text-muted);
        text-align: center;
    }
    
    .progress-step.active .step-label {
        color: var(--text-primary);
        font-weight: var(--font-medium);
    }
    
    @media (max-width: 768px) {
        .progress-indicator {
            flex-direction: column;
            gap: var(--space-md);
        }
        
        .progress-step {
            flex-direction: row;
            justify-content: flex-start;
            text-align: left;
        }
        
        .progress-step::after {
            display: none;
        }
    }
`;
document.head.appendChild(validationStyle);
// ===== TAB SYSTEM DEBUG & FIXES =====

// Re-initialize tabs after any dynamic content changes
function reinitializeTabs() {
    console.log('Reinitializing tabs...');
    
    // Remove existing event listeners by cloning elements
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        const newTab = tab.cloneNode(true);
        tab.parentNode.replaceChild(newTab, tab);
    });
    
    // Add fresh event listeners
    initializeTabs();
}

// Tab switching handled by initializeTabs() above

// Keyboard navigation for tabs
document.addEventListener('keydown', function(e) {
    if (e.target.classList.contains('tab')) {
        const tabs = Array.from(document.querySelectorAll('.tab'));
        const currentIndex = tabs.indexOf(e.target);
        let nextIndex = currentIndex;
        
        switch (e.key) {
            case 'ArrowLeft':
                nextIndex = currentIndex > 0 ? currentIndex - 1 : tabs.length - 1;
                break;
            case 'ArrowRight':
                nextIndex = currentIndex < tabs.length - 1 ? currentIndex + 1 : 0;
                break;
            case 'Home':
                nextIndex = 0;
                break;
            case 'End':
                nextIndex = tabs.length - 1;
                break;
            case 'Enter':
            case ' ':
                e.target.click();
                return;
            default:
                return;
        }
        
        e.preventDefault();
        tabs[nextIndex].focus();
        tabs[nextIndex].click();
    }
});

// Ensure tabs are accessible
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.tab').forEach((tab, index) => {
        // Add ARIA attributes
        tab.setAttribute('role', 'tab');
        tab.setAttribute('tabindex', index === 0 ? '0' : '-1');
        tab.setAttribute('aria-selected', index === 0 ? 'true' : 'false');
        
        // Add keyboard focus styles
        tab.addEventListener('focus', function() {
            this.style.outline = '2px solid var(--accent-primary)';
            this.style.outlineOffset = '2px';
        });
        
        tab.addEventListener('blur', function() {
            this.style.outline = 'none';
        });
    });
    
    // Add ARIA attributes to tab content
    document.querySelectorAll('.tab-content').forEach((content, index) => {
        content.setAttribute('role', 'tabpanel');
        content.setAttribute('aria-hidden', index === 0 ? 'false' : 'true');
    });
});

// Debug function to check tab state
function debugTabs() {
    console.log('=== TAB DEBUG INFO ===');
    
    const tabs = document.querySelectorAll('.tab');
    const contents = document.querySelectorAll('.tab-content');
    
    console.log('Tabs found:', tabs.length);
    console.log('Tab contents found:', contents.length);
    
    tabs.forEach((tab, i) => {
        console.log(`Tab ${i}:`, {
            text: tab.textContent.trim(),
            dataTab: tab.dataset.tab,
            isActive: tab.classList.contains('active'),
            hasClickListener: tab.onclick !== null
        });
    });
    
    contents.forEach((content, i) => {
        console.log(`Content ${i}:`, {
            id: content.id,
            isActive: content.classList.contains('active'),
            display: getComputedStyle(content).display
        });
    });
}

// Call debug function in console if needed
window.debugTabs = debugTabs;