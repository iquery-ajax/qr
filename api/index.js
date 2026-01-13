const https = require('https');
const http = require('http');
const { URL } = require('url');

// Base32 decode
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
    
    return Buffer.from(result);
}

// Generate TOTP
const crypto = require('crypto');

function generateTOTP(secret, timeStep = 30, digits = 6) {
    const key = base32Decode(secret);
    const time = Math.floor(Date.now() / 1000 / timeStep);
    
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeUInt32BE(0, 0);
    timeBuffer.writeUInt32BE(time, 4);
    
    const hmac = crypto.createHmac('sha1', key).update(timeBuffer).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    
    const code = (
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)
    ) % Math.pow(10, digits);
    
    return code.toString().padStart(digits, '0');
}

function getRemainingSeconds(timeStep = 30) {
    return timeStep - (Math.floor(Date.now() / 1000) % timeStep);
}

// Parse otpauth URL
function parseOtpAuthUrl(url) {
    if (!url.startsWith('otpauth://')) {
        return { secret: url };
    }
    
    try {
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.search);
        const path = decodeURIComponent(urlObj.pathname);
        const parts = path.split(':');
        
        return {
            secret: params.get('secret') || '',
            issuer: params.get('issuer') || (parts[0] ? parts[0].replace(/^\/+/, '') : ''),
            account: parts[1] || ''
        };
    } catch (e) {
        return { secret: url };
    }
}

// Decode QR using external API
async function decodeQR(imageData) {
    return new Promise((resolve, reject) => {
        // Remove data URL prefix if present
        let base64Data = imageData;
        if (imageData.includes('base64,')) {
            base64Data = imageData.split('base64,')[1];
        }
        
        const imageBuffer = Buffer.from(base64Data, 'base64');
        const boundary = '----FormBoundary' + Math.random().toString(36).substr(2);
        
        const bodyParts = [
            `--${boundary}\r\n`,
            'Content-Disposition: form-data; name="file"; filename="qrcode.png"\r\n',
            'Content-Type: image/png\r\n\r\n'
        ];
        
        const bodyEnd = `\r\n--${boundary}--\r\n`;
        const bodyStart = Buffer.from(bodyParts.join(''));
        const bodyEndBuf = Buffer.from(bodyEnd);
        const body = Buffer.concat([bodyStart, imageBuffer, bodyEndBuf]);
        
        const options = {
            hostname: 'api.qrserver.com',
            path: '/v1/read-qr-code/',
            method: 'POST',
            headers: {
                'Content-Type': `multipart/form-data; boundary=${boundary}`,
                'Content-Length': body.length
            }
        };
        
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const result = JSON.parse(data);
                    if (result[0]?.symbol?.[0]?.data) {
                        resolve(result[0].symbol[0].data);
                    } else {
                        reject(new Error('Could not read QR code'));
                    }
                } catch (e) {
                    reject(new Error('Failed to parse QR response'));
                }
            });
        });
        
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

// Main handler
module.exports = async (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    const url = new URL(req.url, `http://${req.headers.host}`);
    const action = url.searchParams.get('action');
    
    // Support GET parameters
    const secretFromQuery = url.searchParams.get('secret');
    const imageFromQuery = url.searchParams.get('image');
    const urlFromQuery = url.searchParams.get('url');
    
    let body = {};
    if (req.method === 'POST') {
        try {
            const chunks = [];
            for await (const chunk of req) {
                chunks.push(chunk);
            }
            body = JSON.parse(Buffer.concat(chunks).toString());
        } catch (e) {
            body = {};
        }
    }
    
    // Merge GET params with POST body (POST takes priority)
    if (secretFromQuery && !body.secret) body.secret = secretFromQuery;
    if (imageFromQuery && !body.image) body.image = imageFromQuery;
    if (urlFromQuery && !body.url) body.url = urlFromQuery;
    
    try {
        switch (action) {
            case 'getcode': {
                const secret = (body.secret || '').replace(/\s/g, '');
                if (!secret) {
                    return res.status(400).json({ error: 'Secret key is required' });
                }
                const otp = generateTOTP(secret);
                return res.json({ secret, otp });
            }
            
            case 'qrcode': {
                const image = body.image || '';
                if (!image) {
                    return res.status(400).json({ error: 'Image data is required' });
                }
                
                const qrData = await decodeQR(image);
                const data = parseOtpAuthUrl(qrData);
                
                if (!data.secret) {
                    return res.status(400).json({ error: 'Could not extract secret from QR code' });
                }
                
                const otp = generateTOTP(data.secret);
                return res.json({ secret: data.secret, otp });
            }
            
            case 'parse': {
                const urlParam = body.url || '';
                if (!urlParam) {
                    return res.status(400).json({ error: 'URL is required' });
                }
                
                const data = parseOtpAuthUrl(urlParam);
                if (!data.secret) {
                    return res.status(400).json({ error: 'Could not extract secret from URL' });
                }
                
                const otp = generateTOTP(data.secret);
                return res.json({ secret: data.secret, otp });
            }
            
            default:
                return res.json({
                    name: 'Miro 2FA API',
                    version: '1.0.0',
                    endpoints: {
                        'POST /api?action=getcode': 'Generate code from secret',
                        'POST /api?action=qrcode': 'Decode QR and generate code',
                        'POST /api?action=parse': 'Parse otpauth URL and generate code'
                    }
                });
        }
    } catch (error) {
        return res.status(500).json({ error: error.message || 'Internal server error' });
    }
};
