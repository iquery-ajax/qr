<?php
/**
 * Miro 2FA API
 * Endpoints:
 * - POST /api.php?action=getcode - Generate code from secret
 * - POST /api.php?action=qrcode - Decode QR and generate code
 * - POST /api.php?action=parse - Parse otpauth URL and generate code
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Get action
$action = $_GET['action'] ?? '';

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true) ?? [];

// Response helper
function respond($data, $code = 200) {
    http_response_code($code);
    echo json_encode($data);
    exit;
}

// Error helper
function error($message, $code = 400) {
    respond(['success' => false, 'error' => $message], $code);
}

// Base32 decode
function base32Decode($encoded) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $encoded = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $encoded));
    
    $buffer = 0;
    $bitsLeft = 0;
    $result = '';
    
    for ($i = 0; $i < strlen($encoded); $i++) {
        $val = strpos($alphabet, $encoded[$i]);
        if ($val === false) continue;
        
        $buffer = ($buffer << 5) | $val;
        $bitsLeft += 5;
        
        if ($bitsLeft >= 8) {
            $bitsLeft -= 8;
            $result .= chr(($buffer >> $bitsLeft) & 0xFF);
        }
    }
    
    return $result;
}

// Generate TOTP
function generateTOTP($secret, $timeStep = 30, $digits = 6) {
    $key = base32Decode($secret);
    $time = floor(time() / $timeStep);
    
    // Pack time as 64-bit big-endian
    $timeBytes = pack('N*', 0, $time);
    
    // HMAC-SHA1
    $hash = hash_hmac('sha1', $timeBytes, $key, true);
    
    // Dynamic truncation
    $offset = ord($hash[19]) & 0x0f;
    $code = (
        ((ord($hash[$offset]) & 0x7f) << 24) |
        ((ord($hash[$offset + 1]) & 0xff) << 16) |
        ((ord($hash[$offset + 2]) & 0xff) << 8) |
        (ord($hash[$offset + 3]) & 0xff)
    ) % pow(10, $digits);
    
    return str_pad($code, $digits, '0', STR_PAD_LEFT);
}

// Get remaining seconds
function getRemainingSeconds($timeStep = 30) {
    return $timeStep - (time() % $timeStep);
}

// Parse otpauth URL
function parseOtpAuthUrl($url) {
    if (strpos($url, 'otpauth://') !== 0) {
        return ['secret' => $url];
    }
    
    $parsed = parse_url($url);
    parse_str($parsed['query'] ?? '', $params);
    
    $path = urldecode($parsed['path'] ?? '');
    $parts = explode(':', ltrim($path, '/'));
    
    return [
        'secret' => $params['secret'] ?? '',
        'issuer' => $params['issuer'] ?? ($parts[0] ?? ''),
        'account' => $parts[1] ?? ''
    ];
}

// ===== Actions =====

switch ($action) {
    case 'getcode':
        $secret = $input['secret'] ?? '';
        
        if (empty($secret)) {
            error('Secret key is required');
        }
        
        $secret = preg_replace('/\s+/', '', $secret);
        
        try {
            $code = generateTOTP($secret);
            respond([
                'success' => true,
                'secret' => $secret,
                'code' => $code,
                'remaining' => getRemainingSeconds()
            ]);
        } catch (Exception $e) {
            error('Invalid secret key');
        }
        break;
        
    case 'qrcode':
        $image = $input['image'] ?? '';
        
        if (empty($image)) {
            error('Image data is required');
        }
        
        // Remove data URL prefix if present
        if (strpos($image, 'base64,') !== false) {
            $image = explode('base64,', $image)[1];
        }
        
        // Decode base64 to binary
        $imageData = base64_decode($image);
        if ($imageData === false) {
            error('Invalid base64 image');
        }
        
        // Save temp file
        $tempFile = tempnam(sys_get_temp_dir(), 'qr_') . '.png';
        file_put_contents($tempFile, $imageData);
        
        // Use QR Server API to decode
        $ch = curl_init();
        $cfile = new CURLFile($tempFile, 'image/png', 'qrcode.png');
        
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://api.qrserver.com/v1/read-qr-code/',
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => ['file' => $cfile],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        // Clean up temp file
        unlink($tempFile);
        
        if ($httpCode !== 200 || !$response) {
            error('Failed to decode QR code');
        }
        
        $result = json_decode($response, true);
        
        if (!$result || !isset($result[0]['symbol'][0]['data'])) {
            error('Could not read QR code');
        }
        
        $qrData = $result[0]['symbol'][0]['data'];
        
        if (empty($qrData) || isset($result[0]['symbol'][0]['error'])) {
            error('QR code is empty or invalid');
        }
        
        // Parse the otpauth URL
        $data = parseOtpAuthUrl($qrData);
        
        if (empty($data['secret'])) {
            error('Could not extract secret from QR code');
        }
        
        try {
            $code = generateTOTP($data['secret']);
            respond([
                'secret' => $data['secret'],
                'otp' => $code
            ]);
        } catch (Exception $e) {
            error('Invalid secret in QR code');
        }
        break;
        
    case 'parse':
        $url = $input['url'] ?? '';
        
        if (empty($url)) {
            error('URL is required');
        }
        
        $data = parseOtpAuthUrl($url);
        
        if (empty($data['secret'])) {
            error('Could not extract secret from URL');
        }
        
        try {
            $code = generateTOTP($data['secret']);
            respond([
                'success' => true,
                'secret' => $data['secret'],
                'code' => $code,
                'issuer' => $data['issuer'],
                'account' => $data['account'],
                'remaining' => getRemainingSeconds()
            ]);
        } catch (Exception $e) {
            error('Invalid secret in URL');
        }
        break;
        
    default:
        // API info
        respond([
            'name' => 'Miro 2FA API',
            'version' => '1.0.0',
            'endpoints' => [
                'POST /api.php?action=getcode' => 'Generate code from secret',
                'POST /api.php?action=parse' => 'Parse otpauth URL and generate code'
            ],
            'example' => [
                'request' => ['secret' => 'JBSWY3DPEHPK3PXP'],
                'response' => [
                    'success' => true,
                    'secret' => 'JBSWY3DPEHPK3PXP',
                    'code' => '123456',
                    'remaining' => 25
                ]
            ]
        ]);
}
