require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();
const Ze = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// Initialize Supabase Client
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_KEY || '';
const supabase = (supabaseUrl && supabaseKey) ? createClient(supabaseUrl, supabaseKey, {
    auth: {
        persistSession: false,
        autoRefreshToken: false
    }
}) : null;

if (!supabase) {
    console.error('[CRITICAL] Supabase client could not be initialized. Check SUPABASE_URL and SUPABASE_KEY env vars.');
} else {
    console.log('[INFO] Supabase client initialized successfully.');
}

// Helpers
function encryptData(data, keyBase64) {
    const key = Buffer.from(keyBase64, 'base64');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return iv.toString('base64') + ':' + encrypted;
}

function decryptPayload(payload, keyBase64) {
    const parts = payload.split(':');
    const iv = Buffer.from(parts[0], 'base64');
    const encrypted = parts[1];
    const key = Buffer.from(keyBase64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}

function encryptResponse(dataObj, keyBase64) {
    return { encrypted: true, payload: encryptData(JSON.stringify(dataObj), keyBase64) };
}

// API Routes
app.post('/api/session/init', Ze(async (req, res) => {
    if (!supabase) {
        return res.status(500).json({ error: 'Database connection not configured' });
    }

    const { fingerprint, action } = req.body;
    const sessionId = crypto.randomUUID();
    const key = crypto.randomBytes(32).toString('base64');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes (user requested)

    const { error } = await supabase.from('sessions').insert([{
        id: sessionId,
        key: key,
        fingerprint: fingerprint || 'unknown',
        action: action || 'register_page',
        expires_at: expiresAt.toISOString()
    }]);

    if (error) {
        console.error('[SESSION ERROR]', error);
        return res.status(500).json({ 
            error: 'Database error', 
            message: error.message,
            code: error.code,
            details: error.details
        });
    }

    res.json({ session_id: sessionId, key: key });
}));

app.post('/api/register', Ze(async (req, res) => {
    const sessionId = req.headers['x-session-id'];
    const encryptedPayload = req.body.payload;

    if (!sessionId) return res.status(401).json({ success: false, message: 'Session ID required' });
    if (!supabase) return res.status(500).json({ success: false, message: 'Database not available' });

    // Get session from Supabase
    const { data: session, error: sessionError } = await supabase
        .from('sessions')
        .select('*')
        .eq('id', sessionId)
        .gt('expires_at', new Date().toISOString())
        .single();

    if (sessionError || !session) {
        return res.status(401).json({ success: false, message: 'Invalid or expired session' });
    }

    let data;
    try {
        data = decryptPayload(encryptedPayload, session.key);
    } catch (e) {
        return res.status(400).json({ success: false, message: 'Security failure' });
    }

    const { username, password, key: accessKey, fingerprint } = data;

    // Optional: fingerprint validation
    if (fingerprint && session.fingerprint && fingerprint !== session.fingerprint) {
        console.warn(`[SECURITY] Fingerprint mismatch for session ${sessionId}`);
    }

    try {
        const { data: keyData, error: keyError } = await supabase
            .from('access_keys')
            .select('*')
            .eq('key_value', accessKey)
            .eq('status', 'active')
            .single();

        if (keyError || !keyData) {
            return res.status(400).json(encryptResponse({ success: false, message: 'Invalid or already used access key' }, session.key));
        }

        const { data: userExist } = await supabase
            .from('users')
            .select('id')
            .eq('username', username)
            .maybeSingle();

        if (userExist) {
            return res.status(400).json(encryptResponse({ success: false, message: 'Username is already taken' }, session.key));
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const generatedUid = Math.floor(10000000 + Math.random() * 90000000).toString();

        const { data: newUser, error: createUserError } = await supabase
            .from('users')
            .insert([{ username, password_hash: passwordHash, uid: generatedUid }])
            .select()
            .single();

        if (createUserError || !newUser) {
            console.error('[DB ERROR] User creation failed:', createUserError);
            throw new Error('Failed to create account');
        }

        // Update key status
        await supabase.from('access_keys').update({ status: 'used', user_id: newUser.id }).eq('id', keyData.id);
        
        // Delete session after use
        await supabase.from('sessions').delete().eq('id', sessionId);

        res.json(encryptResponse({ success: true, uid: generatedUid }, session.key));
    } catch (error) {
        console.error('[REGISTRATION ERROR]', error);
        res.status(500).json({ success: false, message: error.message || 'Internal server error' });
    }
}));

// Serve Static Files
app.use(express.static(path.join(__dirname, '..')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Error Handling
app.use((err, req, res, next) => {
    console.error('[REGISTER API ERROR]', err);
    res.status(500).json({ 
        success: false, 
        message: 'Internal Server Error', 
        details: err.message 
    });
});

module.exports = app;

