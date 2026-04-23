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

// ─── Helpers ──────────────────────────────────────────────────────────────────
function decryptPayload(payload, keyBase64) {
    try {
        const parts = payload.split(':');
        const iv = Buffer.from(parts[0], 'base64');
        const encrypted = parts[1];
        const key = Buffer.from(keyBase64, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (e) {
        console.error('[DECRYPT ERROR]', e.message);
        throw e;
    }
}

function encryptResponse(dataObj, keyBase64) {
    try {
        const iv = crypto.randomBytes(16);
        const key = Buffer.from(keyBase64, 'base64');
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(JSON.stringify(dataObj), 'utf8', 'base64');
        encrypted += cipher.final('base64');
        return { encrypted: true, payload: iv.toString('base64') + ':' + encrypted };
    } catch (e) {
        console.error('[ENCRYPT ERROR]', e.message);
        return { encrypted: false, ...dataObj };
    }
}

async function generateUniqueUid() {
    let attempts = 0;
    while (attempts < 5) {
        const uid = Math.floor(10000000 + Math.random() * 90000000).toString();
        const { data } = await supabase.from('users').select('uid').eq('uid', uid).maybeSingle();
        if (!data) return uid;
        attempts++;
    }
    return Date.now().toString().slice(-8); // Final fallback
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

// Standard Session Init for Web
app.post('/api/session/init', Ze(async (req, res) => {
    const { fingerprint, action } = req.body;
    const sessionId = crypto.randomUUID();
    const key = crypto.randomBytes(32).toString('base64');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    if (!supabase) {
        console.warn('[SESSION] No Supabase client, using local session');
        return res.json({ session_id: sessionId, key: key, _local: true });
    }

    try {
        const { error } = await supabase.from('sessions').insert([{
            id: sessionId,
            key: key,
            fingerprint: fingerprint || 'unknown',
            action: action || 'register_page',
            expires_at: expiresAt.toISOString()
        }]);

        if (error) {
            console.error('[SESSION DB ERROR]', error.message);
            // Fallback to local session
            return res.json({ session_id: sessionId, key: key, _local: true, warning: 'db_error' });
        }
    } catch (err) {
        console.error('[SESSION FATAL ERROR]', err.message);
        return res.json({ session_id: sessionId, key: key, _local: true });
    }

    res.json({ session_id: sessionId, key: key });
}));

// Web Register (Encrypted)
app.post('/api/register', Ze(async (req, res) => {
    const sessionId = req.headers['x-session-id'];
    const encryptedPayload = req.body.payload;

    if (!sessionId) return res.status(401).json({ error: 'Session ID missing' });

    // Fetch session
    let sessionKey = null;
    if (supabase) {
        const { data: session, error: sessionError } = await supabase
            .from('sessions')
            .select('key')
            .eq('id', sessionId)
            .gt('expires_at', new Date().toISOString())
            .maybeSingle();
        
        if (session) sessionKey = session.key;
    }

    if (!sessionKey) return res.status(401).json({ error: 'Session expired or invalid. Please reload.' });

    try {
        const { username, password, key } = decryptPayload(encryptedPayload, sessionKey);

        if (!username || !password || !key) {
            return res.json(encryptResponse({ success: false, error: 'All fields are required' }, sessionKey));
        }

        // Validate Access Key
        const { data: accessKey, error: keyError } = await supabase
            .from('access_keys')
            .select('*')
            .eq('key_value', key)
            .eq('status', 'active')
            .is('user_id', null)
            .maybeSingle();

        if (keyError || !accessKey) {
            return res.json(encryptResponse({ success: false, error: 'Invalid or already used key' }, sessionKey));
        }

        // Check if username exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('username', username)
            .maybeSingle();

        if (existingUser) {
            return res.json(encryptResponse({ success: false, error: 'Username already taken' }, sessionKey));
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const generatedUid = await generateUniqueUid();

        const { data: newUser, error: createUserError } = await supabase
            .from('users')
            .insert([{ username, password_hash: passwordHash, uid: generatedUid }])
            .select()
            .single();

        if (createUserError || !newUser) {
            console.error('[REG ERROR] User creation failed:', createUserError);
            return res.json(encryptResponse({ error: 'Registration failed. Try again.' }, sessionKey));
        }

        // Mark key as used
        await supabase
            .from('access_keys')
            .update({ status: 'used', user_id: newUser.id })
            .eq('id', accessKey.id);

        res.json(encryptResponse({ success: true, message: 'Account created successfully!', uid: generatedUid }, sessionKey));

    } catch (e) {
        console.error('[REG ERROR]', e);
        res.status(400).json({ error: 'Security verification failed' });
    }
}));

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', supabase: !!supabase, time: new Date().toISOString() });
});

// Static Files
app.use(express.static(path.join(__dirname, '..')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Error Handler
app.use((err, req, res, next) => {
    console.error('[GLOBAL ERROR]', err);
    res.status(500).json({ error: 'Internal server error' });
});

module.exports = app;

