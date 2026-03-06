/**
 * vuln_app.js - Intentionally vulnerable Node.js code for SAST testing.
 * DO NOT deploy in production.
 */

const express = require('express');
const mysql = require('mysql');
const exec = require('child_process').exec;
const fs = require('fs');
const crypto = require('crypto');

// ── HARDCODED SECRETS ─────────────────────────────────────────────
const DB_HOST = 'localhost';
const DB_USER = 'root';
const DB_PASSWORD = 'password123';
const JWT_SECRET = 'jwt-secret-key';
const STRIPE_KEY = 'sk_test_EXAMPLE_REPLACE_ME_NOT_REAL';

const app = express();
app.use(express.json());

// ── SQL INJECTION ──────────────────────────────────────────────────
app.get('/user', (req, res) => {
    const { id } = req.query;
    const conn = mysql.createConnection({ host: DB_HOST, user: DB_USER, password: DB_PASSWORD });
    // VULN: String interpolation in query
    conn.query(`SELECT * FROM users WHERE id = ${id}`, (err, results) => {
        res.json(results);
    });
});

// ── XSS — REFLECTED ───────────────────────────────────────────────
app.get('/search', (req, res) => {
    const { q } = req.query;
    // VULN: Directly injecting user input into HTML
    res.send(`<h1>Results for: ${q}</h1>`);
});

// ── COMMAND INJECTION ──────────────────────────────────────────────
app.post('/convert', (req, res) => {
    const { filename } = req.body;
    // VULN: User-controlled shell command
    exec(`convert ${filename} output.png`, (err, stdout) => {
        res.send(stdout);
    });
});

// ── PATH TRAVERSAL ─────────────────────────────────────────────────
app.get('/download', (req, res) => {
    const { file } = req.query;
    // VULN: No path sanitization
    res.sendFile('/var/www/uploads/' + file);
});

// ── INSECURE EVAL ──────────────────────────────────────────────────
app.post('/calculate', (req, res) => {
    const { expr } = req.body;
    // VULN: eval() with user input — code execution
    const result = eval(expr);
    res.json({ result });
});

// ── WEAK CRYPTO ────────────────────────────────────────────────────
function hashPassword(password) {
    // VULN: MD5 is insecure for passwords
    return crypto.createHash('md5').update(password).digest('hex');
}

// ── INSECURE RANDOM ────────────────────────────────────────────────
function generateToken() {
    // VULN: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

// ── PROTOTYPE POLLUTION ────────────────────────────────────────────
function merge(target, source) {
    for (let key in source) {
        // VULN: No __proto__ check
        target[key] = source[key];
    }
    return target;
}

app.listen(3000, () => console.log('Server running (debug mode)'));
