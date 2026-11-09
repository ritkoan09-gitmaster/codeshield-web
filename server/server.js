require('dotenv').config();
const express = require('express');
const multer = require('multer');
const AdmZip = require('adm-zip');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const upload = multer({ dest: path.join(__dirname, '../uploads') });

const USERS_FILE = path.join(__dirname, '../users.json');
const SCANS_FILE = path.join(__dirname, '../scans.json');

function getUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function getScans() {
    if (!fs.existsSync(SCANS_FILE)) return [];
    return JSON.parse(fs.readFileSync(SCANS_FILE, 'utf8'));
}
function saveScanRecord(record) {
    const scans = getScans();
    scans.unshift(record); // newest first
    if (scans.length > 30) scans.pop();
    fs.writeFileSync(SCANS_FILE, JSON.stringify(scans, null, 2));
}

const SECURE_PATTERNS = [
    { name: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/ },
    { name: "GitHub Token", regex: /ghp_[a-zA-Z0-9]{36}/ },
    { name: "Generic API Key", regex: /(api[_-]?key|secret[_-]?key)\s*['"]?[=:]\s*['"]([a-zA-Z0-9_\-]{16,})['"]/i },
    { name: "Hardcoded Password", regex: /(password|passwd|pwd)\s*['"]?[=:]\s*['"]([^'"]{4,})['"]/i },
    { name: "SQL Injection Risk", regex: /(SELECT\s+\*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM).*\+/i },
    { name: "Insecure HTTP URL", regex: /http:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/ },
    { name: "TODO Comment", regex: /(#|\/\/)\s*TODO/i }
];

const IGNORE_DIRS = ['.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build', '.idea'];
const IGNORE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.pdf', '.zip', '.exe', '.ico', '.lock', '.pyc'];

function scanFolder(dirPath) {
    let findings = [];
    const items = fs.readdirSync(dirPath, { withFileTypes: true });

    for (const item of items) {
        const fullPath = path.join(dirPath, item.name);

        if (item.isDirectory()) {
            if (!IGNORE_DIRS.includes(item.name)) {
                findings = findings.concat(scanFolder(fullPath));
            }
        } else if (item.isFile()) {
            const ext = path.extname(item.name).toLowerCase();
            if (!IGNORE_EXTENSIONS.includes(ext)) {
                try {
                    const content = fs.readFileSync(fullPath, 'utf8');
                    const lines = content.split(/\r?\n/);
                    lines.forEach((line, index) => {
                        for (const patternObj of SECURE_PATTERNS) {
                            if (patternObj.regex.test(line)) {
                                findings.push({
                                    file: path.relative(dirPath, fullPath),
                                    line: index + 1,
                                    type: patternObj.name,
                                    content: line.trim().substring(0, 100)
                                });
                            }
                        }
                    });
                } catch (err) {}
            }
        }
    }
    return findings;
}

// Auth Endpoints
app.post('/api/signup', (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required.' });
    const users = getUsers();
    if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Email already registered.' });
    const newUser = { id: Date.now(), name, email, password };
    users.push(newUser);
    saveUsers(users);
    res.json({ success: true, user: { name: newUser.name, email: newUser.email } });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = getUsers();
    const user = users.find(u => u.email === email && u.password === password);
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });
    res.json({ success: true, user: { name: user.name, email: user.email } });
});

// Scan Endpoint & User Isolation
app.post('/api/scan', upload.single('projectZip'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No archive uploaded.' });
    const userEmail = req.body.email || 'anonymous';
    const originalName = req.file.originalname;
    const zipPath = req.file.path;
    const extractDir = path.join(__dirname, '../uploads', `extracted_${Date.now()}`);

    try {
        const zip = new AdmZip(zipPath);
        zip.extractAllTo(extractDir, true);
        const findings = scanFolder(extractDir);
        fs.unlinkSync(zipPath);
        fs.rmSync(extractDir, { recursive: true, force: true });

        const scanRecord = {
            id: Date.now(),
            userEmail: userEmail,
            filename: originalName,
            timestamp: new Date().toLocaleString(),
            total: findings.length,
            findings: findings
        };

        saveScanRecord(scanRecord);

        res.json({ success: true, total: findings.length, findings, scanId: scanRecord.id });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process archive.' });
    }
});

// Get User-Specific Scan History Endpoint
app.get('/api/scans', (req, res) => {
    const userEmail = req.query.email;
    const scans = getScans();
    const userScans = scans.filter(s => s.userEmail === userEmail);
    res.json({ success: true, scans: userScans });
});

// CodeShield AI Chat Endpoint
app.post('/api/ai-chat', async (req, res) => {
    const { messages } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
        return res.status(500).json({ error: 'Server configuration error: GEMINI_API_KEY is missing.' });
    }

    try {
        const { GoogleGenAI } = await import('@google/genai');
        const ai = new GoogleGenAI({ 
            apiKey: apiKey, 
            apiVersion: 'v1beta' 
        });

        const systemInstruction = "You are CodeShield AI, an expert software security engineer and coding assistant. Answer any text questions from the user clearly, professionally, and concisely.";

        const formattedContents = messages.map(msg => ({
            role: msg.role === 'user' ? 'user' : 'model',
            parts: [{ text: msg.text }]
        }));

        const response = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: formattedContents,
            config: {
                systemInstruction: systemInstruction
            }
        });

        res.json({ success: true, reply: response.text });
    } catch (error) {
        console.error('CodeShield Chat Error:', error);
        res.status(500).json({ error: 'Failed to get response from CodeShield AI.' });
    }
});

app.listen(PORT, () => {
    console.log(`[+] CodeShield Enterprise Backend running on http://localhost:${PORT}`);
});