require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const pdf = require('pdf-parse');
const xlsx = require('xlsx');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { OpenAI } = require("openai");
const cors = require('cors');
const path = require('path');

// Import des Modèles
const User = require('./models/User');
const Feedback = require('./models/Feedback');
let Campaign;
try { Campaign = require('./models/Campaign'); } catch (e) { console.log("⚠️ Note: Historique désactivé (fichier manquant)."); }

const app = express();

// --- 1. CONFIGURATION ---

if (!process.env.JWT_SECRET) {
    console.error("🔥 ERREUR : JWT_SECRET manquant dans .env");
    // On ne coupe pas le processus pour laisser Render afficher les logs
}

const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Connecté à MongoDB'))
    .catch(err => console.error('❌ Erreur MongoDB:', err));

app.use(express.static('public'));
app.use(express.json());
app.use(cors());

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage: storage });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });


// --- 2. MIDDLEWARES ---

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Non connecté." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expirée." });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    const admins = (process.env.ADMIN_EMAIL || "").split(',').map(e => e.trim());
    if (!admins.includes(req.user.email)) {
        return res.status(403).json({ error: "Accès interdit." });
    }
    next();
}


// --- 3. ROUTES PUBLIQUES ---

app.get('/track/:userId', async (req, res) => {
    try { await User.findByIdAndUpdate(req.params.userId, { $inc: { opens: 1 } }); } catch (e) {}
    const img = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    res.writeHead(200, { 'Content-Type': 'image/gif', 'Content-Length': img.length });
    res.end(img);
});

app.post('/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ error: "Email pris" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ email, password: hashedPassword });
        await user.save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Erreur serveur" }); }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: "Identifiants incorrects" });
        
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
        const admins = (process.env.ADMIN_EMAIL || "").split(',').map(e => e.trim());
        const isAdmin = admins.includes(user.email);

        res.json({ success: true, token, credits: user.credits, opens: user.opens || 0, isAdmin });
    } catch (e) { res.status(500).json({ error: "Erreur serveur" }); }
});


// --- 4. MODULE ADMIN ---

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const users = await User.find();
        const totalCredits = users.reduce((acc, curr) => acc + (curr.credits || 0), 0);
        const totalOpens = users.reduce((acc, curr) => acc + (curr.opens || 0), 0);
        let totalSent = 0;
        if(Campaign) totalSent = await Campaign.countDocuments();
        res.json({ totalUsers, totalCredits, totalSent, totalOpens });
    } catch (e) { res.status(500).json({ error: "Erreur stats" }); }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find().sort({ createdAt: -1 }).select('-password');
        res.json(users);
    } catch (e) { res.status(500).json({ error: "Erreur liste" }); }
});

app.post('/api/admin/credits', authenticateToken, requireAdmin, async (req, res) => {
    const { userId, amount } = req.body;
    try {
        const user = await User.findById(userId);
        if(!user) return res.status(404).json({ error: "User introuvable" });
        user.credits += parseInt(amount);
        await user.save();
        res.json({ success: true, newCredits: user.credits });
    } catch (e) { res.status(500).json({ error: "Erreur update" }); }
});

app.delete('/api/admin/user/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        if(Campaign) await Campaign.deleteMany({ userId: req.params.id });
        await Feedback.deleteMany({ userId: req.params.id });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Erreur suppression" }); }
});

app.get('/api/admin/feedbacks', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const feedbacks = await Feedback.find().populate('userId', 'email').sort({ date: -1 });
        res.json(feedbacks);
    } catch (e) { res.status(500).json({ error: "Erreur feedbacks" }); }
});


// --- 5. FEATURES UTILISATEUR ---

app.post('/api/assist', authenticateToken, async (req, res) => {
    const { question } = req.body;
    try {
        const systemContext = `Tu es l'assistant de Newsletter Studio. Réponds brièvement. Tarifs: Starter(3000F/500), Pro(10000F/2000).`;
        const completion = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [{ role: "system", content: systemContext }, { role: "user", content: question }],
        });
        res.json({ reply: completion.choices[0].message.content });
    } catch (error) { res.status(500).json({ error: "Je dors..." }); }
});

app.post('/api/feedback', authenticateToken, async (req, res) => {
    try {
        const { type, message } = req.body;
        await new Feedback({ userId: req.user.id, type, message }).save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

app.post('/api/payment/init', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const pack = req.body.pack;
    let creditsToAdd = 0;
    switch (pack) {
        case 'starter': creditsToAdd = 500; break;
        case 'pro': creditsToAdd = 2000; break;
        case 'business': creditsToAdd = 5000; break;
        default: return res.status(400).json({ error: "Pack inconnu" });
    }
    try {
        const user = await User.findById(userId);
        if (user) { user.credits += creditsToAdd; await user.save(); }
        res.json({ success: true, message: `Pack ${pack} activé`, newCredits: user.credits });
    } catch (e) { res.status(500).json({ error: "Erreur paiement" }); }
});

app.post('/api/settings/smtp', authenticateToken, async (req, res) => {
    try {
        const { smtpUser, smtpPass } = req.body;
        await User.findByIdAndUpdate(req.user.id, { smtpUser, smtpPass });
        res.json({ success: true, message: "Configuration Gmail sauvegardée !" });
    } catch (e) { res.status(500).json({ error: "Erreur sauvegarde" }); }
});

app.get('/api/history', authenticateToken, async (req, res) => {
    try {
        if(!Campaign) return res.json({ success: true, campaigns: [] });
        const campaigns = await Campaign.find({ userId: req.user.id }).sort({ sentAt: -1 }).limit(10);
        res.json({ success: true, campaigns });
    } catch (e) { res.status(500).json({ error: "Erreur historique" }); }
});

app.post('/extract-file', authenticateToken, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Aucun fichier' });
    const filePath = req.file.path;
    let extractedContacts = [];
    try {
        if (req.file.originalname.toLowerCase().endsWith('.pdf')) {
            const data = await pdf(fs.readFileSync(filePath));
            const found = data.text.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi) || [];
            extractedContacts = [...new Set(found.map(e => e.toLowerCase()))];
        } else if (req.file.originalname.match(/\.(xlsx|xls|csv)$/)) {
            const workbook = xlsx.readFile(filePath);
            const sheet = workbook.Sheets[workbook.SheetNames[0]];
            const rows = xlsx.utils.sheet_to_json(sheet);
            rows.forEach(row => {
                const keys = Object.keys(row);
                const emailKey = keys.find(k => k.toLowerCase().includes('mail'));
                const nameKey = keys.find(k => k.toLowerCase().match(/(nom|name|prenom)/));
                if (emailKey && row[emailKey]) {
                    const email = String(row[emailKey]).trim();
                    const name = nameKey && row[nameKey] ? String(row[nameKey]).trim() : '';
                    if (email.includes('@')) extractedContacts.push(name ? `${email}, ${name}` : email);
                }
            });
        }
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        res.json({ contacts: extractedContacts });
    } catch (error) {
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        res.status(500).json({ error: 'Erreur lecture' });
    }
});

app.post('/generate-content', authenticateToken, async (req, res) => {
    try {
        const completion = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [
                { role: "system", content: "Réponds UNIQUEMENT avec un JSON valide : { \"subject\": \"...\", \"body\": \"...\" }. Le body est du HTML simple." },
                { role: "user", content: `Sujet: "${req.body.topic}". Utilise {{nom}}.` }
            ],
        });
        res.json(JSON.parse(completion.choices[0].message.content.replace(/```json/g, '').replace(/```/g, '').trim()));
    } catch (error) { res.status(500).json({ error: "Erreur IA" }); }
});


// --- 6. ENVOI EMAIL (LOGIQUE INTELLIGENTE) ---
app.post('/send-mail', authenticateToken, upload.single('attachment'), async (req, res) => {
    let recipients;
    try { recipients = JSON.parse(req.body.recipients); } catch (e) { return res.status(400).json({ error: "Erreur destinataires" }); }

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "Inconnu" });
    if (user.credits < recipients.length) return res.status(403).json({ error: "Crédits insuffisants" });

    // --- CONFIGURATION SMTP INTELLIGENTE ---
    let transporter;
    let fromAddress;
    let replyToAddress;

    // CAS 1 : SMTP Perso (Paramètres)
    if (user.smtpUser && user.smtpPass) {
        transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: user.smtpUser, pass: user.smtpPass }
        });
        fromAddress = user.smtpUser;
        replyToAddress = user.smtpUser;
    } 
    // CAS 2 : Système par défaut (Brevo)
    else {
        if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
            console.error("❌ CRITIQUE : Variables SMTP système manquantes sur Render (SMTP_USER/SMTP_PASS).");
            return res.status(500).json({ error: "Serveur d'envoi non configuré." });
        }

        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || "smtp-relay.brevo.com",
            port: parseInt(process.env.SMTP_PORT || "587"),
            secure: false, // true pour 465, false pour les autres ports
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });

        // "De la part de..." + Réponse vers l'utilisateur
        fromAddress = `"Via Newsletter" <${process.env.SMTP_USER}>`; 
        replyToAddress = user.email; 
    }

    const trackingPixel = `<img src="${req.protocol}://${req.get('host')}/track/${user._id}" width="1" height="1" style="display:none;" />`;
    let successCount = 0;
    let errorCount = 0;

    console.log(`📧 Démarrage envoi pour ${user.email} (SMTP Perso: ${!!user.smtpUser})`);

    for (const contact of recipients) {
        try {
            await transporter.sendMail({
                from: fromAddress,
                replyTo: replyToAddress, // La réponse va chez l'utilisateur
                to: contact.email,
                subject: req.body.subject,
                html: req.body.message.replace(/{{nom}}/gi, contact.name || '').replace(/Bonjour\s?,/gi, 'Bonjour,') + trackingPixel,
                attachments: req.file ? [{ filename: req.file.originalname, path: req.file.path }] : []
            });
            successCount++;
            console.log(`✅ OK: ${contact.email}`);
            await new Promise(r => setTimeout(r, 500)); // Pause anti-spam
        } catch (error) { 
            console.error(`❌ ERREUR vers ${contact.email}:`, error.message);
            errorCount++; 
        }
    }

    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);

    if (successCount > 0) {
        user.credits -= successCount;
        await user.save();
        if(Campaign) try { await new Campaign({ userId: user._id, subject: req.body.subject, recipientCount: successCount }).save(); } catch(e) {}
    }
    
    res.json({ success: true, count: successCount, errors: errorCount, newCredits: user.credits, currentOpens: user.opens });
});

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/landing', (req, res) => res.sendFile(path.join(__dirname, 'public/landing.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public/admin.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur prêt sur http://localhost:${PORT}`));