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

// --- IMPORT DES MODÈLES ---
const User = require('./models/User');
const Feedback = require('./models/Feedback');
const Transaction = require('./models/Transaction');
let Campaign;
try { Campaign = require('./models/Campaign'); } catch (e) { console.log("⚠️ Note: Historique désactivé."); }

const app = express();

// --- CONFIGURATION ---
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


// --- MIDDLEWARES ---
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
    if (!admins.includes(req.user.email)) return res.status(403).json({ error: "Accès interdit." });
    next();
}


// --- ROUTES ---

// 1. IA MARKETING
app.post('/generate-content', authenticateToken, async (req, res) => {
    try {
        const systemPrompt = `
            Tu es un Expert Copywriter. Rédige une newsletter captivante.
            Méthode : AIDA. Ton : Engageant, humain, quelques emojis.
            Format de réponse (JSON pur) : { "subject": "...", "body": "..." }
            Le body doit être en HTML simple (<p>, <br>, <strong>).
        `;
        const completion = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [{ role: "system", content: systemPrompt }, { role: "user", content: `Sujet : "${req.body.topic}"` }],
        });
        res.json(JSON.parse(completion.choices[0].message.content.replace(/```json/g, '').replace(/```/g, '').trim()));
    } catch (error) { res.status(500).json({ error: "Erreur IA" }); }
});

// 2. ENVOI EMAIL (AVEC DESABONNEMENT)
app.post('/send-mail', authenticateToken, upload.single('attachment'), async (req, res) => {
    let recipients;
    try { 
        recipients = JSON.parse(req.body.recipients).map(c => ({ email: c.email.trim(), name: c.name ? c.name.trim() : '' })).filter(c => c.email.includes('@'));
    } catch (e) { return res.status(400).json({ error: "Liste invalide" }); }

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "Inconnu" });
    if (user.credits < recipients.length) return res.status(403).json({ error: "Crédits insuffisants" });

    let transporter, fromAddress, replyToAddress;

    // CAS 1 : SMTP Perso
    if (user.smtpUser && user.smtpPass) {
        transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: user.smtpUser, pass: user.smtpPass } });
        fromAddress = user.smtpUser;
        replyToAddress = user.smtpUser;
    } 
    // CAS 2 : Système par défaut
    else {
        if (!process.env.SMTP_USER || !process.env.SENDER_EMAIL) return res.status(500).json({ error: "Erreur config serveur (SENDER_EMAIL manquant)." });
        
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || "in-v3.mailjet.com",
            port: parseInt(process.env.SMTP_PORT || "587"),
            secure: false,
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        });
        fromAddress = `"Newsletter" <${process.env.SENDER_EMAIL}>`; 
        replyToAddress = user.email;
    }

    const trackingPixel = `<img src="${req.protocol}://${req.get('host')}/track/${user._id}" width="1" height="1" style="display:none;" />`;
    
    // PIED DE PAGE DÉSABONNEMENT (Légal & Anti-Spam)
    const unsubscribeFooter = `
        <br><br>
        <div style="text-align:center; font-size:12px; color:#94a3b8; border-top:1px solid #e2e8f0; padding-top:15px; margin-top:20px;">
            Cet email a été envoyé via une plateforme de marketing.<br>
            <a href="${req.protocol}://${req.get('host')}/unsubscribe" style="color:#64748b; text-decoration:underline;">Se désinscrire de cette liste</a>
        </div>
    `;

    let successCount = 0, errorCount = 0;
    console.log(`📧 Envoi ${recipients.length} mails. From: ${fromAddress}`);

    for (const contact of recipients) {
        try {
            let finalHtml = req.body.message
                .replace(/{{nom}}/gi, contact.name || '')
                .replace(/Bonjour\s?,/gi, 'Bonjour,');
            
            // Ajout Pixel + Footer
            finalHtml += unsubscribeFooter + trackingPixel;

            await transporter.sendMail({
                from: fromAddress,
                replyTo: replyToAddress,
                to: contact.email,
                subject: req.body.subject,
                html: finalHtml,
                attachments: req.file ? [{ filename: req.file.originalname, path: req.file.path }] : []
            });
            successCount++;
            await new Promise(r => setTimeout(r, 400));
        } catch (error) { 
            console.error(`❌ Échec ${contact.email}:`, error.message);
            errorCount++; 
        }
    }

    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    if (successCount > 0) {
        user.credits -= successCount;
        await user.save();
        if(Campaign) try { await new Campaign({ userId: user._id, subject: req.body.subject, recipientCount: successCount }).save(); } catch(e) {}
    }
    
    res.json({ success: true, count: successCount, errors: errorCount, newCredits: user.credits });
});

// 3. PAIEMENT MANUEL
app.post('/api/payment/declare', authenticateToken, async (req, res) => {
    const { pack, ref } = req.body;
    let amount = 0;
    if(pack === 'starter') amount = 3000;
    else if(pack === 'pro') amount = 10000;
    else if(pack === 'business') amount = 20000;
    else return res.status(400).json({ error: "Pack invalide" });

    try {
        await new Transaction({ userId: req.user.id, pack, amount, ref }).save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

// 4. AUTHENTIFICATION (AUTO LOGIN + 50 CRÉDITS)
app.post('/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if(await User.findOne({ email })) return res.status(400).json({ error: "Email pris" });
        
        // CADEAU DE BIENVENUE : 50 Credits
        const user = new User({ 
            email, 
            password: await bcrypt.hash(password, 10),
            credits: 50 
        });
        
        await user.save();

        // GÉNÉRATION IMMEDIATE DU TOKEN (Pour connexion directe)
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

        // On renvoie le token et les infos
        res.json({ success: true, token, credits: 50, opens: 0 });
    } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

app.post('/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ error: "Erreur login" });
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
        const admins = (process.env.ADMIN_EMAIL || "").split(',').map(e => e.trim());
        res.json({ success: true, token, credits: user.credits, opens: user.opens || 0, isAdmin: admins.includes(user.email) });
    } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

// 5. ADMIN
app.get('/api/admin/transactions', authenticateToken, requireAdmin, async (req, res) => {
    try { res.json(await Transaction.find().populate('userId', 'email').sort({ date: -1 })); } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

app.post('/api/admin/validate-transaction', authenticateToken, requireAdmin, async (req, res) => {
    const { transactionId, action } = req.body;
    try {
        const transac = await Transaction.findById(transactionId);
        if(!transac || transac.status !== 'pending') return res.status(400).json({ error: "Impossible" });

        if (action === 'approve') {
            const user = await User.findById(transac.userId);
            let credits = 0;
            if(transac.pack === 'starter') credits = 500;
            if(transac.pack === 'pro') credits = 2000;
            if(transac.pack === 'business') credits = 5000;
            user.credits += credits;
            await user.save();
            transac.status = 'approved';
        } else {
            transac.status = 'rejected';
        }
        await transac.save();
        res.json({ success: true, status: transac.status });
    } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => res.json(await User.find().sort({createdAt:-1})));
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    const users = await User.find();
    res.json({ totalUsers: users.length, totalCredits: users.reduce((a,c)=>a+(c.credits||0),0) });
});
// Delete User
app.delete('/api/admin/user/:id', authenticateToken, requireAdmin, async (req, res) => {
    try { await User.findByIdAndDelete(req.params.id); res.json({success:true}); } catch(e){ res.status(500).json({error:"Err"}); }
});
// Add Bonus Credits
app.post('/api/admin/credits', authenticateToken, requireAdmin, async (req, res) => {
    try { await User.findByIdAndUpdate(req.body.userId, { $inc: { credits: req.body.amount } }); res.json({success:true}); } catch(e){ res.status(500).json({error:"Err"}); }
});
app.get('/api/admin/feedbacks', authenticateToken, requireAdmin, async (req, res) => res.json(await Feedback.find().populate('userId','email').sort({date:-1})));

// --- OUTILS & HELPERS ---
app.post('/extract-file', authenticateToken, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Fichier manquant' });
    let contacts = [];
    try {
        if (req.file.originalname.match(/\.pdf$/i)) {
            const data = await pdf(fs.readFileSync(req.file.path));
            contacts = data.text.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi) || [];
        } else {
            const rows = xlsx.utils.sheet_to_json(xlsx.readFile(req.file.path).Sheets[xlsx.readFile(req.file.path).SheetNames[0]]);
            rows.forEach(row => {
                const k = Object.keys(row).find(k => k.toLowerCase().includes('mail'));
                if (k && row[k]) contacts.push(row[k]);
            });
        }
        if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.json({ contacts: [...new Set(contacts)] });
    } catch (e) { if(fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); res.status(500).json({error:"Erreur lecture"}); }
});

app.post('/api/settings/smtp', authenticateToken, async (req, res) => {
    await User.findByIdAndUpdate(req.user.id, req.body);
    res.json({ success: true });
});

app.get('/api/history', authenticateToken, async (req, res) => {
    if(!Campaign) return res.json({ campaigns: [] });
    const campaigns = await Campaign.find({ userId: req.user.id }).sort({ sentAt: -1 }).limit(10);
    res.json({ success: true, campaigns });
});

app.get('/track/:userId', async (req, res) => {
    try { await User.findByIdAndUpdate(req.params.userId, { $inc: { opens: 1 } }); } catch (e) {}
    const img = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    res.writeHead(200, { 'Content-Type': 'image/gif', 'Content-Length': img.length });
    res.end(img);
});

// Route Désabonnement
app.get('/unsubscribe', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Désabonnement</title>
            <style>body{font-family:'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f8fafc;color:#334155;} .box{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,0.05);text-align:center;max-width:400px;}</style>
        </head>
        <body>
            <div class="box">
                <h2 style="color:#10b981;">✅ C'est fait.</h2>
                <p>Vous avez été désinscrit avec succès de cette liste de diffusion.</p>
                <p style="font-size:0.9rem; color:#94a3b8; margin-top:20px;">Vous ne recevrez plus d'emails de cet expéditeur.</p>
            </div>
        </body>
        </html>
    `);
});

// Chatbot & Feedback
app.post('/api/assist', authenticateToken, async (req, res) => {
    try {
        const c = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{role:"system", content:"Tu es l'assistant de Newsletter Studio. Réponse courte."}, {role:"user", content: req.body.question}] });
        res.json({ reply: c.choices[0].message.content });
    } catch(e) { res.json({ reply: "Désolé, je dors." }); }
});
app.post('/api/feedback', authenticateToken, async (req, res) => { await new Feedback({ userId: req.user.id, ...req.body }).save(); res.json({success:true}); });

// Pages
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/landing', (req, res) => res.sendFile(path.join(__dirname, 'public/landing.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public/admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur prêt sur port ${PORT}`));