require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
// const pdf = require('pdf-parse'); // RETIRÉ CAR CAUSE DES CRASHS SUR VERCEL
const xlsx = require('xlsx');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { OpenAI } = require("openai");
const cors = require('cors');
const path = require('path');
const os = require('os');

const app = express();

// --- MODÈLES ---
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    credits: { type: Number, default: 0 },
    opens: { type: Number, default: 0 },
    smtpUser: String, smtpPass: String,
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.models.User || mongoose.model('User', userSchema);

const feedbackSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, type: String, message: String, date: { type: Date, default: Date.now } });
const Feedback = mongoose.models.Feedback || mongoose.model('Feedback', feedbackSchema);

const transactionSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, pack: String, amount: Number, ref: String, status: { type: String, default: 'pending' }, date: { type: Date, default: Date.now } });
const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);

const campaignSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, subject: String, recipientCount: Number, sentAt: { type: Date, default: Date.now } });
const Campaign = mongoose.models.Campaign || mongoose.model('Campaign', campaignSchema);

// --- CONFIG VERCEL ---
const uploadDir = os.tmpdir(); 

let isConnected = false;
const connectToDatabase = async () => {
    if (isConnected) return;
    try {
        if (!process.env.MONGO_URI) throw new Error("MONGO_URI manque !");
        await mongoose.connect(process.env.MONGO_URI, { bufferCommands: false });
        isConnected = true;
        console.log('✅ MongoDB Connecté');
    } catch (error) {
        console.error('❌ Erreur MongoDB:', error);
    }
};

app.use(express.static('public'));
app.use(express.json());
app.use(cors());

// Middleware DB
app.use(async (req, res, next) => {
    await connectToDatabase();
    next();
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage: storage });

let openai;
if (process.env.OPENAI_API_KEY) {
    openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
}

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
    if (!admins.includes(req.user.email)) return res.status(403).json({ error: "Interdit" });
    next();
}

// --- ROUTES ---
app.get('/api/health', (req, res) => {
    res.json({ status: "En ligne", mongo: isConnected ? "Connecté" : "Déconnecté" });
});

app.post('/generate-content', authenticateToken, async (req, res) => {
    if (!openai) return res.status(500).json({ error: "Clé OpenAI manquante" });
    try {
        const completion = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [{ role: "system", content: "Expert Copywriter. JSON: {subject, body}" }, { role: "user", content: `Sujet : "${req.body.topic}"` }],
        });
        res.json(JSON.parse(completion.choices[0].message.content.replace(/```json/g, '').replace(/```/g, '').trim()));
    } catch (error) { res.status(500).json({ error: "Erreur IA" }); }
});

app.post('/send-mail', authenticateToken, upload.single('attachment'), async (req, res) => {
    let recipients;
    try { recipients = JSON.parse(req.body.recipients).map(c => ({ email: c.email.trim(), name: c.name ? c.name.trim() : '' })).filter(c => c.email.includes('@')); } 
    catch (e) { return res.status(400).json({ error: "Liste invalide" }); }

    const user = await User.findById(req.user.id);
    if (!user || user.credits < recipients.length) return res.status(403).json({ error: "Crédits insuffisants" });

    let transporter, fromAddress;
    if (user.smtpUser && user.smtpPass) {
        transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: user.smtpUser, pass: user.smtpPass } });
        fromAddress = user.smtpUser;
    } else {
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || "in-v3.mailjet.com",
            port: parseInt(process.env.SMTP_PORT || "587"),
            secure: false,
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        });
        fromAddress = process.env.SENDER_EMAIL;
    }
    
    let successCount = 0;
    const footer = `<br><div style="text-align:center;font-size:12px;color:#999;margin-top:20px;"><a href="${req.protocol}://${req.get('host')}/unsubscribe">Se désinscrire</a></div>`;

    for (const contact of recipients) {
        try {
            await transporter.sendMail({
                from: fromAddress, replyTo: user.email, to: contact.email, subject: req.body.subject,
                html: req.body.message + footer,
                attachments: req.file ? [{ filename: req.file.originalname, path: req.file.path }] : []
            });
            successCount++;
        } catch (e) { console.error(e); }
    }

    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    if (successCount > 0) {
        user.credits -= successCount;
        await user.save();
        await new Campaign({ userId: user._id, subject: req.body.subject, recipientCount: successCount }).save();
    }
    res.json({ success: true, count: successCount, newCredits: user.credits });
});

app.post('/auth/register', async (req, res) => {
    try {
        if(await User.findOne({ email: req.body.email })) return res.status(400).json({ error: "Pris" });
        const user = new User({ email: req.body.email, password: await bcrypt.hash(req.body.password, 10), credits: 50 });
        await user.save();
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token, credits: 50, opens: 0 });
    } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

app.post('/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ error: "Erreur" });
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
        const admins = (process.env.ADMIN_EMAIL || "").split(',').map(e => e.trim());
        res.json({ success: true, token, credits: user.credits, opens: user.opens || 0, isAdmin: admins.includes(user.email) });
    } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

app.post('/api/payment/declare', authenticateToken, async (req, res) => {
    try { await new Transaction({ userId: req.user.id, ...req.body, amount: req.body.pack==='starter'?3000:req.body.pack==='pro'?10000:20000 }).save(); res.json({ success: true }); } catch (e) { res.status(500).json({ error: "Erreur" }); }
});

// ADMIN ROUTES
app.get('/api/admin/transactions', authenticateToken, requireAdmin, async (req, res) => res.json(await Transaction.find().populate('userId', 'email').sort({ date: -1 })));
app.post('/api/admin/validate-transaction', authenticateToken, requireAdmin, async (req, res) => {
    const t = await Transaction.findById(req.body.transactionId);
    if(req.body.action === 'approve') {
        const u = await User.findById(t.userId);
        u.credits += t.pack==='starter'?500:t.pack==='pro'?2000:5000;
        await u.save(); t.status='approved';
    } else t.status='rejected';
    await t.save(); res.json({success:true});
});
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => res.json(await User.find().sort({createdAt:-1})));
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => { const u = await User.find(); res.json({ totalUsers: u.length, totalCredits: u.reduce((a,c)=>a+(c.credits||0),0) }); });
app.delete('/api/admin/user/:id', authenticateToken, requireAdmin, async (req, res) => { await User.findByIdAndDelete(req.params.id); res.json({success:true}); });
app.post('/api/admin/credits', authenticateToken, requireAdmin, async (req, res) => { await User.findByIdAndUpdate(req.body.userId, { $inc: { credits: req.body.amount } }); res.json({success:true}); });
app.get('/api/admin/feedbacks', authenticateToken, requireAdmin, async (req, res) => res.json(await Feedback.find().populate('userId','email').sort({date:-1})));

// TOOLS (SANS PDF)
app.post('/extract-file', authenticateToken, upload.single('file'), async (req, res) => {
    if(!req.file) return res.status(400).json({error:'Fichier?'});
    try {
        let c = [];
        // On accepte uniquement les fichiers Excel maintenant
        if (!req.file.originalname.match(/\.pdf$/i)) {
            xlsx.utils.sheet_to_json(xlsx.readFile(req.file.path).Sheets[xlsx.readFile(req.file.path).SheetNames[0]]).forEach(r=>{const k=Object.keys(r).find(x=>x.toLowerCase().includes('mail')); if(k) c.push(r[k])});
        }
        if(fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.json({contacts:[...new Set(c)]});
    } catch(e){ res.status(500).json({error:"Erreur"}); }
});

app.post('/api/settings/smtp', authenticateToken, async (req, res) => { await User.findByIdAndUpdate(req.user.id, req.body); res.json({ success: true }); });
app.get('/api/history', authenticateToken, async (req, res) => { const c = await Campaign.find({ userId: req.user.id }).sort({ sentAt: -1 }).limit(10); res.json({ success: true, campaigns: c }); });
app.get('/track/:userId', async (req, res) => { await User.findByIdAndUpdate(req.params.userId, { $inc: { opens: 1 } }); res.end(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64')); });
app.get('/unsubscribe', (req, res) => res.send('<h1>Désabonnement confirmé.</h1>'));
app.post('/api/assist', authenticateToken, async (req, res) => { try { const c = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{role:"system", content:"Court."}, {role:"user", content: req.body.question}] }); res.json({ reply: c.choices[0].message.content }); } catch(e) { res.json({ reply: "..." }); } });
app.post('/api/feedback', authenticateToken, async (req, res) => { await new Feedback({ userId: req.user.id, ...req.body }).save(); res.json({success:true}); });

// PAGES
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/landing', (req, res) => res.sendFile(path.join(__dirname, 'public/landing.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public/admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

// EXPORT POUR VERCEL
module.exports = app;