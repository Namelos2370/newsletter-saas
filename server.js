require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const xlsx = require('xlsx'); // Pas de PDF
const fs = require('fs');
const nodemailer = require('nodemailer');
const { OpenAI } = require("openai");
const cors = require('cors');
const path = require('path');
const os = require('os');

const app = express();
const uploadDir = os.tmpdir(); 

// --- MODELS ---
const userSchema = new mongoose.Schema({ email: {type:String,unique:true}, password: String, credits: {type:Number,default:50}, opens: {type:Number,default:0}, smtpUser: String, smtpPass: String });
const User = mongoose.models.User || mongoose.model('User', userSchema);
const feedbackSchema = new mongoose.Schema({ userId: mongoose.Schema.Types.ObjectId, type: String, message: String, date: {type:Date,default:Date.now} });
const Feedback = mongoose.models.Feedback || mongoose.model('Feedback', feedbackSchema);
const transactionSchema = new mongoose.Schema({ userId: mongoose.Schema.Types.ObjectId, pack: String, amount: Number, ref: String, status: {type:String,default:'pending'}, date: {type:Date,default:Date.now} });
const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
const campaignSchema = new mongoose.Schema({ userId: mongoose.Schema.Types.ObjectId, subject: String, recipientCount: Number, sentAt: {type:Date,default:Date.now} });
const Campaign = mongoose.models.Campaign || mongoose.model('Campaign', campaignSchema);

// --- DB & MIDDLEWARES ---
let isConnected = false;
const connectToDatabase = async () => {
    if (isConnected) return;
    try { await mongoose.connect(process.env.MONGO_URI); isConnected = true; console.log('✅ DB Connectée'); } 
    catch (e) { console.error('❌ Erreur DB:', e); }
};
app.use(express.static('public'));
app.use(express.json());
app.use(cors());
app.use(async (req, res, next) => { await connectToDatabase(); next(); });

const upload = multer({ storage: multer.diskStorage({ destination: (req, f, cb) => cb(null, uploadDir), filename: (req, f, cb) => cb(null, Date.now()+'-'+f.originalname) }) });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

function authenticateToken(req, res, next) {
    const t = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!t) return res.status(401).json({ error: "Non connecté" });
    jwt.verify(t, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Expiré" });
        req.user = user; next();
    });
}
function requireAdmin(req, res, next) {
    if (!(process.env.ADMIN_EMAIL||"").includes(req.user.email)) return res.status(403).json({ error: "Interdit" });
    next();
}

// --- ROUTES ---

// SEND MAIL (AVEC RETOUR D'ERREUR PRÉCIS)
app.post('/send-mail', authenticateToken, upload.single('attachment'), async (req, res) => {
    let recipients;
    try { recipients = JSON.parse(req.body.recipients).map(c => ({ email: c.email.trim(), name: c.name||'' })).filter(c => c.email.includes('@')); } 
    catch (e) { return res.status(400).json({ error: "Liste invalide" }); }

    const user = await User.findById(req.user.id);
    if (!user || user.credits < recipients.length) return res.status(403).json({ error: "Crédits insuffisants !" });

    // CONFIG SMTP
    let transporterConfig;
    let fromAddress;

    if (user.smtpUser && user.smtpPass) {
        // SMTP PERSO (Gmail)
        transporterConfig = { service: 'gmail', auth: { user: user.smtpUser, pass: user.smtpPass } };
        fromAddress = user.smtpUser;
    } else {
        // SMTP PAR DÉFAUT (Vercel Env Vars)
        // Vérification critique
        if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
            return res.json({ success: false, error: "ERREUR CONFIG: Les variables SMTP_USER ou SMTP_PASS manquent sur Vercel." });
        }
        transporterConfig = {
            host: process.env.SMTP_HOST || "smtp.gmail.com", // Force Gmail par défaut si non précisé
            port: 587,
            secure: false,
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        };
        fromAddress = process.env.SENDER_EMAIL || process.env.SMTP_USER;
    }

    const transporter = nodemailer.createTransport(transporterConfig);
    let successCount = 0;
    let lastError = "";

    const footer = `<br><div style="text-align:center;font-size:12px;color:#999;margin-top:20px;"><a href="${req.protocol}://${req.get('host')}/unsubscribe">Se désinscrire</a></div>`;

    for (const contact of recipients) {
        try {
            await transporter.sendMail({
                from: `"Newsletter" <${fromAddress}>`,
                to: contact.email,
                replyTo: user.email,
                subject: req.body.subject,
                html: req.body.message + footer,
                attachments: req.file ? [{ filename: req.file.originalname, path: req.file.path }] : []
            });
            successCount++;
        } catch (e) {
            console.error("❌ Erreur Envoi :", e.message);
            lastError = e.message; // On capture l'erreur pour l'afficher
        }
    }

    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    
    if (successCount > 0) {
        user.credits -= successCount;
        await user.save();
        await new Campaign({ userId: user._id, subject: req.body.subject, recipientCount: successCount }).save();
        res.json({ success: true, count: successCount, newCredits: user.credits });
    } else {
        // Si 0 succès, on renvoie l'erreur technique
        res.json({ success: false, error: "Échec envoi SMTP: " + lastError });
    }
});

// AUTRES ROUTES (SIMPLIFIÉES)
app.post('/auth/register', async (req, res) => {
    if(await User.findOne({email:req.body.email})) return res.status(400).json({error:"Pris"});
    const u = new User({email:req.body.email, password:await bcrypt.hash(req.body.password,10), credits:50});
    await u.save();
    res.json({success:true, token:jwt.sign({id:u._id,email:u.email}, process.env.JWT_SECRET), credits:50});
});
app.post('/auth/login', async (req, res) => {
    const u = await User.findOne({email:req.body.email});
    if(!u || !await bcrypt.compare(req.body.password, u.password)) return res.status(400).json({error:"Erreur"});
    res.json({success:true, token:jwt.sign({id:u._id,email:u.email}, process.env.JWT_SECRET), credits:u.credits, isAdmin:(process.env.ADMIN_EMAIL||"").includes(u.email)});
});
app.post('/generate-content', authenticateToken, async (req, res) => {
    try { const c = await openai.chat.completions.create({model:"gpt-4o-mini", messages:[{role:"system",content:"JSON: {subject, body}"},{role:"user",content:req.body.topic}]}); res.json(JSON.parse(c.choices[0].message.content)); } catch(e){ res.status(500).json({}); }
});
app.post('/api/payment/declare', authenticateToken, async(req,res)=>{ await new Transaction({...req.body, userId:req.user.id}).save(); res.json({success:true}); });
app.get('/api/admin/transactions', authenticateToken, requireAdmin, async(req,res)=>res.json(await Transaction.find().populate('userId','email').sort({date:-1})));
app.post('/api/admin/validate-transaction', authenticateToken, requireAdmin, async(req,res)=>{ 
    const t=await Transaction.findById(req.body.transactionId); 
    if(req.body.action==='approve'){ const u=await User.findById(t.userId); u.credits+=t.pack==='starter'?500:t.pack==='pro'?2000:5000; await u.save(); t.status='approved'; } 
    else t.status='rejected'; await t.save(); res.json({success:true}); 
});
app.get('/api/history', authenticateToken, async(req,res)=>res.json({campaigns:await Campaign.find({userId:req.user.id}).sort({sentAt:-1}).limit(10)}));
app.post('/extract-file', authenticateToken, upload.single('file'), async(req,res)=>{ 
    if(!req.file)return res.status(400).json({error:'Fichier?'}); 
    const c=[]; xlsx.utils.sheet_to_json(xlsx.readFile(req.file.path).Sheets[xlsx.readFile(req.file.path).SheetNames[0]]).forEach(r=>c.push(Object.values(r).find(v=>String(v).includes('@')))); 
    res.json({contacts:[...new Set(c.filter(Boolean))]}); 
});
app.post('/api/assist', authenticateToken, async(req,res)=>{ res.json({reply:"..."}); });
app.post('/api/feedback', authenticateToken, async(req,res)=>{ await new Feedback({...req.body,userId:req.user.id}).save(); res.json({success:true}); });
app.get('/unsubscribe', (req,res)=>res.send('Désabonné.'));

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/landing', (req, res) => res.sendFile(path.join(__dirname, 'public/landing.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public/admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

module.exports = app;