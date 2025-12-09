const mongoose = require('mongoose');

const CampaignSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Qui a envoyé ?
    subject: String, // Quel sujet ?
    content: String, // (Optionnel) Le contenu HTML
    recipientCount: Number, // Combien de personnes ?
    status: { type: String, default: 'Sent' },
    sentAt: { type: Date, default: Date.now } // Quand ?
});

module.exports = mongoose.model('Campaign', CampaignSchema);