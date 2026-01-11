const mongoose = require('mongoose');

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    pack: { type: String, required: true }, // 'starter', 'pro', 'business'
    amount: { type: Number, required: true },
    method: { type: String, default: 'Mobile Money' },
    ref: { type: String, required: true }, // Numéro de téléphone ou ID transaction
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Transaction', TransactionSchema);