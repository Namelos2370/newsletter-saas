const mongoose = require('mongoose');

const FeedbackSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['bug', 'feature', 'other'], default: 'other' }, 
    message: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Feedback', FeedbackSchema);