const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  shops: [{ type: String, unique: true, required: true }], // shops names array
});

module.exports = mongoose.model('User', userSchema);
