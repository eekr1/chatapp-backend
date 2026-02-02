const bcrypt = require('bcrypt');
const crypto = require('crypto');

const SALT_ROUNDS = 10;

exports.hashPassword = async (password) => {
    return await bcrypt.hash(password, SALT_ROUNDS);
};

exports.comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

exports.generateSessionToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

exports.hashToken = (token) => {
    return crypto.createHash('sha256').update(token).digest('hex');
};
