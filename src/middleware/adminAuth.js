const auth = require('./auth');

module.exports = (req, res, next) => {
    const decoded = auth(req, res, next, 'admin');
    if (decoded) {
        req.admin = decoded;
        next();
    }
};