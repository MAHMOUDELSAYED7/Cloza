const auth = require('./auth');

module.exports = (req, res, next) => {
    const decoded = auth(req, res, next, 'user');
    if (decoded) {
        req.user = decoded; 
        next();
    }
};