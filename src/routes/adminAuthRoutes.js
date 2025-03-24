const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminAuthController');
const adminAuth = require('../middleware/adminAuth');

router.post('/create', adminController.createAdmin);
router.post('/login', adminController.login);
router.post('/refresh-token', adminController.refreshToken);
router.post('/logout', adminAuth, adminController.logout);

router.get('/dashboard', adminAuth, (req, res) => {
    res.json({ message: 'Welcome to the admin dashboard', adminId: req.admin.id });
});

module.exports = router;