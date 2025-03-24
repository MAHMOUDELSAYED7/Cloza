const express = require('express');
const router = express.Router();
const userController = require('../controllers/userAuthController');
const userAuth = require('../middleware/userAuth');

router.post('/register', userController.register);
router.post('/verify-otp', userController.verifyOtp);
router.post('/login', userController.login);
router.post('/refresh-token', userController.refreshToken);
router.post('/logout', userAuth, userController.logout);
router.post('/forgot-password', userController.forgotPassword);
router.post('/reset-password', userController.resetPassword);

module.exports = router;