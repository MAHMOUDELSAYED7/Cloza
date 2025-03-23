const User = require('../models/user');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

const sendOtpEmail = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });
    const mailOptions = {
        from: `"Cloza" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Email Verification OTP',
        html: `
      <div style="font-family: Arial, sans-serif; text-align: center; background-color: #f9f9f9; padding: 20px; border-radius: 10px; border: 1px solid #ddd;">
        <h2 style="color: #333;">Welcome to Cloza!</h2>
        <p style="font-size: 16px; color: #555;">We are excited to have you on board. To verify your email, please use the OTP below:</p>
        <h1 style="color: #4CAF50; font-size: 48px; margin: 10px 0;">${otp}</h1>
        <p style="font-size: 14px; color: #999;">This OTP will expire in <span id="countdown" style="font-weight: bold; color: #e74c3c;">2:00</span> minutes.</p>
        <p style="font-size: 14px; color: #555;">If you did not request this, please ignore this email.</p>
        <p style="font-size: 14px; color: #555;">Thank you,<br>The Cloza Team</p>
      </div>
    `,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email Sent:', info.response);
        return true;
    } catch (error) {
        console.error('Email Error:', error);
        throw new Error('Failed to send verification email');
    }
};

exports.register = async (req, res) => {
    try {
        const { fullname, email, password } = req.body;

        if (!fullname || !email || !password) {
            return res.status(400).json({ message: 'Fullname, email, and password are required' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            if (!existingUser.verified) {
                const otp = Math.floor(1000 + Math.random() * 9000).toString();
                existingUser.otp = otp;
                existingUser.otpExpires = Date.now() + 120000; // 2 minutes
                await existingUser.save();

                await sendOtpEmail(email, otp);
                return res.status(400).json({ message: 'Email already exists but not verified. A new OTP has been sent to your email.' });
            }
            return res.status(400).json({ message: 'Email already exists' });
        }

        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        const user = new User({
            fullname,
            email,
            password,
            otp,
            otpExpires: Date.now() + 120000, // 2 minutes
        });
        await user.save();

        await sendOtpEmail(email, otp);
        res.status(201).json({ message: 'User registered. Please verify your email with the OTP sent.' });
    } catch (err) {
        res.status(500).json({ message: 'Internal Server Error', error: err.message });
    }
};

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (!user.verified) {
            const otp = Math.floor(1000 + Math.random() * 9000).toString();
            user.otp = otp;
            user.otpExpires = Date.now() + 120000; // 2 minutes
            await user.save();

            await sendOtpEmail(email, otp);
            return res.status(403).json({ message: 'Please verify your email before logging in. A new OTP has been sent to your email.' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const accessToken = jwt.sign(
            { id: user._id, role: 'user' },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '2m' }
        );
        const refreshToken = jwt.sign(
            { id: user._id },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '7d' }
        );

        user.refreshToken = refreshToken;
        await user.save();

        res.status(200).json({ accessToken, refreshToken });
    } catch (err) {
        res.status(500).json({ message: 'Internal Server Error', error: err.message });
    }
};
exports.verifyOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ message: 'Email and OTP are required' });
        }

        const user = await User.findOne({ email });
        if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid OTP or OTP has expired' });
        }

        user.verified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully. Please sign in.' });
    } catch (err) {
        res.status(500).json({ message: 'Internal Server Error', error: err.message });
    }
};
exports.refreshToken = async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token is required' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decoded.id);

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        const accessToken = jwt.sign(
            { id: user._id, role: 'user' },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '2m' }
        );

        res.status(200).json({ accessToken });
    } catch (err) {
        res.status(403).json({ message: 'Invalid refresh token' });
    }
};

exports.logout = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (user) {
            user.refreshToken = null;
            await user.save();
        }
        res.status(200).json({ message: 'Logged out successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Internal Server Error', error: err.message });
    }
};

exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (!user.verified) {
            return res.status(403).json({ message: 'Please verify your email before requesting a password reset' });
        }

        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 120000; // 2 minutes
        await user.save();

        await sendOtpEmail(email, otp);
        res.status(200).json({ message: 'OTP has been sent to your email for password reset' });
    } catch (err) {
        res.status(500).json({ message: 'Internal Server Error', error: err.message });
    }
};

exports.resetPassword = async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        if (!email || !otp || !newPassword) {
            return res.status(400).json({ message: 'Email, OTP, and new password are required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'New password must be at least 6 characters long' });
        }

        const user = await User.findOne({ email });
        if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid OTP or OTP has expired' });
        }

        user.password = newPassword;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Password has been reset successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Internal Server Error', error: err.message });
    }
};