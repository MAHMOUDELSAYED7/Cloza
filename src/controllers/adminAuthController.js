const Admin = require('../models/admin');
const jwt = require('jsonwebtoken');
require('dotenv').config();

exports.createAdmin = async (req, res) => {
    try {
        const { fullname, email, password, adminSecret } = req.body;

        if (!fullname || !email || !password || !adminSecret) {
            return res.status(400).json({ message: 'Fullname, email, password, and admin secret are required' });
        }

        if (adminSecret !== process.env.ADMIN_SECRET) {
            return res.status(403).json({ message: 'Invalid admin secret' });
        }

        const existingAdmin = await Admin.findOne({ email });
        if (existingAdmin) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        const admin = new Admin({
            fullname,
            email,
            password,
        });
        await admin.save();

        res.status(201).json({ message: 'Admin created successfully. Please sign in.' });
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

        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const isMatch = await admin.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const accessToken = jwt.sign(
            { id: admin._id, role: 'admin' },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '2m' }
        );
        const refreshToken = jwt.sign(
            { id: admin._id },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '7d' }
        );

        admin.refreshToken = refreshToken;
        await admin.save();

        res.status(200).json({ accessToken, refreshToken });
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
        const admin = await Admin.findById(decoded.id);

        if (!admin || admin.refreshToken !== refreshToken) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        const accessToken = jwt.sign(
            { id: admin._id, role: 'admin' },
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
        const admin = await Admin.findById(req.admin.id);
        if (admin) {
            admin.refreshToken = null;
            await admin.save();
        }
        res.status(200).json({ message: 'Logged out successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Internal Server Error', error: err.message });
    }
};