const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const userRoutes = require('./routes/userAuthRoutes');
const adminRoutes = require('./routes/adminAuthRoutes');

const app = express();
const port = process.env.PORT;

app.use(cors({
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Authorization', 'Content-Type'],
}));
app.use(express.json());

const mongoUri = process.env.MONGO_URI;

mongoose.connect(mongoUri)
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('MongoDB connection error:', err));

app.use('/api/auth/user', userRoutes);
app.use('/api/auth/admin', adminRoutes);

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});