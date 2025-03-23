const jwt = require('jsonwebtoken');
require('dotenv').config();

module.exports = (req, res, next, role) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    if (decoded.role !== role) {
      return res.status(403).json({ message: `Access denied: ${role} role required` });
    }
    return decoded;
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};