const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Constants
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRATION = '15m'; // 15 minute expiration

/**
 * Hash a plain text password using bcrypt
 * @param {string} plainPassword - The password to hash
 * @returns {Promise<string>} - The hashed password
 */
async function hashPassword(plainPassword) {
  try {
    // Salt rounds = 10 (higher = slower but more secure)
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(plainPassword, salt);
    return hash;
  } catch (error) {
    console.error('Error hashing password:', error);
    throw new Error('Password hashing failed');
  }
}

/**
 * Verify a plain text password against a bcrypt hash
 * @param {string} plainPassword - The password to verify
 * @param {string} hashedPassword - The stored hash to compare against
 * @returns {Promise<boolean>} - True if password matches, false otherwise
 */
async function verifyPassword(plainPassword, hashedPassword) {
  try {
    const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
    return isMatch;
  } catch (error) {
    console.error('Error verifying password:', error);
    return false;
  }
}

/**
 * Generate a JWT token for authenticated user
 * @param {string} userId - User ID
 * @param {string} username - Username
 * @returns {string} - JWT token
 */
function generateJWT(userId, username) {
  try {
    const token = jwt.sign(
      {
        userId: userId,
        username: username,
        iat: Math.floor(Date.now() / 1000) // issued at
      },
      JWT_SECRET,
      {
        expiresIn: JWT_EXPIRATION,
        algorithm: 'HS256'
      }
    );
    return token;
  } catch (error) {
    console.error('Error generating JWT:', error);
    throw new Error('JWT generation failed');
  }
}

/**
 * Verify and decode a JWT token
 * @param {string} token - JWT token to verify
 * @returns {Object} - Decoded token payload
 */
function verifyJWT(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256']
    });
    return decoded;
  } catch (error) {
    console.error('Error verifying JWT:', error);
    return null;
  }
}

/**
 * Generate a UUID for user identification
 * @returns {string} - UUID v4
 */
function generateUUID() {
  return uuidv4();
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateJWT,
  verifyJWT,
  generateUUID
};
