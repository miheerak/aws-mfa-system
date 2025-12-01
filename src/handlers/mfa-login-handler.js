const { verifyPassword, generateJWT } = require('../utils/auth');
const { getUserByUsername, logAuthenticationAttempt } = require('../utils/dynamodb');
const { v4: uuidv4 } = require('uuid');

/**
 * Main Lambda handler for login endpoint
 * Implements: Username + Password authentication → JWT token
 */
exports.handler = async (event) => {
  console.log('Login request received:', {
    path: event.path,
    method: event.httpMethod,
    timestamp: new Date().toISOString()
  });

  try {
    // ===== STEP 1: Parse and Validate Input =====
    const body = JSON.parse(event.body || '{}');
    const { username, password } = body;

    // Get client IP for logging
    const ipAddress = event.requestContext?.identity?.sourceIp || 'unknown';
    const userAgent = event.headers?.['user-agent'] || 'unknown';

    console.log(`Login attempt for username: ${username}`);

    // Validate input
    if (!username || !password) {
      console.warn('Missing credentials in login request');
      return buildResponse(401, {
        success: false,
        error: 'Invalid credentials'
      });
    }

    // ===== STEP 2: Query DynamoDB to find user =====
    console.log('Querying Users table for username:', username);
    const user = await getUserByUsername(username);

    if (!user) {
      console.warn(`User not found: ${username}`);
      // Don't reveal that username doesn't exist (security best practice)
      await logAuthenticationAttempt({
        logId: uuidv4(),
        timestamp: new Date().toISOString(),
        userId: 'UNKNOWN',
        username: username,
        success: false,
        ipAddress: ipAddress,
        userAgent: userAgent,
        reason: 'User not found'
      });

      return buildResponse(401, {
        success: false,
        error: 'Invalid credentials'
      });
    }

    // ===== STEP 3: Verify password using bcrypt =====
    console.log('Verifying password for user:', username);
    const passwordMatch = await verifyPassword(password, user.passwordHash);

    if (!passwordMatch) {
      console.warn(`Password verification failed for user: ${username}`);
      // Log failed attempt
      await logAuthenticationAttempt({
        logId: uuidv4(),
        timestamp: new Date().toISOString(),
        userId: user.userId,
        username: username,
        success: false,
        ipAddress: ipAddress,
        userAgent: userAgent,
        reason: 'Invalid password'
      });

      return buildResponse(401, {
        success: false,
        error: 'Invalid credentials'
      });
    }

    // ===== STEP 4: Generate JWT Token =====
    console.log('Password verified, generating JWT token for user:', username);
    const jwtToken = generateJWT(user.userId, username);

    // ===== STEP 5: Log successful authentication =====
    console.log('Logging successful authentication for user:', username);
    await logAuthenticationAttempt({
      logId: uuidv4(),
      timestamp: new Date().toISOString(),
      userId: user.userId,
      username: username,
      success: true,
      ipAddress: ipAddress,
      userAgent: userAgent,
      deviceInfo: {
        userAgent: userAgent,
        platform: event.headers?.['cloudfront-is-desktop-viewer'] ? 'desktop' : 'mobile'
      }
    });

    // ===== STEP 6: Return JWT Token =====
    console.log('Login successful, returning JWT token');
    return buildResponse(200, {
      success: true,
      message: 'Login successful',
      token: jwtToken,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email || null
      },
      expiresIn: '15m'
    });

  } catch (error) {
    console.error('Login handler error:', error);
    
    return buildResponse(500, {
      success: false,
      error: 'Internal server error',
      requestId: event.requestContext?.requestId
    });
  }
};

/**
 * Build standardized HTTP response
 * @param {number} statusCode - HTTP status code
 * @param {Object} body - Response body
 * @returns {Object} - Formatted Lambda response
 */
function buildResponse(statusCode, body) {
  return {
    statusCode: statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
    },
    body: JSON.stringify(body)
  };
}
