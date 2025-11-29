/**
 * AWS MFA System - User Registration Lambda Handler
 * Step 17: Complete implementation with embedded utilities
 * Runtime: Node.js 20.x
 * KEY SCHEMA: userId (Partition Key)
 * GSI: username-index for duplicate checking
 * 
 * TEST CASES COVERED:
 * 1. Valid registration (201)
 * 2. Weak password (400)
 * 3. Invalid email (400)
 * 4. Missing fields (400)
 * 5. Duplicate username (409)
 */

const AWS = require('aws-sdk');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const dynamodb = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = process.env.USERS_TABLE || 'Users';

// =====================================================
// EMBEDDED UTILITIES (Step 17)
// =====================================================

/**
 * Hash password using bcrypt
 */
async function hashPassword(plainTextPassword) {
  try {
    if (!plainTextPassword || plainTextPassword.trim() === '') {
      throw new Error('Password cannot be empty');
    }
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(plainTextPassword, saltRounds);
    console.log('✓ Password hashed successfully');
    return hashedPassword;
  } catch (error) {
    console.error('✗ Error hashing password:', error);
    throw new Error('Failed to hash password: ' + error.message);
  }
}

/**
 * Verify password against stored hash
 */
async function verifyPassword(plainTextPassword, hashedPassword) {
  try {
    if (!plainTextPassword || !hashedPassword) {
      throw new Error('Both password and hash are required');
    }
    const isMatch = await bcrypt.compare(plainTextPassword, hashedPassword);
    console.log('✓ Password verification completed:', isMatch ? 'Match' : 'No match');
    return isMatch;
  } catch (error) {
    console.error('✗ Error verifying password:', error);
    return false;
  }
}

/**
 * Validate password strength
 * Requirements:
 * - Minimum 8 characters
 * - Maximum 128 characters
 * - At least one uppercase letter (A-Z)
 * - At least one lowercase letter (a-z)
 * - At least one number (0-9)
 * - At least one special character
 */
function validatePasswordStrength(password) {
  const errors = [];

  if (!password || password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }

  if (password && password.length > 128) {
    errors.push('Password must not exceed 128 characters');
  }

  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter (A-Z)');
  }

  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter (a-z)');
  }

  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number (0-9)');
  }

  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character (!@#$%^&*...)');
  }

  return {
    isValid: errors.length === 0,
    errors: errors
  };
}

/**
 * Sanitize username
 * - Convert to lowercase
 * - Trim whitespace
 */
function sanitizeUsername(username) {
  if (!username) return '';
  return username.toLowerCase().trim();
}

/**
 * Validate email format
 */
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate username format
 */
function validateUsername(username) {
  if (!username || username.length < 3) {
    return { isValid: false, error: 'Username must be at least 3 characters long' };
  }
  if (username.length > 30) {
    return { isValid: false, error: 'Username must not exceed 30 characters' };
  }
  return { isValid: true };
}

// =====================================================
// LAMBDA HANDLER
// =====================================================

exports.handler = async (event, context) => {
  console.log('=== User Registration Request ===');
  console.log('Event:', JSON.stringify(event, null, 2));

  try {
    // Parse request body
    let body;
    try {
      body = JSON.parse(event.body);
    } catch (parseError) {
      console.error('✗ JSON parse error:', parseError);
      return createResponse(400, {
        message: 'Invalid JSON in request body',
        error: parseError.message
      });
    }

    const { username, password, email, phoneNumber } = body;
    console.log('Registration attempt for username:', username);

    // ===========================
    // Step 1: Validate Required Fields
    // ===========================
    if (!username || !password || !email) {
      console.warn('✗ Missing required fields');
      return createResponse(400, {
        message: 'Missing required fields',
        requiredFields: ['username', 'password', 'email'],
        receivedFields: {
          username: !!username,
          password: !!password,
          email: !!email
        }
      });
    }

    // ===========================
    // Step 2: Sanitize and Validate Username
    // ===========================
    const sanitizedUsername = sanitizeUsername(username);
    const usernameValidation = validateUsername(sanitizedUsername);

    if (!usernameValidation.isValid) {
      console.warn('✗ Invalid username:', usernameValidation.error);
      return createResponse(400, {
        message: usernameValidation.error,
        providedUsername: username
      });
    }

    console.log('✓ Username valid:', sanitizedUsername);

    // ===========================
    // Step 3: Validate Email Format
    // ===========================
    if (!validateEmail(email)) {
      console.warn('✗ Invalid email format:', email);
      return createResponse(400, {
        message: 'Invalid email format',
        providedEmail: email,
        example: 'user@example.com'
      });
    }

    console.log('✓ Email valid:', email);

    // ===========================
    // Step 4: Validate Password Strength
    // ===========================
    console.log('Validating password strength...');
    const passwordValidation = validatePasswordStrength(password);

    if (!passwordValidation.isValid) {
      console.warn('✗ Password validation failed:', passwordValidation.errors);
      return createResponse(400, {
        message: 'Password does not meet security requirements',
        errors: passwordValidation.errors,
        requirements: {
          minLength: 8,
          maxLength: 128,
          mustContain: [
            'At least one uppercase letter (A-Z)',
            'At least one lowercase letter (a-z)',
            'At least one number (0-9)',
            'At least one special character (!@#$%^&*...)'
          ]
        }
      });
    }

    console.log('✓ Password strength validation passed');

    // ===========================
    // Step 5: Check Username Uniqueness (Using GSI)
    // ===========================
    console.log('Checking if username already exists (using GSI username-index)...');
    let usernameExists = false;

    try {
      const queryResult = await dynamodb.query({
        TableName: USERS_TABLE,
        IndexName: 'username-index',  // Global Secondary Index
        KeyConditionExpression: 'username = :username',
        ExpressionAttributeValues: {
          ':username': sanitizedUsername
        },
        Limit: 1
      }).promise();

      usernameExists = queryResult.Items && queryResult.Items.length > 0;
      console.log('Username exists:', usernameExists);
    } catch (dbError) {
      console.error('✗ DynamoDB GSI query error:', dbError);
      return createResponse(500, {
        message: 'Database error while checking username',
        error: dbError.message
      });
    }

    if (usernameExists) {
      console.warn('✗ Username already taken:', sanitizedUsername);
      return createResponse(409, {
        message: 'Username already exists',
        username: sanitizedUsername,
        suggestion: 'Please choose a different username'
      });
    }

    console.log('✓ Username is available');

    // ===========================
    // Step 6: Hash Password
    // ===========================
    console.log('Hashing password using bcrypt (salt rounds: 10)...');
    let hashedPassword;

    try {
      hashedPassword = await hashPassword(password);
      console.log('✓ Hash length:', hashedPassword.length, 'characters');
      console.log('✓ Hash prefix:', hashedPassword.substring(0, 7));
    } catch (hashError) {
      console.error('✗ Password hashing error:', hashError);
      return createResponse(500, {
        message: 'Error processing password',
        error: 'Password hashing failed'
      });
    }

    // ===========================
    // Step 7: Generate User ID
    // ===========================
    const userId = uuidv4();
    console.log('✓ Generated user ID:', userId);

    // ===========================
    // Step 8: Create User Record
    // ===========================
    const timestamp = new Date().toISOString();

    const userRecord = {
      userId: userId,  // Partition Key
      username: sanitizedUsername,
      email: email,
      phoneNumber: phoneNumber || null,
      passwordHash: hashedPassword,
      mfaEnabled: false,
      mfaSecret: null,
      backupCodes: [],
      accountStatus: 'ACTIVE',
      accountLocked: false,
      failedLoginAttempts: 0,
      lastLoginAt: null,
      createdAt: timestamp,
      updatedAt: timestamp,
      riskScore: 0,
      trustedDevices: [],
      registrationIP: event.requestContext?.identity?.sourceIp || 'unknown',
      userAgent: event.headers?.['User-Agent'] || 'unknown'
    };

    console.log('✓ User record prepared');

    // ===========================
    // Step 9: Write to DynamoDB
    // ===========================
    console.log('Writing user record to DynamoDB...');

    try {
      await dynamodb.put({
        TableName: USERS_TABLE,
        Item: userRecord
      }).promise();

      console.log('✓ User saved successfully in DynamoDB');
    } catch (dbError) {
      console.error('✗ DynamoDB write error:', dbError);

      return createResponse(500, {
        message: 'Database error during registration',
        error: dbError.message
      });
    }

    // ===========================
    // Step 10: Return Success Response
    // ===========================
    console.log('=== Registration Completed Successfully ===');

    return createResponse(201, {
      message: 'User registered successfully',
      user: {
        userId: userId,
        username: sanitizedUsername,
        email: email,
        phoneNumber: phoneNumber || null,
        mfaEnabled: false,
        accountStatus: 'ACTIVE',
        createdAt: timestamp
      },
      nextSteps: [
        'You can now log in with your username and password',
        'Consider enabling MFA for enhanced security'
      ]
    });

  } catch (error) {
    // ===========================
    // Global Error Handler
    // ===========================
    console.error('=== Unexpected Error During Registration ===');
    console.error('Error:', error);
    console.error('Stack:', error.stack);

    return createResponse(500, {
      message: 'Internal server error during registration',
      error: error.message,
      requestId: context.requestId
    });
  }
};

/**
 * Create consistent API Gateway response
 */
function createResponse(statusCode, body) {
  return {
    statusCode: statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
      'Access-Control-Allow-Methods': 'POST,OPTIONS'
    },
    body: JSON.stringify(body, null, 2)
  };
}