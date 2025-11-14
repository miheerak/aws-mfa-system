const AWS = require('aws-sdk');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const dynamodb = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = 'Users';
const PASSWORD_MIN_LENGTH = 12;
const BCRYPT_ROUNDS = 10;

function validatePasswordStrength(password) {
  const requirements = {
    minLength: password.length >= PASSWORD_MIN_LENGTH,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumber: /[0-9]/.test(password),
    hasSymbol: /[!@#$%^&*()_+\-=\[\]{};:'",.<>?/\\|`~]/.test(password)
  };
  const isValid = Object.values(requirements).every(req => req === true);
  return {
    isValid,
    requirements,
    message: getPasswordErrorMessage(requirements)
  };
}

function getPasswordErrorMessage(requirements) {
  const missing = [];
  if (!requirements.minLength) missing.push(`at least ${PASSWORD_MIN_LENGTH} characters`);
  if (!requirements.hasUppercase) missing.push('at least one uppercase letter');
  if (!requirements.hasLowercase) missing.push('at least one lowercase letter');
  if (!requirements.hasNumber) missing.push('at least one number');
  if (!requirements.hasSymbol) missing.push('at least one special character');
  if (missing.length === 0) return null;
  return `Password must contain: ${missing.join(', ')}`;
}

async function hashPassword(password) {
  try {
    const salt = await bcrypt.genSalt(BCRYPT_ROUNDS);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  } catch (error) {
    throw new Error(`Password hashing failed: ${error.message}`);
  }
}

async function checkUsernameExists(username) {
  try {
    const params = {
      TableName: USERS_TABLE,
      IndexName: 'username-index',
      KeyConditionExpression: 'username = :username',
      ExpressionAttributeValues: {
        ':username': username
      },
      Select: 'COUNT'
    };
    const result = await dynamodb.query(params).promise();
    return result.Count > 0;
  } catch (error) {
    throw new Error(`Failed to check username availability: ${error.message}`);
  }
}

function createBehaviorProfile() {
  return {
    devices: [],
    locations: [],
    averageTypingSpeed: 0,
    loginTimes: [],
    lastLoginTime: null,
    loginAttempts: 0,
    failedAttempts: 0,
    riskScore: 0,
    mfaRequired: true
  };
}

exports.handler = async (event) => {
  console.log('Registration event received:', { body: event.body, headers: event.headers });
  try {
    let requestBody;
    try {
      requestBody = typeof event.body === 'string' 
        ? JSON.parse(event.body) 
        : event.body;
    } catch (error) {
      return createErrorResponse(400, 'Invalid JSON in request body');
    }
    const { username, password, email } = requestBody;
    if (!username || !password) {
      return createErrorResponse(400, 'Username and password are required');
    }
    if (username.length < 3 || username.length > 20) {
      return createErrorResponse(400, 'Username must be between 3 and 20 characters');
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      return createErrorResponse(400, 'Username can only contain alphanumeric characters, hyphens, and underscores');
    }
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
      return createErrorResponse(400, passwordValidation.message);
    }
    const usernameExists = await checkUsernameExists(username);
    if (usernameExists) {
      return createErrorResponse(409, 'Username already taken. Please choose another.');
    }
    const passwordHash = await hashPassword(password);
    const userId = uuidv4();
    const timestamp = Date.now();
    const userRecord = {
      userId,
      username,
      passwordHash,
      email: email || null,
      status: 'active',
      behaviorProfile: createBehaviorProfile(),
      createdAt: timestamp,
      updatedAt: timestamp,
      registrationMethod: 'standard',
      emailVerified: false,
      phoneNumberVerified: false,
      twoFactorEnabled: false
    };
    const params = {
      TableName: USERS_TABLE,
      Item: userRecord,
      ConditionExpression: 'attribute_not_exists(userId)'
    };
    await dynamodb.put(params).promise();
    return createSuccessResponse(201, {
      success: true,
      userId,
      username,
      message: 'User registered successfully. Please proceed with MFA setup.',
      registeredAt: new Date(timestamp).toISOString()
    });
  } catch (error) {
    if (error.code === 'ConditionalCheckFailedException') {
      return createErrorResponse(409, 'Registration failed. Please try again.');
    }
    if (error.code === 'ValidationException') {
      return createErrorResponse(400, 'Invalid data format');
    }
    if (error.code === 'ProvisionedThroughputExceededException') {
      return createErrorResponse(503, 'Service temporarily unavailable. Please try again later.');
    }
    return createErrorResponse(500, 'An error occurred during registration. Please try again later.');
  }
};

function createSuccessResponse(statusCode, data) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS'
    },
    body: JSON.stringify(data)
  };
}

function createErrorResponse(statusCode, message) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS'
    },
    body: JSON.stringify({
      success: false,
      error: message,
      timestamp: new Date().toISOString()
    })
  };
}
