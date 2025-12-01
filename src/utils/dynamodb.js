const AWS = require('aws-sdk');

// Create DynamoDB DocumentClient for easier operations
const dynamodb = new AWS.DynamoDB.DocumentClient({
  region: process.env.AWS_REGION || 'us-east-1'
});

/**
 * Query user by username from Users table
 * @param {string} username - Username to find
 * @returns {Promise<Object>} - User object or null
 */
async function getUserByUsername(username) {
  try {
    const params = {
      TableName: process.env.USERS_TABLE || 'Users',
      IndexName: 'UsernameIndex', // Requires GSI on username
      KeyConditionExpression: 'username = :username',
      ExpressionAttributeValues: {
        ':username': username
      }
    };

    const result = await dynamodb.query(params).promise();

    if (result.Items && result.Items.length > 0) {
      return result.Items;
    }
    return null;
  } catch (error) {
    console.error('Error getting user by username:', error);
    throw new Error('Database query failed');
  }
}

/**
 * Get user by userId
 * @param {string} userId - User ID to find
 * @returns {Promise<Object>} - User object or null
 */
async function getUserById(userId) {
  try {
    const params = {
      TableName: process.env.USERS_TABLE || 'Users',
      Key: {
        userId: userId
      }
    };

    const result = await dynamodb.get(params).promise();
    return result.Item || null;
  } catch (error) {
    console.error('Error getting user by ID:', error);
    throw new Error('Database query failed');
  }
}

/**
 * Log authentication attempt to AuthenticationLogs table
 * @param {Object} logData - Data to log
 * @returns {Promise<void>}
 */
async function logAuthenticationAttempt(logData) {
  try {
    const params = {
      TableName: process.env.AUTH_LOGS_TABLE || 'AuthenticationLogs',
      Item: {
        logId: logData.logId,
        timestamp: logData.timestamp,
        userId: logData.userId,
        username: logData.username,
        success: logData.success,
        ipAddress: logData.ipAddress,
        userAgent: logData.userAgent,
        deviceInfo: logData.deviceInfo || {},
        ttl: Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60) // 30 day TTL
      }
    };

    await dynamodb.put(params).promise();
  } catch (error) {
    console.error('Error logging authentication attempt:', error);
    // Don't throw here - logging failure shouldn't break authentication
  }
}

module.exports = {
  getUserByUsername,
  getUserById,
  logAuthenticationAttempt
};
