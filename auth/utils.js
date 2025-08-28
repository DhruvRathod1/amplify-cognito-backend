const AWS = require('aws-sdk');
const axios = require('axios');

// Set up AWS region
AWS.config.update({ region: process.env.REGION || 'us-east-1' });

// Initialize Cognito Identity Provider
const cognito = new AWS.CognitoIdentityServiceProvider();

/**
 * Sign up a new user
 */
async function signUp(email, password, name) {
  try {
    console.log('Signing up user:', email);

    const params = {
      ClientId: process.env.CLIENT_ID,
      Username: email,
      Password: password,
      UserAttributes: [
        {
          Name: 'email',
          Value: email
        }
      ]
    };

    if (name) {
      params.UserAttributes.push({
        Name: 'name',
        Value: name
      });
    }

    const result = await cognito.signUp(params).promise();
    console.log('Sign up successful');

    return {
      success: true,
      message: 'Sign up successful. Please check your email for verification code.',
      userSub: result.UserSub
    };
  } catch (error) {
    console.error('Error signing up:', error);
    throw error;
  }
}

/**
 * Sign in a user
 */
async function signIn(email, password) {
  try {
    console.log('Signing in user:', email);

    const params = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: process.env.CLIENT_ID,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password
      }
    };

    const result = await cognito.initiateAuth(params).promise();
    console.log('Sign in successful');

    return {
      success: true,
      message: 'Sign in successful',
      tokens: {
        idToken: result.AuthenticationResult.IdToken,
        accessToken: result.AuthenticationResult.AccessToken,
        refreshToken: result.AuthenticationResult.RefreshToken,
        expiresIn: result.AuthenticationResult.ExpiresIn
      }
    };
  } catch (error) {
    console.error('Error signing in:', error);

    // Handle specific error cases
    if (error.code === 'UserNotConfirmedException') {
      return {
        success: false,
        message: 'User is not verified. Please check your email for verification code.',
        unverified: true
      };
    }

    throw error;
  }
}

/**
 * Verify a user's email
 */
async function verifyEmail(email, code) {
  try {
    console.log('Verifying email for user:', email);

    const params = {
      ClientId: process.env.CLIENT_ID,
      Username: email,
      ConfirmationCode: code
    };

    await cognito.confirmSignUp(params).promise();
    console.log('Email verification successful');

    return {
      success: true,
      message: 'Email verification successful. You can now sign in.'
    };
  } catch (error) {
    console.error('Error verifying email:', error);
    throw error;
  }
}

/**
 * Initiate the forgot password flow
 */
async function forgotPassword(email) {
  try {
    console.log('Initiating forgot password flow for user:', email);

    const params = {
      ClientId: process.env.CLIENT_ID,
      Username: email
    };

    await cognito.forgotPassword(params).promise();
    console.log('Forgot password request successful');

    return {
      success: true,
      message: 'Password reset code has been sent to your email.'
    };
  } catch (error) {
    console.error('Error initiating forgot password flow:', error);
    throw error;
  }
}

/**
 * Complete the password reset flow
 */
async function resetPassword(email, code, newPassword) {
  try {
    console.log('Resetting password for user:', email);

    const params = {
      ClientId: process.env.CLIENT_ID,
      Username: email,
      ConfirmationCode: code,
      Password: newPassword
    };

    await cognito.confirmForgotPassword(params).promise();
    console.log('Password reset successful');

    return {
      success: true,
      message: 'Password has been reset successfully. You can now sign in with your new password.'
    };
  } catch (error) {
    console.error('Error resetting password:', error);
    throw error;
  }
}

/**
 * Refresh tokens using refresh token
 */
async function refreshTokens(refreshToken) {
  try {
    console.log('Refreshing tokens');

    const params = {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: process.env.CLIENT_ID,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken
      }
    };

    const result = await cognito.initiateAuth(params).promise();
    console.log('Token refresh successful');

    return {
      success: true,
      message: 'Token refresh successful',
      tokens: {
        idToken: result.AuthenticationResult.IdToken,
        accessToken: result.AuthenticationResult.AccessToken,
        expiresIn: result.AuthenticationResult.ExpiresIn,
        // Note: A new refresh token is not provided when refreshing tokens
      }
    };
  } catch (error) {
    console.error('Error refreshing tokens:', error);
    throw error;
  }
}

/**
 * Generate Google OAuth URL
 */
function getGoogleAuthUrl(state, redirectUri) {
  const baseUrl = 'https://accounts.google.com/o/oauth2/v2/auth';

  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'email profile openid',
    state: state,
    access_type: 'offline',
    prompt: 'consent'
  });

  return `${baseUrl}?${params.toString()}`;
}

/**
 * Handle Google OAuth callback and exchange code for tokens
 */
async function handleGoogleCallback(code, redirectUri) {
  try {
    console.log('Handling Google callback with code');

    // Exchange authorization code for tokens
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    });
    console.log('Received token response from Google');

    // Get user info with access token
    const userInfoResponse = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenResponse.data.access_token}` },
    });
    console.log('Received user info from Google');

    const { email, sub, name, picture } = userInfoResponse.data;
    console.log('User email:', email);

    // We'll create a direct sign-in attempt - this is simpler than going through
    // the federated identity setup, which requires more configuration
    const params = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: process.env.CLIENT_ID,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: `Google-${sub}-${process.env.GOOGLE_CLIENT_SECRET.substring(0, 10)}` // Never expose this
      }
    };

    let result;

    try {
      // Try to sign in with the generated password
      console.log('Attempting to sign in user');
      result = await cognito.initiateAuth(params).promise();
      console.log('Sign-in successful');
    } catch (err) {
      console.log('Sign-in failed, checking if user exists:', err.code);

      if (err.code === 'UserNotFoundException' || err.code === 'NotAuthorizedException') {
        // User doesn't exist or wrong password, create or update them
        console.log('Creating or updating user');
        try {
          // Check if user exists
          await cognito.adminGetUser({
            UserPoolId: process.env.USER_POOL_ID,
            Username: email
          }).promise();

          // User exists, set the password
          console.log('User exists, setting password');
          await cognito.adminSetUserPassword({
            UserPoolId: process.env.USER_POOL_ID,
            Username: email,
            Password: `Google-${sub}-${process.env.GOOGLE_CLIENT_SECRET.substring(0, 10)}`,
            Permanent: true
          }).promise();
        } catch (userErr) {
          if (userErr.code === 'UserNotFoundException') {
            // Create the user
            console.log('User not found, creating user');
            await cognito.adminCreateUser({
              UserPoolId: process.env.USER_POOL_ID,
              Username: email,
              TemporaryPassword: `Google-${sub}-${process.env.GOOGLE_CLIENT_SECRET.substring(0, 10)}`,
              UserAttributes: [
                { Name: 'email', Value: email },
                { Name: 'email_verified', Value: 'true' },
                { Name: 'name', Value: name || '' },
                { Name: 'picture', Value: picture || '' }
              ]
            }).promise();

            // Set permanent password
            console.log('Setting permanent password');
            await cognito.adminSetUserPassword({
              UserPoolId: process.env.USER_POOL_ID,
              Username: email,
              Password: `Google-${sub}-${process.env.GOOGLE_CLIENT_SECRET.substring(0, 10)}`,
              Permanent: true
            }).promise();
          } else {
            throw userErr;
          }
        }

        // Try sign-in again after user creation/update
        console.log('Trying sign-in again');
        result = await cognito.initiateAuth(params).promise();
      } else {
        // Some other error
        throw err;
      }
    }

    console.log('Authentication successful');
    return {
      success: true,
      message: 'Google authentication successful',
      userInfo: { email, googleId: sub, name, picture },
      tokens: {
        idToken: result.AuthenticationResult.IdToken,
        accessToken: result.AuthenticationResult.AccessToken,
        refreshToken: result.AuthenticationResult.RefreshToken,
        expiresIn: result.AuthenticationResult.ExpiresIn
      }
    };
  } catch (error) {
    console.error('Error handling Google callback:', error);
    return {
      success: false,
      message: error.message || 'An error occurred during Google authentication',
    };
  }
}

module.exports = {
  signUp,
  signIn,
  verifyEmail,
  forgotPassword,
  resetPassword,
  refreshTokens,
  getGoogleAuthUrl,
  handleGoogleCallback
};