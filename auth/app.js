const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const serverless = require('serverless-http');
require('dotenv').config();

// Import utility functions
const {
  signUp,
  confirmSignUp,
  signIn,
  forgotPassword,
  confirmForgotPassword,
  refreshTokens,
  processGoogleOAuth,
  verifyToken
} = require('./utils');

// Initialize Express app
const app = express();

// Set up AWS region and environment variables mapping
const region = process.env.REGION || 'us-east-1';

// Map CloudFormation environment variables to the ones used in our utility functions
process.env.COGNITO_CLIENT_ID = process.env.CLIENT_ID;
process.env.AWS_REGION = region;

// Parse incoming request bodies
app.use(bodyParser.json());
app.use(cookieParser());

// Set up CORS
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',');
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf('*') !== -1 || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Add headers for OPTIONS requests (preflight)
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    const headers = {
      'Access-Control-Allow-Origin': req.headers.origin,
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
      'Access-Control-Max-Age': '3600',
      'Access-Control-Allow-Credentials': true
    };
    res.set(headers).status(204).send();
  } else {
    next();
  }
});

// Define routes
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Auth service running' });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Sign up endpoint
app.post('/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const attributes = name ? { 'name': name } : {};

    const result = await signUp(email, password, attributes);
    res.json({
      success: true,
      message: 'User registration successful. Please check your email for verification code.',
      ...result
    });
  } catch (error) {
    console.error('Sign up error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An error occurred during sign up'
    });
  }
});

// Sign in endpoint
app.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await signIn(email, password);
    res.json(result);
  } catch (error) {
    console.error('Sign in error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An error occurred during sign in'
    });
  }
});

// Verify email endpoint
app.post('/verify', async (req, res) => {
  try {
    const { email, code } = req.body;
    const result = await confirmSignUp(email, code);
    res.json({
      success: true,
      message: 'Email verification successful',
      ...result
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An error occurred during email verification'
    });
  }
});

// Forgot password endpoint
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const result = await forgotPassword(email);
    res.json(result);
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An error occurred during password reset request'
    });
  }
});

// Reset password endpoint
app.post('/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    const result = await confirmForgotPassword(email, newPassword, code);
    res.json({
      success: true,
      message: 'Password has been reset successfully',
      ...result
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An error occurred during password reset'
    });
  }
});

// Refresh tokens endpoint
app.post('/refresh-tokens', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const result = await refreshTokens(refreshToken);
    res.json(result);
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An error occurred during token refresh'
    });
  }
});

// Google Auth URL endpoint
app.get('/google/auth', (req, res) => {
  try {
    const state = require('crypto').randomBytes(16).toString('hex');
    const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;

    // Generate Google OAuth URL
    const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    googleAuthUrl.searchParams.append('client_id', process.env.GOOGLE_CLIENT_ID);
    googleAuthUrl.searchParams.append('redirect_uri', redirectUri);
    googleAuthUrl.searchParams.append('response_type', 'code');
    googleAuthUrl.searchParams.append('scope', 'email profile openid');
    googleAuthUrl.searchParams.append('state', state);

    res.json({
      success: true,
      authUrl: googleAuthUrl.toString(),
      state
    });
  } catch (error) {
    console.error('Google auth URL error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An error occurred while generating Google auth URL'
    });
  }
});

// Google callback endpoint
app.get('/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code) {
      return res.status(400).json({
        success: false,
        message: 'Authorization code is required'
      });
    }

    const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;
    const result = await processGoogleOAuth(code, redirectUri);

    // Redirect to frontend with tokens
    if (process.env.FRONTEND_URL) {
      const frontendUrl = process.env.FRONTEND_URL;
      const redirectUrl = new URL(frontendUrl);

      // Add user info and tokens to URL params for frontend to extract
      redirectUrl.searchParams.append('email', result.userInfo.email);

      if (result.googleTokens) {
        redirectUrl.searchParams.append('googleIdToken', result.googleTokens.id_token);
        redirectUrl.searchParams.append('googleAccessToken', result.googleTokens.access_token);
      }

      if (result.cognitoCredentials) {
        redirectUrl.searchParams.append('identityId', result.cognitoCredentials.IdentityId);
        redirectUrl.searchParams.append('accessKeyId', result.cognitoCredentials.Credentials.AccessKeyId);
        redirectUrl.searchParams.append('secretKey', result.cognitoCredentials.Credentials.SecretKey);
        redirectUrl.searchParams.append('sessionToken', result.cognitoCredentials.Credentials.SessionToken);
      }

      return res.redirect(redirectUrl.toString());
    }

    res.json({
      success: true,
      result
    });
  } catch (error) {
    console.error('Google callback error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'An error occurred during Google authentication'
    });
  }
});

// Handle Lambda invocation
exports.handler = serverless(app);
