require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const sqlite3 = require('sqlite3').verbose();
const csrf = require('csurf');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://js.stripe.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "https://api.stripe.com"],
      frameSrc: ["'self'", "https://js.stripe.com"],
    },
  },
}));

// CORS Configuration
app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = [
      process.env.CORS_ORIGIN,
      'https://charannapos.onrender.com',
      'http://localhost:3000'
    ].filter(Boolean);
    
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(bodyParser.json({ limit: '1mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '1mb' }));

// CSRF Protection
const csrfProtection = csrf({ 
  cookie: { 
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many payment attempts, please try again later.' }
});

app.use('/api/', limiter);
app.use('/api/create-payment-intent', paymentLimiter);
app.use('/api/capture-payment', paymentLimiter);

// Database Initialization - FIXED PATH FOR RENDER
const dbPath = process.env.NODE_ENV === 'production' ? '/tmp/transactions.db' : './transactions.db';
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    stripe_payment_intent_id TEXT UNIQUE,
    amount INTEGER NOT NULL,
    currency TEXT DEFAULT 'usd',
    status TEXT NOT NULL,
    capture_method TEXT NOT NULL,
    customer_name TEXT,
    customer_email TEXT,
    billing_address TEXT,
    metadata TEXT,
    is_moto BOOLEAN DEFAULT 0,
    approval_code TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    context TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Logging utility
const logger = {
  info: (message, context = {}) => {
    console.log(`[INFO] ${message}`, context);
    db.run(
      'INSERT INTO system_logs (level, message, context) VALUES (?, ?, ?)',
      ['info', message, JSON.stringify(context)]
    );
  },
  error: (message, error, context = {}) => {
    console.error(`[ERROR] ${message}`, error, context);
    db.run(
      'INSERT INTO system_logs (level, message, context) VALUES (?, ?, ?)',
      ['error', message, JSON.stringify({ ...context, error: error.message })]
    );
  },
  warn: (message, context = {}) => {
    console.warn(`[WARN] ${message}`, context);
    db.run(
      'INSERT INTO system_logs (level, message, context) VALUES (?, ?, ?)',
      ['warn', message, JSON.stringify(context)]
    );
  }
};

// Input validation schemas
const paymentIntentValidation = [
  body('amount')
    .isFloat({ min: 0.5, max: 999999.99 })
    .withMessage('Amount must be between $0.50 and $999,999.99'),
  body('currency')
    .isLength({ min: 3, max: 3 })
    .isUppercase()
    .withMessage('Currency must be a 3-letter ISO code'),
  body('capture_method')
    .isIn(['automatic', 'manual'])
    .withMessage('Capture method must be automatic or manual'),
  body('metadata')
    .optional()
    .isObject()
    .withMessage('Metadata must be a valid object')
];

const capturePaymentValidation = [
  body('paymentIntentId')
    .isLength({ min: 10, max: 50 })
    .matches(/^pi_[a-zA-Z0-9_]+$/)
    .withMessage('Valid Payment Intent ID required'),
  body('amount')
    .optional()
    .isFloat({ min: 0.5, max: 999999.99 })
    .withMessage('Amount must be between $0.50 and $999,999.99')
];

// Utility functions
function sanitizeInput(input) {
  if (typeof input === 'string') {
    return input.trim().replace(/[<>]/g, '');
  }
  return input;
}

function generateApprovalCode(prefix = 'APP') {
  return prefix + Math.random().toString(36).substring(2, 10).toUpperCase();
}

// Serve static files
app.use(express.static('client'));

// Apply CSRF protection to API routes
app.use(csrfProtection);

// Secure configuration endpoint
app.get('/api/config', (req, res) => {
  res.json({
    stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    backendUrl: process.env.BACKEND_URL || `http://localhost:${PORT}`,
    environment: process.env.NODE_ENV || 'development',
    csrfToken: req.csrfToken()
  });
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    db.get('SELECT 1 as test', (err) => {
      if (err) {
        logger.error('Database health check failed', err);
        return res.status(500).json({ 
          status: 'error', 
          timestamp: new Date().toISOString(),
          service: 'Cheranna SoftPOS API',
          database: 'unhealthy'
        });
      }

      res.json({ 
        status: 'online', 
        timestamp: new Date().toISOString(),
        service: 'Cheranna SoftPOS API',
        database: 'healthy',
        version: '1.0.0'
      });
    });
  } catch (error) {
    logger.error('Health check failed', error);
    res.status(500).json({ 
      status: 'error', 
      timestamp: new Date().toISOString(),
      service: 'Cheranna SoftPOS API'
    });
  }
});

// Create Payment Intent
app.post('/api/create-payment-intent', paymentIntentValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for payment intent', { errors: errors.array() });
      return res.status(400).json({ 
        error: 'Invalid input data', 
        details: errors.array() 
      });
    }

    const { amount, currency = 'usd', capture_method = 'automatic', metadata = {} } = req.body;

    const sanitizedAmount = Math.round(sanitizeInput(amount) * 100);
    const sanitizedCurrency = sanitizeInput(currency).toUpperCase();
    const sanitizedCaptureMethod = sanitizeInput(capture_method);

    if (!sanitizedAmount || sanitizedAmount < 50) {
      return res.status(400).json({ error: 'Valid amount required (minimum $0.50)' });
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount: sanitizedAmount,
      currency: sanitizedCurrency,
      capture_method: sanitizedCaptureMethod,
      metadata: {
        ...metadata,
        system: 'cheranna-softpos',
        timestamp: new Date().toISOString()
      }
    });

    const approvalCode = generateApprovalCode();

    const transactionData = {
      id: paymentIntent.id + '_' + Date.now(),
      stripe_payment_intent_id: paymentIntent.id,
      amount: sanitizedAmount,
      currency: sanitizedCurrency,
      status: paymentIntent.status,
      capture_method: sanitizedCaptureMethod,
      customer_email: metadata.customer_email || '',
      customer_name: metadata.customer_name || '',
      billing_address: JSON.stringify(metadata.billing_address || {}),
      metadata: JSON.stringify(metadata),
      is_moto: metadata.is_moto === 'true' ? 1 : 0,
      approval_code: approvalCode
    };

    db.run(
      `INSERT INTO transactions (
        id, stripe_payment_intent_id, amount, currency, status, 
        capture_method, customer_email, customer_name, billing_address, 
        metadata, is_moto, approval_code
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        transactionData.id,
        transactionData.stripe_payment_intent_id,
        transactionData.amount,
        transactionData.currency,
        transactionData.status,
        transactionData.capture_method,
        transactionData.customer_email,
        transactionData.customer_name,
        transactionData.billing_address,
        transactionData.metadata,
        transactionData.is_moto,
        transactionData.approval_code
      ],
      function(err) {
        if (err) {
          logger.error('Failed to store transaction', err, { paymentIntentId: paymentIntent.id });
        } else {
          logger.info('Transaction stored successfully', { 
            paymentIntentId: paymentIntent.id,
            transactionId: transactionData.id
          });
        }
      }
    );

    logger.info('Payment intent created successfully', {
      paymentIntentId: paymentIntent.id,
      amount: sanitizedAmount,
      capture_method: sanitizedCaptureMethod
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      status: paymentIntent.status,
      approvalCode: approvalCode
    });

  } catch (error) {
    logger.error('Payment intent creation failed', error, { body: req.body });
    res.status(400).json({ 
      error: error.message,
      code: error.code || 'payment_intent_error'
    });
  }
});

// Capture Payment Intent
app.post('/api/capture-payment', capturePaymentValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Invalid input data', 
        details: errors.array() 
      });
    }

    const { paymentIntentId, amount } = req.body;

    const sanitizedPaymentIntentId = sanitizeInput(paymentIntentId);
    const sanitizedAmount = amount ? Math.round(sanitizeInput(amount) * 100) : undefined;

    db.get(
      'SELECT * FROM transactions WHERE stripe_payment_intent_id = ?',
      [sanitizedPaymentIntentId],
      async (err, transaction) => {
        if (err) {
          logger.error('Database error checking transaction', err, { paymentIntentId: sanitizedPaymentIntentId });
          return res.status(500).json({ error: 'Database error' });
        }

        if (!transaction) {
          return res.status(404).json({ error: 'Transaction not found' });
        }

        if (transaction.status !== 'requires_capture') {
          return res.status(400).json({ error: 'Payment intent cannot be captured' });
        }

        try {
          const captureAmount = sanitizedAmount ? { amount_to_capture: sanitizedAmount } : {};
          const paymentIntent = await stripe.paymentIntents.capture(
            sanitizedPaymentIntentId,
            captureAmount
          );

          db.run(
            'UPDATE transactions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE stripe_payment_intent_id = ?',
            [paymentIntent.status, sanitizedPaymentIntentId],
            function(updateErr) {
              if (updateErr) {
                logger.error('Failed to update transaction status', updateErr, { paymentIntentId: sanitizedPaymentIntentId });
              } else {
                logger.info('Transaction status updated', {
                  paymentIntentId: sanitizedPaymentIntentId,
                  newStatus: paymentIntent.status
                });
              }
            }
          );

          const captureApprovalCode = generateApprovalCode('CAP');

          logger.info('Payment captured successfully', {
            paymentIntentId: sanitizedPaymentIntentId,
            amount_captured: paymentIntent.amount_captured
          });

          res.json({
            success: true,
            paymentIntentId: paymentIntent.id,
            status: paymentIntent.status,
            amount_captured: paymentIntent.amount_captured / 100,
            approval_code: captureApprovalCode
          });

        } catch (stripeError) {
          logger.error('Stripe capture failed', stripeError, { paymentIntentId: sanitizedPaymentIntentId });
          res.status(400).json({ 
            error: stripeError.message,
            code: stripeError.code || 'capture_error'
          });
        }
      }
    );

  } catch (error) {
    logger.error('Capture payment failed', error, { body: req.body });
    res.status(400).json({ 
      error: error.message,
      code: error.code || 'capture_error'
    });
  }
});

// Get transactions with filtering
app.get('/api/transactions', async (req, res) => {
  try {
    const { status, limit = 50, offset = 0 } = req.query;
    
    let query = 'SELECT * FROM transactions';
    let params = [];
    
    if (status) {
      query += ' WHERE status = ?';
      params.push(sanitizeInput(status));
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    db.all(query, params, (err, transactions) => {
      if (err) {
        logger.error('Failed to fetch transactions', err);
        return res.status(500).json({ error: 'Database error' });
      }

      const formattedTransactions = transactions.map(tx => ({
        id: tx.stripe_payment_intent_id,
        amount: tx.amount / 100,
        status: tx.status,
        capture_method: tx.capture_method,
        created: Math.floor(new Date(tx.created_at).getTime() / 1000),
        currency: tx.currency,
        metadata: JSON.parse(tx.metadata || '{}'),
        approval_code: tx.approval_code,
        customer_email: tx.customer_email,
        is_moto: tx.is_moto === 1
      }));

      logger.info('Transactions fetched successfully', { count: formattedTransactions.length });
      res.json(formattedTransactions);
    });

  } catch (error) {
    logger.error('Get transactions failed', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Webhook handler for Stripe events
app.post('/webhook', bodyParser.raw({type: 'application/json'}), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.WEBHOOK_SECRET_KEY);
  } catch (err) {
    logger.error('Webhook signature verification failed', err);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'payment_intent.succeeded':
      handlePaymentIntentSucceeded(event.data.object);
      break;
    case 'payment_intent.payment_failed':
      handlePaymentIntentFailed(event.data.object);
      break;
    case 'payment_intent.canceled':
      handlePaymentIntentCanceled(event.data.object);
      break;
    case 'payment_intent.amount_capturable_updated':
      handlePaymentIntentAmountCapturableUpdated(event.data.object);
      break;
    default:
      logger.info(`Unhandled event type: ${event.type}`, { eventId: event.id });
  }

  res.json({received: true});
});

// Webhook event handlers
function handlePaymentIntentSucceeded(paymentIntent) {
  db.run(
    'UPDATE transactions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE stripe_payment_intent_id = ?',
    [paymentIntent.status, paymentIntent.id],
    function(err) {
      if (err) {
        logger.error('Failed to update transaction status for succeeded payment', err, {
          paymentIntentId: paymentIntent.id
        });
      } else {
        logger.info('Transaction status updated to succeeded', {
          paymentIntentId: paymentIntent.id
        });
      }
    }
  );
}

function handlePaymentIntentFailed(paymentIntent) {
  db.run(
    'UPDATE transactions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE stripe_payment_intent_id = ?',
    [paymentIntent.status, paymentIntent.id],
    function(err) {
      if (err) {
        logger.error('Failed to update transaction status for failed payment', err, {
          paymentIntentId: paymentIntent.id
        });
      } else {
        logger.info('Transaction status updated to failed', {
          paymentIntentId: paymentIntent.id,
          lastError: paymentIntent.last_payment_error
        });
      }
    }
  );
}

function handlePaymentIntentCanceled(paymentIntent) {
  db.run(
    'UPDATE transactions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE stripe_payment_intent_id = ?',
    [paymentIntent.status, paymentIntent.id],
    function(err) {
      if (err) {
        logger.error('Failed to update transaction status for canceled payment', err, {
          paymentIntentId: paymentIntent.id
        });
      } else {
        logger.info('Transaction status updated to canceled', {
          paymentIntentId: paymentIntent.id
        });
      }
    }
  );
}

function handlePaymentIntentAmountCapturableUpdated(paymentIntent) {
  db.run(
    'UPDATE transactions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE stripe_payment_intent_id = ?',
    [paymentIntent.status, paymentIntent.id],
    function(err) {
      if (err) {
        logger.error('Failed to update transaction status for capturable payment', err, {
          paymentIntentId: paymentIntent.id
        });
      } else {
        logger.info('Transaction status updated to requires_capture', {
          paymentIntentId: paymentIntent.id
        });
      }
    }
  );
}

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error('Unhandled error', error, {
    path: req.path,
    method: req.method,
    ip: req.ip
  });

  res.status(500).json({
    error: 'Internal server error',
    reference: `ERR-${Date.now()}`
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.path
  });
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'client', 'index.html'));
});

// Graceful shutdown
process.on('SIGINT', () => {
  logger.info('Server shutting down gracefully');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
      process.exit(1);
    } else {
      console.log('Database connection closed');
      process.exit(0);
    }
  });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Cheranna SoftPOS server running on port ${PORT}`, {
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});
