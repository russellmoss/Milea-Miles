// Polyfill Object.hasOwn if it doesn't exist.
if (typeof Object.hasOwn !== 'function') {
  Object.hasOwn = function(obj, prop) {
    return Object.prototype.hasOwnProperty.call(obj, prop);
  };
}

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

const app = express();

app.use(cookieParser());

// ---------------- Security Middleware ----------------

// Set secure HTTP headers.
app.use( helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      // Allow images from self, data URIs, and i.imgur.com:
      imgSrc: ["'self'", "data:", "https://i.imgur.com"],
      // You can add other directives as needed:
      frameAncestors: ["'self'", "https://mileaestatevineyard.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

// Enable CORS only for allowed origins.
const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));

// Parse incoming JSON bodies.
app.use(express.json());

// Serve static files (including index.html and create-account.html).
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting for authentication endpoints.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: "Too many authentication attempts from this IP, please try again after 15 minutes",
});

// ---------------- Environment Variables ----------------

const PORT = process.env.PORT || 3001;
const APP_ID = process.env.APP_ID;
const SECRET_KEY = process.env.SECRET_KEY;
const KLAVIYO_PUBLIC_KEY = process.env.KLAVIYO_PUBLIC_KEY;
const TENANT_ID = process.env.TENANT_ID;
const C7_API_BASE = 'https://api.commerce7.com/v1';
const PROMOTION_ID = "a7623848-13ea-4b4e-9ae8-0f2799414f2c";
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";


// ---------------- JWT Helper Functions ----------------

// Generate a JWT token (valid for 1 hour)
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '3h' });
}

// ---------------- Authentication Middleware ----------------

/**
 * Checks the request for a valid JWT.
 * If missing/invalid, and if the request accepts HTML, redirect to the login page ("/").
 * Otherwise, respond with a JSON error.
 */
function checkAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return req.accepts('html')
      ? res.redirect('/')
      : res.status(401).json({ error: 'Unauthorized' });
  }
  const token = authHeader.split(' ')[1];
  if (!token) {
    return req.accepts('html')
      ? res.redirect('/')
      : res.status(401).json({ error: 'Unauthorized' });
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return req.accepts('html')
        ? res.redirect('/')
        : res.status(403).json({ error: 'Invalid or expired token' });
    }
    // Attach decoded user info to the request.
    req.user = decoded;
    next();
  });
}

// ---------------- Global Protection ----------------

// Define public paths (only login and the root static assets are public).
const publicPaths = ['/auth/login', '/'];

// All endpoints not matching the public paths will be protected.
app.use((req, res, next) => {
  if (publicPaths.includes(req.path)) {
    return next();
  }
  return checkAuth(req, res, next);
});

// ---------------- Endpoints ----------------

// --- Login Endpoint (public) ---
app.post('/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

    // Fetch customer by email
    const searchResponse = await axios.get(`${C7_API_BASE}/customer`, {
      params: { q: email },
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });

    const customer = searchResponse.data.customers?.[0];
    if (!customer) {
      return res.status(404).json({ message: 'Customer not found.' });
    }

    // (Optional) Validate the password if available.

    // Generate a JWT token with essential customer info.
    const token = generateToken({
      id: customer.id,
      email,
      firstName: customer.firstName,
      lastName: customer.lastName,
    });

    return res.status(200).json({
      message: 'Login successful.',
      token,
      user: {
        id: customer.id,
        firstName: customer.firstName,
        lastName: customer.lastName,
        loyaltyPoints: customer.loyalty?.points || 0,
      },
    });
  } catch (error) {
    console.error('Error logging in:', error.response?.data || error.message);
    return res.status(error.response?.status || 500).json({
      message: 'Error logging in.',
      error: error.response?.data || error.message,
    });
  }
});

// --- Create Account Endpoint (protected) ---
// Even though the create-account page is public, this endpoint is locked down.
app.post('/create-account', authLimiter, async (req, res) => {
  const { firstName, lastName, email, password, emailMarketingStatus, metaData } = req.body;
  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

    // Check if customer already exists.
    const searchResponse = await axios.get(`${C7_API_BASE}/customer`, {
      params: { q: email },
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    const existingCustomer = searchResponse.data.customers?.[0];
    if (existingCustomer) {
      return res.status(409).json({
        message: 'Customer already exists.',
        customer: existingCustomer,
      });
    }

    // Create new customer profile.
    const createResponse = await axios.post(`${C7_API_BASE}/customer`, {
      firstName,
      lastName,
      emails: [{ email }],
      emailMarketingStatus,
      metaData,
    }, {
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });

    const newCustomer = createResponse.data;
    return res.status(201).json({
      message: 'Account created successfully.',
      customer: newCustomer,
    });
  } catch (error) {
    console.error('Error creating account:', error.response?.data || error.message);
    return res.status(error.response?.status || 500).json({
      message: 'Error creating account.',
      error: error.response?.data || error.message,
    });
  }
});

// --- Referral Tasting (protected) ---
app.post('/referral', async (req, res) => {
  const { referrerId, referrerEmail, referrerName, firstName, lastName, email } = req.body;
  if (!referrerId || !referrerEmail || !referrerName || !firstName || !lastName || !email) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

    // Step 1: Process the referred customer.
    let customer;
    const searchResponse = await axios.get(`${C7_API_BASE}/customer`, {
      params: { q: email },
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    const existingCustomer = searchResponse.data.customers?.[0];

    if (existingCustomer) {
      // Update existing customer metadata.
      await axios.put(`${C7_API_BASE}/customer/${existingCustomer.id}`, {
        metaData: {
          ...existingCustomer.metaData,
          referrername: referrerName,
          referrer_email: referrerEmail,
          referral: 'referral',
          referral_tasting_redeemed: false,
        },
      }, {
        headers: {
          Authorization: basicAuth,
          'Content-Type': 'application/json',
          Tenant: TENANT_ID,
        },
      });
      customer = existingCustomer;
    } else {
      // Create a new referred customer.
      const createResponse = await axios.post(`${C7_API_BASE}/customer`, {
        firstName,
        lastName,
        emails: [{ email }],
        emailMarketingStatus: 'Subscribed',
        metaData: {
          referrername: referrerName,
          referrer_email: referrerEmail,
          referral: 'referral',
          referral_tasting_redeemed: false,
        },
      }, {
        headers: {
          Authorization: basicAuth,
          'Content-Type': 'application/json',
          Tenant: TENANT_ID,
        },
      });
      customer = createResponse.data;
    }

    // Step 2: Update the referrer's metadata.
    try {
      const referrerResponse = await axios.get(`${C7_API_BASE}/customer`, {
        params: { q: referrerEmail },
        headers: {
          Authorization: basicAuth,
          'Content-Type': 'application/json',
          Tenant: TENANT_ID,
        },
      });
      const referrer = referrerResponse.data.customers?.[0];
      if (referrer) {
        const currentReferrals = referrer.metaData?.referrals || '';
        const updatedReferrals = currentReferrals + email + ',';
        await axios.put(`${C7_API_BASE}/customer/${referrer.id}`, {
          metaData: { ...referrer.metaData, referrals: updatedReferrals },
        }, {
          headers: {
            Authorization: basicAuth,
            'Content-Type': 'application/json',
            Tenant: TENANT_ID,
          },
        });
      } else {
        console.warn(`Referrer with email ${referrerEmail} not found.`);
      }
    } catch (referrerError) {
      console.error('Error updating referrer metadata:', referrerError.response?.data || referrerError.message);
    }

    const statusCode = existingCustomer ? 200 : 201;
    const message = existingCustomer
      ? 'Referral tasting updated successfully for existing customer.'
      : 'Referral tasting created successfully for new customer.';
    return res.status(statusCode).json({ message, customer });
  } catch (error) {
    console.error('Error sending referral tasting:', error.response?.data || error.message);
    return res.status(error.response?.status || 500).json({
      message: 'Error sending referral tasting.',
      error: error.response?.data || error.message,
    });
  }
});

// --- Get Referrals (protected) ---
app.get('/api/referrals', async (req, res) => {
  const userEmail = req.query.email;
  if (!userEmail) {
    return res.status(400).json({ error: 'Missing email parameter.' });
  }

  // Sanitize the email to create a safe cookie name.
  const safeEmail = userEmail.replace(/[^a-zA-Z0-9]/g, '_');
  const cookieKey = `referrals_${safeEmail}`;

  // Check if we already have a cached value in the cookie.
  if (req.cookies[cookieKey]) {
    try {
      const cachedData = JSON.parse(req.cookies[cookieKey]);
      //console.log('Returning cached referrals for', userEmail);
      return res.json({ referrals: cachedData });
    } catch (err) {
      console.error("Error parsing cached referrals cookie:", err);
      // If parsing fails, we proceed to fetch fresh data.
    }
  }

  const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

  try {
    // Fetch customer details.
    const customerResponse = await axios.get(`${C7_API_BASE}/customer`, {
      params: { q: userEmail },
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    const customer = customerResponse.data.customers?.[0];
    if (!customer) {
      return res.status(404).json({ error: 'Customer not found.' });
    }
    let referralsStr = customer.metaData?.referrals;
    if (!referralsStr) {
      // Cache an empty array in the cookie and return.
      res.cookie(cookieKey, JSON.stringify([]), { maxAge: 1 * 60 * 1000 });
      return res.json({ referrals: [] });
    }
    if (referralsStr.endsWith(',')) {
      referralsStr = referralsStr.slice(0, -1);
    }
    const referralEmails = referralsStr.split(',').filter(email => email.trim() !== '');

    const referralsData = await Promise.all(referralEmails.map(async (refEmail, index) => {
      let metaRedeemed = false;
      let promotionRedeemed = false;
      let referredCustomer = null;
      // Fetch referred customer data.
      await delay(index * 250);
      try {
        const refCustomerResponse = await axios.get(`${C7_API_BASE}/customer`, {
          params: { q: refEmail },
          headers: {
            Authorization: basicAuth,
            'Content-Type': 'application/json',
            Tenant: TENANT_ID,
          },
        });
        referredCustomer = refCustomerResponse.data.customers?.[0];
        if (referredCustomer && referredCustomer.metaData &&
            typeof referredCustomer.metaData.referral_tasting_redeemed !== 'undefined') {
          metaRedeemed = referredCustomer.metaData.referral_tasting_redeemed;
        }
      } catch (error) {
        console.error(`Error fetching customer data for ${refEmail}:`, error.message);
      }
      // Check orders for promotion redemption.
      try {
        let ordersResponse;
        if (referredCustomer && referredCustomer.id) {
          ordersResponse = await axios.get(`${C7_API_BASE}/order`, {
            params: { customerId: referredCustomer.id },
            headers: {
              Authorization: basicAuth,
              'Content-Type': 'application/json',
              Tenant: TENANT_ID,
            },
          });
        } else {
          ordersResponse = await axios.get(`${C7_API_BASE}/order`, {
            params: { q: refEmail },
            headers: {
              Authorization: basicAuth,
              'Content-Type': 'application/json',
              Tenant: TENANT_ID,
            },
          });
        }
        const orders = ordersResponse.data.orders || ordersResponse.data || [];
        if (orders && orders.length > 0) {
          for (const order of orders) {
            if (order.promotions && Array.isArray(order.promotions)) {
              if (order.promotions.some(promo => promo.promotionId === PROMOTION_ID)) {
                promotionRedeemed = true;
                break;
              }
            }
          }
        } else {
          console.warn(`No orders found for ${refEmail}.`);
        }
      } catch (error) {
        console.error(`Error fetching orders for ${refEmail}:`, error.response?.data || error.message);
      }
      return [refEmail, metaRedeemed, promotionRedeemed];
    }));

    // Cache the referrals data in a cookie for 5 minutes.
    res.cookie(cookieKey, JSON.stringify(referralsData), { maxAge: 1 * 60 * 1000, httpOnly: false });
    return res.json({ referrals: referralsData });
  } catch (error) {
    console.error('Error fetching referrals:', error.message);
    return res.status(500).json({ error: 'Failed to fetch referrals.' });
  }
});

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// --- Update Loyalty (protected) ---
app.post('/api/update-loyalty', async (req, res) => {
  const { referrerEmail, referreeEmail } = req.body;
  if (!referrerEmail || !referreeEmail) {
    return res.status(400).json({ error: 'Both referrer and referree emails are required.' });
  }
  const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

  try {
    // Retrieve the referrer customer record.
    const customerResponse = await axios.get(`${C7_API_BASE}/customer`, {
      params: { q: referrerEmail },
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    const customer = customerResponse.data.customers?.[0];
    if (!customer) {
      return res.status(404).json({ error: 'Referrer not found.' });
    }

    // Retrieve the referree customer record.
    const referreeResponse = await axios.get(`${C7_API_BASE}/customer`, {
      params: { q: referreeEmail },
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    const referree = referreeResponse.data.customers?.[0];
    if (!referree) {
      return res.status(404).json({ error: 'Referree not found.' });
    }

    // Add 10 loyalty points.
    try {
      const loyaltyResponse = await axios.post(`${C7_API_BASE}/loyalty-transaction`, {
        customerId: customer.id,
        amount: 10,
        notes: "Referral reward for redeemed tasting promotion",
      }, {
        headers: {
          Authorization: basicAuth,
          'Content-Type': 'application/json',
          Tenant: TENANT_ID,
        },
      });
      console.log(`Loyalty points added for ${referrerEmail}:`, loyaltyResponse.data);
    } catch (loyaltyError) {
      console.error('Error adding loyalty points:', loyaltyError.response?.data || loyaltyError.message);
      return res.status(500).json({ error: 'Failed to update loyalty points.' });
    }

    // Update the referree's metadata.
    try {
      await axios.put(`${C7_API_BASE}/customer/${referree.id}`, {
        metaData: {
          ...referree.metaData,
          referral_tasting_redeemed: true,
        },
      }, {
        headers: {
          Authorization: basicAuth,
          'Content-Type': 'application/json',
          Tenant: TENANT_ID,
        },
      });
      console.log(`Updated referral_tasting_redeemed for ${referreeEmail}`);
    } catch (metaUpdateError) {
      console.error('Error updating referral meta:', metaUpdateError.response?.data || metaUpdateError.message);
      return res.status(500).json({ error: 'Failed to update referral redemption status.' });
    }

    return res.json({ success: true, message: 'Loyalty points added and referral marked as redeemed.' });
  } catch (error) {
    console.error('Error updating loyalty points:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Failed to update loyalty points.' });
  }
});

// --- Get Loyalty Points (protected) ---
app.get('/api/loyalty-points', async (req, res) => {
  const userEmail = req.query.email;
  if (!userEmail) {
    return res.status(400).json({ error: 'Missing email parameter.' });
  }

  // Sanitize email for a safe cookie name (replace non-alphanumeric with underscores)
  const safeEmail = userEmail.replace(/[^a-zA-Z0-9]/g, '_');
  const cookieKey = `loyaltyPoints_${safeEmail}`;

  // Check if the cookie exists and is a valid number.
  if (req.cookies[cookieKey]) {
    const cachedPoints = parseInt(req.cookies[cookieKey], 10);
    if (!isNaN(cachedPoints)) {
      //console.log('Returning cached loyalty points for', userEmail);
      return res.json({ points: cachedPoints });
    }
  }

  const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

  try {
    // Fetch customer details.
    const customerResponse = await axios.get(`${C7_API_BASE}/customer`, {
      params: { q: userEmail },
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    const customer = customerResponse.data.customers?.[0];
    if (!customer) {
      return res.status(404).json({ error: 'Customer not found.' });
    }

    // Fetch all loyalty transactions using page-based pagination.
    let page = 1;
    const limit = 50; // Adjust limit if necessary.
    let allTransactions = [];
    let fetchedTransactions = [];

    do {
      const loyaltyResponse = await axios.get(`${C7_API_BASE}/loyalty-transaction`, {
        params: { customerId: customer.id, limit, page },
        headers: {
          Authorization: basicAuth,
          'Content-Type': 'application/json',
          Tenant: TENANT_ID,
        },
      });
      // Assume the API returns an array in loyaltyTransactions.
      fetchedTransactions = loyaltyResponse.data.loyaltyTransactions || [];
      allTransactions = allTransactions.concat(fetchedTransactions);
      page++; // Move to the next page.
    } while (fetchedTransactions.length === limit); // Continue if we got a full page.

    // Sum up the "amount" from all transactions.
    const totalPoints = allTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);

    // Cache the total points in a cookie for 5 minutes (300000 milliseconds).
    res.cookie(cookieKey, totalPoints.toString(), { maxAge: 1 * 60 * 1000, httpOnly: false });

    return res.json({ points: totalPoints });
  } catch (error) {
    console.error('Error fetching loyalty points:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Failed to fetch loyalty points.' });
  }
});



// --- Update Instagram (protected) ---
app.post('/api/update-instagram', async (req, res) => {
  const { userEmail, instagramHandle } = req.body;
  if (!userEmail || !instagramHandle) {
    return res.status(400).json({ error: 'Both userEmail and instagramHandle are required.' });
  }
  const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

  try {
    const customerResponse = await axios.get(`${C7_API_BASE}/customer`, {
      params: { q: userEmail },
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    const customer = customerResponse.data.customers?.[0];
    if (!customer) {
      return res.status(404).json({ error: 'Customer not found.' });
    }
    const updatedMetaData = {
      ...customer.metaData,
      instagram_handle: instagramHandle,
    };
    const updateResponse = await axios.put(`${C7_API_BASE}/customer/${customer.id}`, {
      metaData: updatedMetaData,
    }, {
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    console.log('Instagram handle update response:', updateResponse.data);
    return res.json({ success: true, message: 'Instagram handle updated successfully.' });
  } catch (error) {
    console.error('Error updating instagram handle:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Failed to update instagram handle.' });
  }
});

// --- Get Instagram (protected) ---
app.get('/api/get-instagram', async (req, res) => {
  const userEmail = req.query.email;
  if (!userEmail) {
    return res.status(400).json({ error: 'Missing email parameter.' });
  }

  // Check if the instagramHandle cookie exists.
  // (Optionally, you might use a cookie key that includes the email if users share the same domain.)
  if (req.cookies.instagramHandle) {
    return res.json({ instagramHandle: req.cookies.instagramHandle });
  }

  const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

  try {
    const customerResponse = await axios.get(`${C7_API_BASE}/customer`, {
      params: { q: userEmail },
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    const customer = customerResponse.data.customers?.[0];
    if (!customer) {
      return res.status(404).json({ error: 'Customer not found.' });
    }

    // Extract the Instagram handle from the customer's meta.
    const instagramHandle = customer.metaData?.instagram_handle || "";

    // Set a cookie with the instagram handle.
    // Adjust options as needed; for example, you might want to set httpOnly to false if client-side scripts need to read it.
    res.cookie('instagramHandle', instagramHandle, { maxAge: ( 24 * 60 * 60 * 1000 ) * 30 }); // 1 day expiration

    return res.json({ instagramHandle });
  } catch (error) {
    console.error('Error fetching instagram handle:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Failed to fetch instagram handle.' });
  }
});


// --- Submit Contact Form (protected) ---
app.post('/api/submit-contact-form', async (req, res) => {
  const { email, message } = req.body;
  if (!email || !message) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const klaviyoEvent = {
      data: {
        type: "event",
        attributes: {
          properties: {
            "Subject": "Point Dashboard - Contact Form Submission",
            "Message": message
          },
          metric: {
            data: {
              type: "metric",
              attributes: {
                "name": "Point Dashboard - Contact Form Submission"
              }
            }
          },
          profile: {
            data: {
              type: "profile",
              attributes: {
                properties: {
                  "$email": email
                }
              }
            }
          }
        }
      }
    };

    const response = await axios.post("https://a.klaviyo.com/api/events", klaviyoEvent, {
      headers: {
        "Authorization": `Klaviyo-API-Key ${process.env.KLAVIYO_PRIVATE_KEY}`,
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
        "Revision": "2025-01-15"
      }
    });
    //console.log("Klaviyo Response:", response.data);
    return res.json({ success: true, message: "Form submitted successfully." });
  } catch (error) {
    console.error("Error sending event to Klaviyo:", error.response?.data || error.message);
    return res.status(500).json({ error: "Failed to submit form." });
  }
});

// ---------------- Start the Server ----------------

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
