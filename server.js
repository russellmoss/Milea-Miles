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
const fs = require('fs');

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

const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(",").map(origin => origin.trim())
  : 'http://localhost:3000';


// Enable CORS only for allowed origins.
const corsOptions = {
  origin: allowedOrigins.length === 1 ? allowedOrigins[0] : allowedOrigins, // Handle single & multiple origins
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));

// Parse incoming JSON bodies.
app.use(express.json());
app.set('trust proxy', 1);


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
const INSTAGRAM_ACCESS_TOKEN = process.env.INSTAGRAM_ACCESS_TOKEN;
const INSTAGRAM_BUSINESS_ID = process.env.INSTAGRAM_BUSINESS_ID;
const WEBHOOK_VERIFY_TOKEN = process.env.WEBHOOK_VERIFY_TOKEN;
const INSTAGRAM_APP_SECRET = process.env.INSTAGRAM_APP_SECRET;

// ---------------- Instagram Handle Database ----------------

// File path for database persistence
const INSTAGRAM_DB_FILE = path.join(__dirname, 'instagram_handle_database.json');

// In-memory database of Instagram handles to customer IDs
const instagramHandleMap = new Map();
let lastDatabaseUpdateTime = null;
let isDatabaseBuilding = false;
let databaseBuildStatus = {
  lastStarted: null,
  currentProgress: "Not started",
  handlesFound: 0
};

// Function to save the Instagram handle database to a file
function saveInstagramHandleDatabase() {
  try {
    const dbObject = {
      lastUpdated: lastDatabaseUpdateTime,
      handles: [...instagramHandleMap.entries()].map(([handle, customer]) => ({
        handle,
        customer
      }))
    };
    
    fs.writeFileSync(INSTAGRAM_DB_FILE, JSON.stringify(dbObject, null, 2));
    console.log(`Instagram handle database saved to file: ${INSTAGRAM_DB_FILE}`);
    console.log(`Contains ${instagramHandleMap.size} Instagram handles`);
  } catch (error) {
    console.error('Error saving Instagram handle database to file:', error);
  }
}

// Function to load the Instagram handle database from a file
function loadInstagramHandleDatabase() {
  try {
    if (!fs.existsSync(INSTAGRAM_DB_FILE)) {
      console.log('No Instagram handle database file found. Will build from scratch.');
      return false;
    }
    
    // Check if file is empty
    const stats = fs.statSync(INSTAGRAM_DB_FILE);
    if (stats.size === 0) {
      console.log('Instagram handle database file is empty. Will build from scratch.');
      return false;
    }
    
    console.log(`Found Instagram database file at ${INSTAGRAM_DB_FILE} with size ${stats.size} bytes`);
    
    try {
      const fileData = fs.readFileSync(INSTAGRAM_DB_FILE, 'utf8');
      
      // Quick validation check before parsing
      if (fileData.trim().startsWith('<') || !fileData.trim().startsWith('{')) {
        console.error('Database file appears to be corrupted (contains HTML or non-JSON content)');
        
        // Log a small preview of the file content to help diagnose the issue
        console.error(`File content preview: ${fileData.substring(0, 100)}...`);
        
        // Rename the corrupt file rather than deleting it
        const backupPath = `${INSTAGRAM_DB_FILE}.corrupt.${Date.now()}`;
        fs.renameSync(INSTAGRAM_DB_FILE, backupPath);
        console.log(`Renamed corrupt database file to ${backupPath}`);
        
        return false;
      }
      
      const dbObject = JSON.parse(fileData);
      
      // Clear existing data
      instagramHandleMap.clear();
      
      // Load handles into map
      if (dbObject.handles && Array.isArray(dbObject.handles)) {
        dbObject.handles.forEach(item => {
          if (item.handle && item.customer) {
            instagramHandleMap.set(item.handle, item.customer);
          }
        });
        
        console.log(`Successfully loaded ${instagramHandleMap.size} handles into memory`);
      } else {
        console.error('Database file is missing the "handles" array property');
        return false;
      }
      
      if (dbObject.lastUpdated) {
        lastDatabaseUpdateTime = new Date(dbObject.lastUpdated);
        console.log(`Database was last updated on: ${lastDatabaseUpdateTime}`);
      } else {
        lastDatabaseUpdateTime = new Date();
        console.log('No lastUpdated timestamp found, using current time');
      }
      
      // Override stale check with environment variable if present
      const forceUseFile = process.env.FORCE_USE_DB_FILE === 'true';
      
      // Make stale check more lenient - 7 days instead of 1
      const isStale = (new Date() - lastDatabaseUpdateTime) > (7 * 24 * 60 * 60 * 1000);
      
      if (isStale && !forceUseFile) {
        console.log(`Database is older than 7 days (last updated: ${lastDatabaseUpdateTime.toISOString()}). Will rebuild to ensure it's up to date.`);
        return false;
      }
      
      console.log(`Loaded Instagram handle database from file. Contains ${instagramHandleMap.size} handles.`);
      databaseBuildStatus.currentProgress = "Loaded from file";
      databaseBuildStatus.handlesFound = instagramHandleMap.size;
      
      return true;
    } catch (parseError) {
      console.error('Error parsing Instagram handle database file:', parseError);
      
      try {
        // Read raw file content to examine what's wrong
        const fileContent = fs.readFileSync(INSTAGRAM_DB_FILE, 'utf8');
        const preview = fileContent.length > 200 ? fileContent.substring(0, 200) + '...' : fileContent;
        console.error(`File content appears to be invalid. First 200 chars: ${preview}`);
        
        // Rename the corrupt file instead of deleting it outright
        const backupPath = `${INSTAGRAM_DB_FILE}.corrupt.${Date.now()}`;
        fs.renameSync(INSTAGRAM_DB_FILE, backupPath);
        console.log(`Renamed corrupt database file to ${backupPath} for later inspection`);
      } catch (backupError) {
        console.error('Failed to backup corrupt file:', backupError);
        
        // If rename fails, try to delete the file
        try {
          fs.unlinkSync(INSTAGRAM_DB_FILE);
          console.log(`Deleted corrupt database file: ${INSTAGRAM_DB_FILE}`);
        } catch (deleteError) {
          console.error('Failed to delete corrupt file:', deleteError);
        }
      }
      
      return false;
    }
  } catch (error) {
    console.error('Error loading Instagram handle database from file:', error);
    return false;
  }
}

// Function to build the Instagram handle database
async function buildInstagramHandleDatabase() {
  // First check if we can load from file
  if (loadInstagramHandleDatabase()) {
    console.log('Successfully loaded Instagram handle database from file. Skipping build.');
    databaseBuildStatus.currentProgress = "Loaded from file";
    databaseBuildStatus.handlesFound = instagramHandleMap.size;
    return;
  }
  
  if (isDatabaseBuilding) {
    console.log('Instagram database build already in progress');
    return;
  }

  isDatabaseBuilding = true;
  databaseBuildStatus = {
    lastStarted: new Date(),
    currentProgress: "Building in progress",
    handlesFound: 0
  };
  console.log('Starting to build Instagram handle database...');
  
  const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;
  const batchSize = 50; // Reduced batch size to be more conservative
  let page = 1;
  let hasMore = true;
  let totalProcessed = 0;
  let customersWithInstagram = 0;
  
  try {
    while (hasMore) {
      console.log(`Fetching customer batch ${page} (${batchSize} customers per batch)`);
      databaseBuildStatus.currentProgress = `Processing batch ${page} (${totalProcessed} customers so far, ${customersWithInstagram} handles found)`;
      
      try {
        // Commerce7 may have issues with the offset/limit approach
        // Let's use createdAt as a filter to get all customers
        const response = await axios.get(`${C7_API_BASE}/customer`, {
          params: { 
            limit: batchSize,
            page: page,
            sort: 'createdAt' // Sort by creation date to have a consistent ordering
          },
          headers: {
            Authorization: basicAuth,
            'Content-Type': 'application/json',
            Tenant: TENANT_ID,
          },
        });
        
        const customers = response.data.customers || [];
        totalProcessed += customers.length;
        
        // If we got fewer customers than the batch size, we're done
        if (customers.length < batchSize) {
          hasMore = false;
        }
        
        console.log(`Processing ${customers.length} customers from batch ${page}`);
        
        // Store customers with Instagram handles in our map
        for (const customer of customers) {
          if (customer.metaData && customer.metaData.instagram_handle) {
            const instagramHandle = customer.metaData.instagram_handle;
            
            // Store customer info in our map
            instagramHandleMap.set(instagramHandle.toLowerCase(), {
              id: customer.id,
              email: customer.emails[0]?.email,
              fullHandle: instagramHandle,
              points: customer.loyalty?.points || 0
            });
            
            customersWithInstagram++;
          }
        }
        
        databaseBuildStatus.handlesFound = customersWithInstagram;
        
        page++;
        
        // Save database to file after each batch to ensure we don't lose progress
        if (page % 5 === 0 && customersWithInstagram > 0) {
          lastDatabaseUpdateTime = new Date();
          saveInstagramHandleDatabase();
        }
        
        // Add rate limiting to avoid hitting Commerce7 API limits
        // Wait 2 seconds between batches
        await new Promise(resolve => setTimeout(resolve, 2000));
        
      } catch (error) {
        console.error(`Error fetching customer batch ${page}:`, error.message);
        console.error(`Error details:`, error.response?.data || 'No additional details');
        
        databaseBuildStatus.currentProgress = `Error on batch ${page}: ${error.message}`;
        
        // Wait longer if we hit an error (possibly rate limiting)
        await new Promise(resolve => setTimeout(resolve, 10000));
        
        // If we keep getting errors, eventually give up
        if (page > 3 && totalProcessed === 0) {
          hasMore = false;
          databaseBuildStatus.currentProgress = "Failed after multiple attempts";
          console.error('Unable to fetch customers after multiple attempts. Giving up.');
        }
      }
    }
    
    lastDatabaseUpdateTime = new Date();
    
    // Save final database to file
    saveInstagramHandleDatabase();
    
    databaseBuildStatus.currentProgress = "Complete";
    
    console.log(`Instagram handle database build complete! Processed ${totalProcessed} customers.`);
    console.log(`Found ${customersWithInstagram} customers with Instagram handles.`);
    if (customersWithInstagram > 0) {
      console.log(`First 5 handles in database: ${[...instagramHandleMap.keys()].slice(0, 5).join(', ')}`);
    }
    
  } catch (error) {
    console.error('Error building Instagram handle database:', error);
    databaseBuildStatus.currentProgress = `Failed with error: ${error.message}`;
  } finally {
    isDatabaseBuilding = false;
  }
}

// Function to update the Instagram handle database daily
async function updateInstagramHandleDatabase() {
  // Schedule next update for 2:00 AM Central Standard Time (CST)
  const scheduleNextUpdate = () => {
    const now = new Date();
    
    // Create a date object for 2:00 AM CST (8:00 AM UTC)
    const nextUpdate = new Date();
    nextUpdate.setUTCHours(8, 0, 0, 0); // 8:00 AM UTC = 2:00 AM CST
    
    // If it's already past 2:00 AM CST today, schedule for tomorrow
    if (now > nextUpdate) {
      nextUpdate.setUTCDate(nextUpdate.getUTCDate() + 1);
    }
    
    const timeUntilNextUpdate = nextUpdate - now;
    const hoursUntilUpdate = timeUntilNextUpdate / (1000 * 60 * 60);
    
    console.log(`Scheduled next Instagram database rebuild for ${nextUpdate.toLocaleString()} UTC`);
    console.log(`(${Math.round(hoursUntilUpdate)} hours from now)`);
    
    // Log more details to debug time calculation
    console.log(`Current time: ${now.toLocaleString()} (${now.toUTCString()})`);
    console.log(`Target time: ${nextUpdate.toLocaleString()} (${nextUpdate.toUTCString()})`);
    console.log(`Target time in CST: 2:00 AM Central Standard Time`);
    console.log(`Time difference in hours: ${hoursUntilUpdate.toFixed(2)}`);
    
    setTimeout(updateInstagramHandleDatabase, timeUntilNextUpdate);
  };
  
  // Always rebuild the database at 2:00 AM CST
  console.log('Starting daily rebuild of Instagram handle database...');
  
  // Rebuild the whole database
  await buildInstagramHandleDatabase();
  
  // Schedule next update
  scheduleNextUpdate();
}

// Build the database when the server starts
console.log('Checking for existing Instagram handle database file...');
if (loadInstagramHandleDatabase()) {
  console.log('Successfully loaded Instagram handle database from file. Skipping initial build.');
  
  // Still schedule the nightly update check
  updateInstagramHandleDatabase();
} else {
  console.log('No valid Instagram handle database file found or file is too old. Will build now...');
  buildInstagramHandleDatabase().then(() => {
    // Schedule first update check for 2:00 AM
    updateInstagramHandleDatabase();
  });
}

// ---------------- Helper Functions ----------------

// Verify that the webhook request is authentic
function verifyWebhookSignature(req) {
  const signature = req.headers['x-hub-signature-256'];
  if (!signature) {
    console.error('No signature found in webhook request');
    return false;
  }

  // Get the raw body of the request
  const body = req.body;
  
  // The signature from Instagram is in the format: sha256=<hash>
  const [signatureType, signatureHash] = signature.split('=');
  
  if (signatureType !== 'sha256') {
    console.error('Unexpected signature type:', signatureType);
    return false;
  }
  
  // Compute the expected hash using our app secret
  const crypto = require('crypto');
  const expectedHash = crypto
    .createHmac('sha256', process.env.INSTAGRAM_APP_SECRET)
    .update(JSON.stringify(body))
    .digest('hex');
    
  // Compare the expected hash with the provided hash
  return signatureHash === expectedHash;
}

// Find customer by Instagram handle using our database
function findCustomerByInstagramHandleFromDatabase(instagramHandle) {
  // Normalize the handle for case-insensitive lookup
  const normalizedHandle = instagramHandle.toLowerCase();
  
  // Try the exact handle first
  if (instagramHandleMap.has(normalizedHandle)) {
    const customer = instagramHandleMap.get(normalizedHandle);
    console.log(`Found customer in database with exact handle: ${customer.id} (${customer.email}) with Instagram handle: ${customer.fullHandle}`);
    return customer;
  }
  
  // Try without @ if the handle starts with @
  if (normalizedHandle.startsWith('@')) {
    const withoutAtHandle = normalizedHandle.substring(1);
    if (instagramHandleMap.has(withoutAtHandle)) {
      const customer = instagramHandleMap.get(withoutAtHandle);
      console.log(`Found customer in database without @ symbol: ${customer.id} (${customer.email}) with Instagram handle: ${customer.fullHandle}`);
      return customer;
    }
  } 
  // Try with @ if the handle doesn't start with @
  else {
    const withAtHandle = '@' + normalizedHandle;
    if (instagramHandleMap.has(withAtHandle)) {
      const customer = instagramHandleMap.get(withAtHandle);
      console.log(`Found customer in database with added @ symbol: ${customer.id} (${customer.email}) with Instagram handle: ${customer.fullHandle}`);
      return customer;
    }
  }
  
  console.log(`No customer found in database with Instagram handle: "${instagramHandle}" (tried variations with/without @)`);
  return null;
}

// Find customer by Instagram handle by searching Commerce7 (fallback method)
async function findCustomerByInstagramHandle(instagramHandle) {
  const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;
  
  console.log(`Looking for customer with Instagram handle: "${instagramHandle}"`);
  
  // With 12K+ customers, we need to be strategic about how we fetch them
  // Let's try fetching a reasonable batch size at a time
  const batchSize = 100;
  let page = 1;
  let hasMore = true;
  
  // Since we can't efficiently search metadata fields, we'll need to 
  // fetch customers in batches and filter them on our side
  while (hasMore) {
    console.log(`Fetching batch ${page} (${batchSize} customers per batch)`);
    
    try {
      const response = await axios.get(`${C7_API_BASE}/customer`, {
        params: { 
          limit: batchSize,
          page: page
        },
        headers: {
          Authorization: basicAuth,
          'Content-Type': 'application/json',
          Tenant: TENANT_ID,
        },
      });
      
      const customers = response.data.customers || [];
      
      // If we got fewer customers than the batch size, we're done after this batch
      if (customers.length < batchSize) {
        hasMore = false;
      }
      
      console.log(`Processing ${customers.length} customers in batch ${page}`);
      
      // Look for customer with matching Instagram handle
      for (const customer of customers) {
        if (customer.metaData && customer.metaData.instagram_handle === instagramHandle) {
          console.log(`Found customer ${customer.id} (${customer.emails[0]?.email}) with Instagram handle: ${instagramHandle}`);
          return customer;
        }
      }
      
      // Move to next page
      page++;
      
      // Safety check - don't process more than 50 pages (5000 customers)
      // We can adjust this limit based on your needs
      if (page > 50) {
        console.log(`Reached maximum page limit (${page}). Stopping search.`);
        hasMore = false;
      }
    } catch (error) {
      console.error(`Error fetching customer batch ${page}:`, error.message);
      hasMore = false;
    }
  }
  
  console.log(`No customer found with Instagram handle: "${instagramHandle}" after checking all available customers`);
  return null;
}

async function awardPointsForMention(instagramUsername, mentionCount = 1) {
  const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

  try {
    // Instagram webhooks don't include the @ symbol, but we store it with @ in Commerce7
    const searchHandle = '@' + instagramUsername;
    
    // First, try to find the customer in our in-memory database (fast lookup)
    let customerInfo = findCustomerByInstagramHandleFromDatabase(searchHandle);
    
    // If customer not found in database and database building is complete, fall back to direct search
    let customer = null;
    
    if (customerInfo) {
      // We have basic info from our database, but need to fetch full customer details
      try {
        const customerResponse = await axios.get(`${C7_API_BASE}/customer/${customerInfo.id}`, {
          headers: {
            Authorization: basicAuth,
            'Content-Type': 'application/json',
            Tenant: TENANT_ID,
          },
        });
        customer = customerResponse.data;
      } catch (error) {
        console.error(`Error fetching customer details for ${customerInfo.id}:`, error.message);
      }
    } else if (!isDatabaseBuilding) {
      // If the database isn't being built and we didn't find the handle,
      // fall back to the direct search method
      console.log('Customer not found in database, falling back to direct search...');
      customer = await findCustomerByInstagramHandle(searchHandle);
      
      // If we find the customer via direct search, add them to our database for next time
      if (customer) {
        instagramHandleMap.set(searchHandle.toLowerCase(), {
          id: customer.id,
          email: customer.emails[0]?.email,
          fullHandle: searchHandle,
          points: customer.loyalty?.points || 0
        });
        
        // Save the updated database to file
        lastDatabaseUpdateTime = new Date();
        saveInstagramHandleDatabase();
      }
    } else {
      console.log('Database is still building and customer not found. Try again later.');
    }
    
    if (!customer) {
      console.log(`No customer found with Instagram handle: "${searchHandle}"`);
      return;
    }

    // Award points
    const pointsToAward = mentionCount * 40;
    console.log(`Awarding ${pointsToAward} points to customer ${customer.id} (${customer.emails[0]?.email})`);
    
    const loyaltyResponse = await axios.post(`${C7_API_BASE}/loyalty-transaction`, {
      customerId: customer.id,
      amount: pointsToAward,
      notes: `Instagram mentions reward (${mentionCount} mentions)`,
    }, {
      headers: {
        Authorization: basicAuth,
        'Content-Type': 'application/json',
        Tenant: TENANT_ID,
      },
    });
    
    console.log('Loyalty points awarded successfully:', loyaltyResponse.data.id);

    // Send Klaviyo notification
    const klaviyoEvent = {
      data: {
        type: "event",
        attributes: {
          properties: {
            "Points Awarded": pointsToAward,
            "Mentions Count": mentionCount,
            "Instagram Handle": searchHandle,
            "Total Points": (customer.loyalty?.points || 0) + pointsToAward
          },
          metric: {
            data: {
              type: "metric",
              attributes: {
                "name": "Instagram Mentions Points Awarded"
              }
            }
          },
          profile: {
            data: {
              type: "profile",
              attributes: {
                properties: {
                  "$email": customer.emails[0]?.email
                }
              }
            }
          }
        }
      }
    };

    await axios.post("https://a.klaviyo.com/api/events", klaviyoEvent, {
      headers: {
        "Authorization": `Klaviyo-API-Key ${process.env.KLAVIYO_PRIVATE_KEY}`,
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
        "Revision": "2025-01-15"
      }
    });

    // Update customer's points in our database
    if (instagramHandleMap.has(searchHandle.toLowerCase())) {
      const updatedInfo = instagramHandleMap.get(searchHandle.toLowerCase());
      updatedInfo.points += pointsToAward;
      instagramHandleMap.set(searchHandle.toLowerCase(), updatedInfo);
    }

    console.log(`Successfully awarded ${pointsToAward} points to ${customer.emails[0]?.email} for Instagram mentions`);
  } catch (error) {
    console.error('Error awarding points for mention:', error.response?.data || error.message);
  }
}

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
const publicPaths = ['/auth/login', '/', '/create-account', '/create-account.html', '/webhook/instagram', '/test-instagram-mention'];

// All endpoints not matching the public paths will be protected.
app.use((req, res, next) => {
  if (publicPaths.includes(req.path)) {
    return next();
  }
  return checkAuth(req, res, next);
});

// ---------------- Endpoints ----------------

// --- Status endpoint for Instagram database build ---
app.get('/api/instagram-database-status', checkAuth, (req, res) => {
  res.json({
    isDatabaseBuilding,
    databaseSize: instagramHandleMap.size,
    lastUpdated: lastDatabaseUpdateTime,
    buildStatus: databaseBuildStatus
  });
});

// --- API endpoint to get the Instagram handle database file ---
app.get('/api/get-instagram-database', checkAuth, (req, res) => {
  try {
    if (!fs.existsSync(INSTAGRAM_DB_FILE)) {
      return res.status(404).json({ error: 'Instagram handle database file not found' });
    }
    
    res.download(INSTAGRAM_DB_FILE, 'instagram_handle_database.json');
  } catch (error) {
    console.error('Error serving Instagram handle database file:', error);
    res.status(500).json({ error: 'Error serving database file' });
  }
});

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

const formatPhoneNumber = (phone) => {
    if (!phone) return null;

    // Remove all non-numeric characters
    const digits = phone.replace(/\D/g, "");

    // Ensure it's a 10-digit US number, then format as +1XXXXXXXXXX
    if (digits.length === 10) {
        return `+1${digits}`;
    } else {
        console.warn("⚠️ Invalid phone number format. Expected 10-digit US number:", phone);
        return null; // Return null for invalid numbers
    }
};

// --- Create Account Endpoint (protected) ---
app.post('/create-account', authLimiter, async (req, res) => {
    const { firstName, lastName, email, password, phone, emailMarketingStatus, metaData } = req.body;

    if (!firstName || !lastName || !email || !password) {
        console.warn("⚠️ Missing required fields in create-account request:", req.body);
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const basicAuth = `Basic ${Buffer.from(`${APP_ID}:${SECRET_KEY}`).toString('base64')}`;

        console.log("🔍 Checking if customer already exists:", email);
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
            console.warn("⚠️ Customer already exists:", existingCustomer);
            return res.status(409).json({
                message: 'Customer already exists.',
                customer: existingCustomer,
            });
        }

        console.log("📝 Creating new customer profile:", { firstName, lastName, email, phone, emailMarketingStatus, metaData });

        // Format phone correctly & log it before sending
        const formattedPhone = phone ? formatPhoneNumber(phone) : null;
        //console.log("📞 Formatted Phone:", formattedPhone);
        const phoneData = formattedPhone ? [{ phone: formattedPhone }] : [];

        // Ensure Instagram handle is included in metadata
        const updatedMetaData = {
            ...metaData,
            instagram_handle: metaData?.instagram_handle || ""
        };
        console.log('heyyyyyyy:')
console.log(phoneData);
        // Create new customer profile.
        const createResponse = await axios.post(`${C7_API_BASE}/customer`, {
            firstName,
            lastName,
            emails: [{ email }],
            phones: phoneData, // Ensure phone follows E.164 format
            emailMarketingStatus,
            countryCode: "US", // Required for Commerce7
            metaData: updatedMetaData,
        }, {
            headers: {
                Authorization: basicAuth,
                'Content-Type': 'application/json',
                Tenant: TENANT_ID,
            },
        });

        const newCustomer = createResponse.data;
        console.log("✅ Customer created successfully:", newCustomer);
        return res.status(201).json({
            message: 'Account created successfully.',
            customer: newCustomer,
        });
    } catch (error) {
        console.error("❌ Error creating account in Commerce7:", error.response?.data || error.message);
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
    
    // Also update our in-memory database with the new Instagram handle
    if (instagramHandle) {
      console.log(`Updating in-memory database with Instagram handle: ${instagramHandle} for customer ${customer.id}`);
      
      // If customer had a previous handle, remove it from the map
      if (customer.metaData && customer.metaData.instagram_handle) {
        const oldHandle = customer.metaData.instagram_handle;
        if (oldHandle.toLowerCase() !== instagramHandle.toLowerCase()) {
          instagramHandleMap.delete(oldHandle.toLowerCase());
          console.log(`Removed old Instagram handle: ${oldHandle} from database`);
        }
      }
      
      // Add/update the new handle in our map
      instagramHandleMap.set(instagramHandle.toLowerCase(), {
        id: customer.id,
        email: customer.emails[0]?.email,
        fullHandle: instagramHandle,
        points: customer.loyalty?.points || 0
      });
      console.log(`Added Instagram handle: ${instagramHandle} to in-memory database`);
    }
    
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

// --- Instagram Webhook Verification Endpoint ---
app.get('/webhook/instagram', (req, res) => {
  console.log('Webhook verification request received');
  console.log('Query parameters:', req.query);
  
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === WEBHOOK_VERIFY_TOKEN) {
    console.log('Webhook verified successfully');
    res.status(200).send(challenge);
  } else {
    console.error('Webhook verification failed');
    console.error(`Expected token: "${WEBHOOK_VERIFY_TOKEN}", received: "${token}"`);
    res.sendStatus(403);
  }
});

// --- Instagram Webhook Notification Endpoint ---
app.post('/webhook/instagram', async (req, res) => {
  // Immediately respond to Instagram to acknowledge receipt
  res.status(200).send('EVENT_RECEIVED');

  try {
    // Log the incoming webhook data for debugging
    console.log('Instagram webhook received:');
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('Body:', JSON.stringify(req.body, null, 2));
    
    // Check if this is a test event
    const isTestEvent = req.query.test === 'true' || (req.body && req.body.test === true);
    
    // For non-test events, verify signature and exit if invalid
    if (!isTestEvent) {
      if (!verifyWebhookSignature(req)) {
        console.error('Invalid webhook signature. Rejecting non-test event.');
        return; // Exit early - don't process events with invalid signatures
      }
      console.log('Signature verified successfully. Processing real Instagram event.');
    } else {
      console.log('Processing test event (bypassing signature verification).');
    }
    
    const { entry } = req.body;
    
    // Process each entry (there might be multiple)
    for (const item of entry) {
      // For comments field, look for mentions in comments or captions
      if (item.changes && item.changes[0] && item.changes[0].field === 'comments') {
        const change = item.changes[0].value;
        
        // Could be a post caption or a comment
        const text = change.text || change.caption || change.message || '';
        const username = change.from?.username || change.username;
        
        if (text && username && text.includes('@mileaestatewinery')) {
          console.log(`Processing mention from ${username}`);
          
          try {
            // Award points for the mention
            await awardPointsForMention(username);
          } catch (error) {
            console.error(`Error awarding points: ${error.message}`);
          }
        }
      }
    }
  } catch (error) {
    console.error('Error processing webhook:', error);
  }
});

// --- Test endpoint for Instagram mention functionality ---
app.get('/test-instagram-mention', async (req, res) => {
  const username = req.query.username || 'test_user';
  const mentionCount = parseInt(req.query.count || '1', 10);
  
  console.log(`Testing Instagram mention for user: ${username}, count: ${mentionCount}`);
  
  try {
    await awardPointsForMention(username, mentionCount);
    res.send(`<h1>Test Complete</h1>
              <p>Awarded ${mentionCount * 40} points to Instagram user: ${username}</p>
              <p>Check server logs for details.</p>`);
  } catch (error) {
    console.error('Test error:', error);
    res.status(500).send(`<h1>Error</h1><p>${error.message}</p>`);
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
//test