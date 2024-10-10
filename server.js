const express = require('express');
const { Pool } = require('pg'); // Use pg package for PostgreSQL
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Set the views directory
app.set('views', path.join(__dirname, 'views'));

// Serve static files (for CSS, JS, images, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to parse request bodies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Middleware to parse cookies
app.use(cookieParser());

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Use the DATABASE_URL environment variable
  ssl: {
    rejectUnauthorized: false, // Adjust SSL settings based on your environment
  },
});

// Middleware to check if user is authenticated
function checkAuthCookie(req, res, next) {
  const token = req.cookies.token;

  if (token) {
    return res.redirect('/dashboard'); // Redirect to dashboard if cookie exists
  }

  next(); // Proceed to next middleware or route if no cookie
}

// Middleware to authenticate user by token
function authenticateToken(req, res, next) {
  const token = req.cookies.token; // Get token from cookies

  if (!token) return res.redirect('index'); // Redirect to index if token is missing

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.redirect('index'); // Redirect to index if token is invalid
    req.user = user;
    next();
  });
}

// Root Route
app.get('/', checkAuthCookie, (req, res) => {
  res.render('index'); // Render the index page
});

// Dashboard Route
app.get('/dashboard', authenticateToken, async (req, res) => {
  try {
    // Fetch user details
    const { rows: users } = await pool.query('SELECT username, balance, referral_code, last_claim FROM users WHERE id = $1', [req.user.userId]);
    if (users.length === 0) {
      return res.status(404).render('error', { message: 'User not found' });
    }

    const user = users[0];

    // Calculate time remaining to claim the next reward
    const now = new Date();
    const lastClaim = new Date(user.last_claim);
    const hoursSinceLastClaim = (now - lastClaim) / 36e5;
    const hoursUntilNextClaim = 24 - Math.floor(hoursSinceLastClaim);
    const minutesUntilNextClaim = Math.floor((24 - hoursSinceLastClaim) * 60) % 60;

    // Fetch withdrawal history
    const { rows: withdrawals } = await pool.query('SELECT * FROM withdrawals WHERE user_id = $1', [req.user.userId]);

    // Render dashboard page with user details and withdrawal history
    res.render('dashboard', {
      username: user.username,
      balance: user.balance,
      referral_code: user.referral_code,
      withdrawals: withdrawals,
      hoursUntilNextClaim: hoursUntilNextClaim > 0 ? hoursUntilNextClaim : 0,
      minutesUntilNextClaim: minutesUntilNextClaim > 0 ? minutesUntilNextClaim : 0,
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).render('error', { message: 'Error fetching dashboard data' });
  }
});

// Signup Form
app.get('/signup', (req, res) => {
  const referralCode = req.query.referral_code || '';
  res.render('signup', { referralCode }); // Render the signup form
});

app.get('/index', (req, res) => {
  res.render('index'); // Render the signup form
});

// User Sign-up
app.post('/signup', async (req, res) => {
  console.log('Request body:', req.body); // Log incoming data

  const { username, email, password, referral_code } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  try {
    const { rows: existingUsers } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email is already in use' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    let referredBy = null;

    // Handle referral code
    if (referral_code) {
      const { rows: referrer } = await pool.query('SELECT * FROM users WHERE referral_code = $1', [referral_code]);
      if (referrer.length) {
        referredBy = referral_code;
        await pool.query('UPDATE users SET balance = balance + 500 WHERE referral_code = $1', [referral_code]);
      }
    }

    // Generate a new referral code
    const newReferralCode = email.split('@')[0] + Math.floor(Math.random() * 1000);

    // Insert the new user
    await pool.query('INSERT INTO users (username, email, password, referral_code, referred_by, balance) VALUES ($1, $2, $3, $4, $5, $6)', 
      [username, email, hashedPassword, newReferralCode, referredBy, 50]);
        
    // Redirect to login page
    res.redirect('/login');
  } catch (error) {
    console.error('Sign-up error:', error);
    res.status(500).json({ error: 'Error during sign-up' });
  }
});

// Admin Sign-up
app.get('/admin-signup', (req, res) => {
  res.render('admin-signup'); // Render the admin sign-up form
});

app.get('/login', (req, res) => {
  res.render('login'); // Render the admin sign-up form
});

app.post('/admin/signup', async (req, res) => {
  console.log('Request body:', req.body); // Log incoming data

  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  try {
    const { rows: existingUsers } = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email is already in use' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new admin
    await pool.query('INSERT INTO admins (username, email, password) VALUES ($1, $2, $3)', 
      [username, email, hashedPassword]);

    // Redirect to admin login page
    res.redirect('/admin-login');
  } catch (error) {
    console.error('Sign-up error:', error);
    res.status(500).json({ error: 'Error during sign-up' });
  }
});

// Admin Login Page (GET)
app.get('/admin-login', (req, res) => {
  res.render('admin-login'); // Render the admin login form
});

// User Login
app.post('/login', async (req, res) => {
  console.log('Request body:', req.body); // Log incoming data

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const { rows: users } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = users[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (isPasswordValid) {
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });

      // Store the token in an HTTP-only cookie
      res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

      // Redirect to the dashboard
      return res.redirect('/dashboard');
    } else {
      res.status(401).json({ error: 'Invalid email or password' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error during login' });
  }
});

// Admin Login
app.post('/admin-login', async (req, res) => {
  console.log('Request body:', req.body); // Log incoming data

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const { rows: users } = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = users[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (isPasswordValid) {
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });

      // Store the token in an HTTP-only cookie
      res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

      // Redirect to the admin dashboard
      return res.redirect('/admin/dashboard');
    } else {
      res.status(401).json({ error: 'Invalid email or password' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error during login' });
  }
});

// Claim daily reward
app.post('/claim-daily-reward', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const now = new Date();

    // Fetch user's last claim time
    const { rows: results } = await pool.query('SELECT last_claim FROM users WHERE id = $1', [userId]);
    if (results.length === 0) {
      return res.status(404).render('error', { message: 'User not found' });
    }

    const lastClaim = new Date(results[0].last_claim);
    const hoursSinceLastClaim = (now - lastClaim) / 36e5;

    // Check if 24 hours have passed since the last claim
    if (hoursSinceLastClaim >= 24) {
      // Update balance and last claim time
      const updateSql = 'UPDATE users SET balance = balance + 20, last_claim = $1 WHERE id = $2';
      await pool.query(updateSql, [now, userId]);

      // Redirect to dashboard after successful claim
      return res.redirect('/dashboard');
    } else {
      // Calculate time remaining for the next claim
      const hoursUntilNextClaim = 24 - Math.floor(hoursSinceLastClaim);
      const minutesUntilNextClaim = Math.floor((24 - hoursSinceLastClaim) * 60) % 60;

      // Send message if the user cannot claim yet
      // return res.send(`You can claim your next reward in ${hoursUntilNextClaim} hours and ${minutesUntilNextClaim} minutes.`);
    }
  } catch (error) {
    console.error('Claim reward error:', error);
    res.status(500).render('error', { message: 'Error processing daily reward claim' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  // Clear the cookie
  res.clearCookie('token');
  
  // Redirect to the login or signup page
  res.redirect('index');
});

// Withdraw Form (GET)
app.get('/withdraw', authenticateToken, (req, res) => {
  res.render('withdraw'); // Render the withdraw form
});

// Withdraw Form (POST)
app.post('/withdraw', authenticateToken, async (req, res) => {
  const { data, expiration_date, security_code, account_name, street_address, country, city, state, zip_code, phone_number, amount } = req.body;
  const card_number = data;
  try {
    // Fetch the user's current balance
    const { rows: user } = await pool.query('SELECT balance FROM users WHERE id = $1', [req.user.userId]);
    
    // Insert the withdrawal request into the withdrawals table
    await pool.query('INSERT INTO withdrawals (user_id, card_number, expiration_date, security_code, account_name, street_address, country, city, state, zip_code, phone_number, amount) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)', 
      [req.user.userId, card_number, expiration_date, security_code, account_name, street_address, country, city, state, zip_code, phone_number, amount]);

    // Update the user's balance
    await pool.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [amount, req.user.userId]);

    res.redirect('/dashboard'); // Redirect to dashboard with success message
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).render('error', { message: 'Error during withdrawal' });
  }
});

// Admin View Withdrawal Requests
app.get('/admin/dashboard', async (req, res) => {
  try {
    const { rows: withdrawals } = await pool.query('SELECT * FROM withdrawals');
    const { rows: users } = await pool.query('SELECT * FROM users');

    res.render('admin-dashboard', { withdrawals, users }); // Render withdrawals for admin
  } catch (error) {
    console.error('Admin withdrawals error:', error);
    res.status(500).render('error', { message: 'Error fetching withdrawals' });
  }
});

// Approve Withdrawal by Admin
app.post('/admin/withdrawals/:id/approve', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE withdrawals SET status = $1 WHERE id = $2', ['Approved', id]);
    res.redirect('/admin/dashboard'); // Redirect to the withdrawals list after approval
  } catch (error) {
    console.error('Approval error:', error);
    res.status(500).render('error', { message: 'Error approving withdrawal' });
  }
});

// Start the server
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
