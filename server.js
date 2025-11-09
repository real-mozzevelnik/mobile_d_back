const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'db',
  database: process.env.DB_NAME || 'budget_planner',
  password: process.env.DB_PASSWORD || 'postgres',
  port: process.env.DB_PORT || 5432,
});

// Initialize database tables
async function initDB() {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        budget_limit DECIMAL(10, 2) DEFAULT 5000.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create categories table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        icon BIGINT NOT NULL,
        color BIGINT NOT NULL,
        is_income INTEGER NOT NULL DEFAULT 0
      )
    `);

    // Create transactions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        amount DECIMAL(10, 2) NOT NULL,
        type INTEGER NOT NULL,
        category_id INTEGER NOT NULL REFERENCES categories(id),
        category_name VARCHAR(255),
        date TIMESTAMP NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insert default categories if not exist
    const categoriesCheck = await pool.query('SELECT COUNT(*) FROM categories');
    if (parseInt(categoriesCheck.rows[0].count) === 0) {
      const defaultCategories = [
        {id: 1, name: "Salary", icon: 59122, color: 4283215696, is_income: 1}, 
        {id: 2, name: "Freelance", icon: 57733, color: 4278228616, is_income: 1}, 
        {id: 3, name: "Food", icon: 58674, color: 4294940672, is_income: 0}, 
        {id: 4, name: "Transport", icon: 57815, color: 4280391411, is_income: 0}, 
        {id: 5, name: "Shopping", icon: 58778, color: 4288423856, is_income: 0}, 
        {id: 6, name: "Entertainment", icon: 58381, color: 4294198070, is_income: 0}, 
        {id: 7, name: "Bills", icon: 58636, color: 4288585374, is_income: 0}, 
        {id: 8, name: "Healthcare", icon: 58328, color: 4293467747, is_income: 0}
    ];

      for (const category of defaultCategories) {
        await pool.query(
          'INSERT INTO categories (id, name, icon, color, is_income) VALUES ($1, $2, $3, $4, $5)',
          [category.id, category.name, category.icon, category.color, category.is_income]
        );
      }
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

// Auth endpoints

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user by email
    const userQuery = await pool.query(
      'SELECT id, email, username, password, budget_limit FROM users WHERE email = $1',
      [email]
    );

    if (userQuery.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = userQuery.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Return user data (excluding password)
    res.json({
      userId: user.id,
      email: user.email,
      username: user.username,
      budgetLimit: parseFloat(user.budget_limit)
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Register
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ error: 'Username, password and email are required' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user with default budget limit of 5000
    const newUser = await pool.query(
      'INSERT INTO users (username, email, password, budget_limit) VALUES ($1, $2, $3, $4) RETURNING id, email, username, budget_limit',
      [username, email, hashedPassword, 5000.00]
    );

    const user = newUser.rows[0];
    res.status(201).json({
      userId: user.id,
      email: user.email,
      username: user.username,
      budgetLimit: parseFloat(user.budget_limit)
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Data endpoints

// Get transactions
app.post('/data/get_transactions', async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const transactions = await pool.query(
      `SELECT 
        t.id,
        t.user_id as "userId",
        t.title,
        t.amount,
        t.type,
        t.category_id as "categoryId",
        t.category_name as "categoryName",
        t.date,
        t.description
      FROM transactions t
      WHERE t.user_id = $1
      ORDER BY t.date DESC`,
      [userId]
    );

    const formattedTransactions = transactions.rows.map(t => ({
      id: t.id,
      userId: t.userId,
      title: t.title,
      amount: parseFloat(t.amount),
      type: t.type,
      categoryId: t.categoryId,
      categoryName: t.categoryName,
      date: t.date,
      description: t.description
    }));

    res.json(formattedTransactions);
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create transaction
app.post('/data/create_transaction', async (req, res) => {
  try {
    const { userId, title, amount, type, categoryId, categoryName, date, description } = req.body;

    if (!userId || !title || amount === undefined || type === undefined || !categoryId || !date) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const newTransaction = await pool.query(
      `INSERT INTO transactions 
        (user_id, title, amount, type, category_id, category_name, date, description)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id`,
      [userId, title, amount, type, categoryId, categoryName || null, date, description || null]
    );

    res.json({ id: newTransaction.rows[0].id });
  } catch (error) {
    console.error('Create transaction error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete transaction
app.post('/data/delete_transaction', async (req, res) => {
  try {
    const { userId, transactionId } = req.body;

    if (!userId || !transactionId) {
      return res.status(400).json({ error: 'userId and transactionId are required' });
    }

    // Delete transaction only if it belongs to the user
    const result = await pool.query(
      'DELETE FROM transactions WHERE id = $1 AND user_id = $2',
      [transactionId, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Transaction not found or does not belong to user' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Delete transaction error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get categories
app.post('/data/get_categories', async (req, res) => {
  try {
    const categories = await pool.query(
      'SELECT id, name, icon, color, is_income FROM categories ORDER BY is_income DESC, name ASC'
    );

    const formattedCategories = categories.rows.map(c => ({
      id: c.id,
      name: c.name,
      icon: c.icon,
      color: c.color,
      is_income: c.is_income
    }));

    res.json(formattedCategories);
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User endpoints

// Update budget limit
app.post('/user/update_budget', async (req, res) => {
  try {
    const { userId, budgetLimit } = req.body;

    if (!userId || budgetLimit === undefined) {
      return res.status(400).json({ error: 'userId and budgetLimit are required' });
    }

    const result = await pool.query(
      'UPDATE users SET budget_limit = $1 WHERE id = $2',
      [budgetLimit, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Update budget error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
async function startServer() {
  try {
    // Initialize database
    await initDB();
    
    // Test database connection
    await pool.query('SELECT NOW()');
    console.log('Connected to PostgreSQL database');
    
    // Start listening
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing HTTP server');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT signal received: closing HTTP server');
  await pool.end();
  process.exit(0);
});
