// 1. Import our squad
const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');

// 2. Initialize the app
const app = express();
const port = 3000;

// 3. Set up middleware
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Session middleware
app.use(session({
    secret: 'your-secret-key', // Replace with a real secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 12 * 60 * 60 * 1000 // 12 hours
    }
}));

// 4. Create a MySQL connection pool
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'test',
    port: 3306
}).promise();

// 5. Authentication middleware
const checkAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

// 6. Define our routes

// --- AUTH ROUTES ---
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Login attempt for username: ${username}`);
    try {
        const [rows] = await db.query('SELECT * FROM user_apps WHERE username = ?', [username]);
        if (rows.length > 0) {
            console.log('User found in database.');
            const user = rows[0];
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                console.log('Password match!');
                req.session.user = { id: user.id, username: user.username, is_admin: user.is_admin };
                res.json({ message: 'Login successful' });
            } else {
                console.log('Password does not match.');
                res.status(401).json({ message: 'Invalid credentials' });
            }
        } else {
            console.log('User not found.');
            res.status(401).json({ message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Could not log out.' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logout successful' });
    });
});

// GET route to get current user
app.get('/api/current_user', (req, res) => {
    if (req.session.user) {
        res.json(req.session.user);
    } else {
        res.status(401).json({ message: 'Not authenticated' });
    }
});


// --- PROTECTED ROUTES ---

app.get('/', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/modules/:moduleName.html', checkAuth, (req, res) => {
    const modulePath = path.join(__dirname, 'modules', `${req.params.moduleName}.html`);
    res.sendFile(modulePath);
});

// --- API ROUTES FOR SUPPLIERS (CRUD) ---
app.get('/api/suppliers', checkAuth, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const search = req.query.search || '';
        const status = req.query.status || 'all';
        const offset = (page - 1) * limit;

        let whereClauses = [];
        let params = [];

        if (status !== 'all') {
            whereClauses.push('status = ?');
            params.push(status);
        }

        if (search) {
            whereClauses.push('(supplier_name LIKE ? OR supplier_email LIKE ? OR supplier_address LIKE ?)');
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm);
        }

        const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        const dataSql = `SELECT id, supplier_name, supplier_address, supplier_email, supplier_phone, status FROM mst_supplier ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`;
        const countSql = `SELECT COUNT(*) as total FROM mst_supplier ${whereSql}`;

        const [data] = await db.query(dataSql, [...params, limit, offset]);
        const [[{ total }]] = await db.query(countSql, params);

        res.json({
            data,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(total / limit),
                totalItems: total,
                limit
            }
        });

    } catch (error) {
        console.error('💀 Error fetching suppliers:', error);
        res.status(500).json({ message: 'Failed to fetch suppliers' });
    }
});

app.get('/api/suppliers/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const [supplier] = await db.query('SELECT * FROM mst_supplier WHERE id = ?', [id]);
        if (supplier.length === 0) {
            return res.status(404).json({ message: 'Supplier not found' });
        }
        res.json(supplier[0]);
    } catch (error) {
        console.error(`💀 Error fetching supplier ${req.params.id}:`, error);
        res.status(500).json({ message: 'Failed to fetch supplier data' });
    }
});

app.post('/api/suppliers', checkAuth, async (req, res) => {
    try {
        const { supplier_name, supplier_address, supplier_email, supplier_phone, status } = req.body;
        
        if (!supplier_name || !supplier_address || !supplier_email || !supplier_phone || !status) {
            return res.status(400).json({ message: 'All fields are required!' });
        }

        const sql = 'INSERT INTO mst_supplier (supplier_name, supplier_address, supplier_email, supplier_phone, status) VALUES (?, ?, ?, ?, ?)';
        await db.query(sql, [supplier_name, supplier_address, supplier_email, supplier_phone, status]);
        
        res.status(201).json({ message: 'Supplier added successfully! ✨' });

    } catch (error) {
        console.error('💀 Error creating supplier:', error);
        res.status(500).json({ message: 'Failed to create supplier' });
    }
});

app.put('/api/suppliers/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { supplier_name, supplier_address, supplier_email, supplier_phone, status } = req.body;

        if (!supplier_name || !supplier_address || !supplier_email || !supplier_phone || !status) {
            return res.status(400).json({ message: 'All fields are required!' });
        }

        const sql = 'UPDATE mst_supplier SET supplier_name = ?, supplier_address = ?, supplier_email = ?, supplier_phone = ?, status = ? WHERE id = ?';
        const [result] = await db.query(sql, [supplier_name, supplier_address, supplier_email, supplier_phone, status, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Supplier not found or no changes made' });
        }

        res.json({ message: 'Supplier updated successfully! 🎉' });

    } catch (error) {
        console.error(`💀 Error updating supplier ${req.params.id}:`, error);
        res.status(500).json({ message: 'Failed to update supplier' });
    }
});

app.delete('/api/suppliers/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query('DELETE FROM mst_supplier WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Supplier not found' });
        }

        res.json({ message: 'Supplier deleted successfully! 🗑️' });

    } catch (error) {
        console.error(`💀 Error deleting supplier ${req.params.id}:`, error);
        res.status(500).json({ message: 'Failed to delete supplier' });
    }
});


// --- API ROUTES FOR USER_APPS (CRUD) ---
app.get('/api/user_apps', checkAuth, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const search = req.query.search || '';
        const offset = (page - 1) * limit;

        let whereClauses = [];
        let params = [];

        if (search) {
            whereClauses.push('(username LIKE ? OR pic LIKE ?)');
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm);
        }

        const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        const dataSql = `SELECT id, is_admin, username, pic, date_inserted, date_last_updated FROM user_apps ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`;
        const countSql = `SELECT COUNT(*) as total FROM user_apps ${whereSql}`;

        const [data] = await db.query(dataSql, [...params, limit, offset]);
        const [[{ total }]] = await db.query(countSql, params);

        res.json({
            data,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(total / limit),
                totalItems: total,
                limit
            }
        });

    } catch (error) {
        console.error('💀 Error fetching user_apps:', error);
        res.status(500).json({ message: 'Failed to fetch user_apps' });
    }
});

app.post('/api/user_apps', checkAuth, async (req, res) => {
    try {
        const { username, password, is_admin } = req.body;
        const pic = req.session.user.username; // Get pic from logged-in user
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required!' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        // Set date_inserted to NOW() and date_last_updated to NULL
        const sql = 'INSERT INTO user_apps (username, password, is_admin, pic, date_inserted, date_last_updated) VALUES (?, ?, ?, ?, NOW(), NULL)';
        await db.query(sql, [username, hashedPassword, is_admin || '3', pic]); // Default is_admin to '3' (Courier)
        res.status(201).json({ message: 'User app added successfully! ✨' });
    } catch (error) {
        console.error('💀 Error creating user_app:', error);
        res.status(500).json({ message: 'Failed to create user_app' });
    }
});

app.put('/api/user_apps/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { username, password, is_admin } = req.body;
        
        let sql;
        let params;

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            sql = 'UPDATE user_apps SET username = ?, password = ?, is_admin = ?, date_last_updated = NOW() WHERE id = ?';
            params = [username, hashedPassword, is_admin, id];
        } else {
            sql = 'UPDATE user_apps SET username = ?, is_admin = ?, date_last_updated = NOW() WHERE id = ?';
            params = [username, is_admin, id];
        }

        const [result] = await db.query(sql, params);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User app not found or no changes made' });
        }
        res.json({ message: 'User app updated successfully! 🎉' });
    } catch (error) {
        console.error(`💀 Error updating user_app ${req.params.id}:`, error);
        res.status(500).json({ message: 'Failed to update user_app' });
    }
});

app.delete('/api/user_apps/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query('DELETE FROM user_apps WHERE id = ?', [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User app not found' });
        }
        res.json({ message: 'User app deleted successfully! 🗑️' });
    } catch (error) {
        console.error(`💀 Error deleting user_app ${req.params.id}:`, error);
        res.status(500).json({ message: 'Failed to delete user_app' });
    }
});


// 7. Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port} 🚀`);
});
