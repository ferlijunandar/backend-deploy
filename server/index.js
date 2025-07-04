import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';
import path, { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// PostgreSQL connection
const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432, // Pastikan dalam format numerik
});

// Cek koneksi ke database
const connectDB = async () => {
  try {
    const client = await pool.connect();
    console.log('✅ Connected to PostgreSQL database');
    client.release();
  } catch (error) {
    console.error('❌ Error connecting to database:', error.message);
  }
};
connectDB();
// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Token not provided' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Role-based Authorization Middleware
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admin role required.' });
  }
  next();
};

// Auth Routes
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    
    if (result.rowCount === 0) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    
    const token = jwt.sign({
      id: user.id,
      username: user.username,
      role: user.role
    }, process.env.JWT_SECRET, { expiresIn: '8h' });
    
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        nama: user.nama,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// User Routes
app.get('/api/users', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nama, username, role, created_at FROM users ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/users', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { nama, username, password, role } = req.body;
    
    // Check if username already exists
    const checkUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (checkUser.rowCount > 0) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO users (nama, username, password, role) VALUES ($1, $2, $3, $4) RETURNING id, nama, username, role',
      [nama, username, hashedPassword, role]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { nama, username, password, role } = req.body;
    
    // Check if username exists and doesn't belong to the current user
    if (username) {
      const checkUser = await pool.query('SELECT * FROM users WHERE username = $1 AND id != $2', [username, id]);
      if (checkUser.rowCount > 0) {
        return res.status(400).json({ message: 'Username already exists' });
      }
    }
    
    let query, params;
    
    if (password) {
      // Hash new password
      const hashedPassword = await bcrypt.hash(password, 10);
      query = 'UPDATE users SET nama = $1, username = $2, password = $3, role = $4 WHERE id = $5 RETURNING id, nama, username, role';
      params = [nama, username, hashedPassword, role, id];
    } else {
      query = 'UPDATE users SET nama = $1, username = $2, role = $3 WHERE id = $4 RETURNING id, nama, username, role';
      params = [nama, username, role, id];
    }
    
    const result = await pool.query(query, params);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Kategori Barang Routes
app.get('/api/kategori', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM kategori_barang ORDER BY nama_kategori');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching kategori:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/kategori', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { nama_kategori } = req.body;
    
    const result = await pool.query(
      'INSERT INTO kategori_barang (nama_kategori) VALUES ($1) RETURNING *',
      [nama_kategori]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating kategori:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/kategori/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { nama_kategori } = req.body;
    
    const result = await pool.query(
      'UPDATE kategori_barang SET nama_kategori = $1 WHERE id = $2 RETURNING *',
      [nama_kategori, id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Kategori not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating kategori:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/kategori/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('DELETE FROM kategori_barang WHERE id = $1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Kategori not found' });
    }
    
    res.json({ message: 'Kategori deleted successfully' });
  } catch (error) {
    console.error('Error deleting kategori:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Jenis Barang Routes
app.get('/api/jenis', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM jenis_barang ORDER BY nama_jenis');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching jenis barang:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/jenis', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { nama_jenis } = req.body;
    
    const result = await pool.query(
      'INSERT INTO jenis_barang (nama_jenis) VALUES ($1) RETURNING *',
      [nama_jenis]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating jenis barang:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/jenis/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { nama_jenis } = req.body;
    
    const result = await pool.query(
      'UPDATE jenis_barang SET nama_jenis = $1 WHERE id = $2 RETURNING *',
      [nama_jenis, id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Jenis barang not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating jenis barang:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/jenis/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('DELETE FROM jenis_barang WHERE id = $1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Jenis barang not found' });
    }
    
    res.json({ message: 'Jenis barang deleted successfully' });
  } catch (error) {
    console.error('Error deleting jenis barang:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Barang Routes
app.get('/api/barang', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT b.*, k.nama_kategori, j.nama_jenis 
      FROM barang b 
      LEFT JOIN kategori_barang k ON b.id_kategori = k.id 
      LEFT JOIN jenis_barang j ON b.id_jenis = j.id 
      ORDER BY b.nama_barang
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching barang:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/barang', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { nama_barang, id_kategori, id_jenis, stok, harga_beli, harga_jual } = req.body;
    
    const result = await pool.query(
      'INSERT INTO barang (nama_barang, id_kategori, id_jenis, stok, harga_beli, harga_jual) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [nama_barang, id_kategori, id_jenis, stok, harga_beli, harga_jual]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating barang:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/barang/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { nama_barang, id_kategori, id_jenis, stok, harga_beli, harga_jual } = req.body;
    
    const result = await pool.query(
      'UPDATE barang SET nama_barang = $1, id_kategori = $2, id_jenis = $3, stok = $4, harga_beli = $5, harga_jual = $6 WHERE id = $7 RETURNING *',
      [nama_barang, id_kategori, id_jenis, stok, harga_beli, harga_jual, id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Barang not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating barang:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/barang/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('DELETE FROM barang WHERE id = $1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Barang not found' });
    }
    
    res.json({ message: 'Barang deleted successfully' });
  } catch (error) {
    console.error('Error deleting barang:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Supplier Routes
app.get('/api/supplier', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM supplier ORDER BY nama_supplier');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching supplier:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/supplier', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { nama_supplier, kontak, alamat } = req.body;
    
    const result = await pool.query(
      'INSERT INTO supplier (nama_supplier, kontak, alamat) VALUES ($1, $2, $3) RETURNING *',
      [nama_supplier, kontak, alamat]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating supplier:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/supplier/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { nama_supplier, kontak, alamat } = req.body;
    
    const result = await pool.query(
      'UPDATE supplier SET nama_supplier = $1, kontak = $2, alamat = $3 WHERE id = $4 RETURNING *',
      [nama_supplier, kontak, alamat, id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Supplier not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating supplier:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/supplier/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('DELETE FROM supplier WHERE id = $1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Supplier not found' });
    }
    
    res.json({ message: 'Supplier deleted successfully' });
  } catch (error) {
    console.error('Error deleting supplier:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Pelanggan Routes
app.get('/api/pelanggan', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM pelanggan ORDER BY nama_pelanggan');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching pelanggan:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/pelanggan', authenticateToken, async (req, res) => {
  try {
    console.log('Received data:', req.body);

    // Menggunakan nama field sesuai data yang dikirim dari frontend
    const { nama_pelanggan, kontak, alamat } = req.body;

    const result = await pool.query(
      'INSERT INTO pelanggan (nama_pelanggan, kontak, alamat) VALUES ($1, $2, $3) RETURNING *',
      [nama_pelanggan, kontak, alamat]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating pelanggan - detail:', error.message, error.stack);
    res.status(500).json({ message: 'Server error', detail: error.message });
  }
});

app.put('/api/pelanggan/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { nama_pelanggan, kontak, alamat } = req.body;

    const result = await pool.query(
      'UPDATE pelanggan SET nama_pelanggan = $1, kontak = $2, alamat = $3 WHERE id = $4 RETURNING *',
      [nama_pelanggan, kontak, alamat, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Pelanggan not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating pelanggan - detail:', error.message, error.stack);
    res.status(500).json({ message: 'Server error', detail: error.message });
  }
});

app.delete('/api/pelanggan/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM pelanggan WHERE id = $1 RETURNING id', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Pelanggan not found' });
    }

    res.json({ message: 'Pelanggan deleted successfully' });
  } catch (error) {
    console.error('Error deleting pelanggan:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Transaksi Pembelian Routes
app.get('/api/pembelian', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT tp.*, s.nama_supplier 
      FROM transaksi_pembelian tp
      LEFT JOIN supplier s ON tp.id_supplier = s.id
      ORDER BY tp.tanggal DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching pembelian:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/pembelian/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get pembelian header
    const headerResult = await pool.query(`
      SELECT tp.*, s.nama_supplier 
      FROM transaksi_pembelian tp
      LEFT JOIN supplier s ON tp.id_supplier = s.id
      WHERE tp.id = $1
    `, [id]);
    
    if (headerResult.rowCount === 0) {
      return res.status(404).json({ message: 'Transaksi pembelian not found' });
    }
    
    // Get detail pembelian
    const detailResult = await pool.query(`
      SELECT dp.*, b.nama_barang 
      FROM detail_pembelian dp
      LEFT JOIN barang b ON dp.id_barang = b.id
      WHERE dp.id_pembelian = $1
    `, [id]);
    
    res.json({
      pembelian: headerResult.rows[0],
      details: detailResult.rows
    });
  } catch (error) {
    console.error('Error fetching pembelian detail:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/pembelian', authenticateToken, authorizeAdmin, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { id_supplier, total_harga, details } = req.body;
    
    // Insert pembelian header
    const headerResult = await client.query(
      'INSERT INTO transaksi_pembelian (id_supplier, total_harga) VALUES ($1, $2) RETURNING *',
      [id_supplier, total_harga]
    );
    
    const pembelianId = headerResult.rows[0].id;
    
    // Insert details and update stock
    for (const detail of details) {
      const { id_barang, jumlah, harga_satuan, subtotal } = detail;
      
      // Insert detail
      await client.query(
        'INSERT INTO detail_pembelian (id_pembelian, id_barang, jumlah, harga_satuan, subtotal) VALUES ($1, $2, $3, $4, $5)',
        [pembelianId, id_barang, jumlah, harga_satuan, subtotal]
      );
      
      // Update barang stock
      await client.query(
        'UPDATE barang SET stok = stok + $1 WHERE id = $2',
        [jumlah, id_barang]
      );
    }
    
    await client.query('COMMIT');
    
    res.status(201).json({ 
      message: 'Transaksi pembelian berhasil',
      id: pembelianId
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error creating pembelian:', error);
    res.status(500).json({ message: 'Server error' });
  } finally {
    client.release();
  }
});
// --- Function untuk generate Nomor Invoice ---
const generateInvoiceNumber = async () => {
  const today = new Date();
  const datePart = today.toISOString().slice(0, 10).replace(/-/g, '');  // Mengambil tanggal dalam format YYYYMMDD

  // Hitung berapa transaksi hari ini
  const result = await pool.query(`
    SELECT COUNT(*) FROM transaksi_penjualan WHERE DATE(tanggal) = CURRENT_DATE
  `);

  const countToday = parseInt(result.rows[0].count, 10) + 1;  // Hitung jumlah transaksi hari ini dan tambahkan 1

  // Menghasilkan nomor invoice dalam format: INV-YYYYMMDD-XXXX
  const invoiceNumber = `INV-${datePart}-${String(countToday).padStart(4, '0')}`;
  console.log('Generated Invoice Number:', invoiceNumber);  // Debugging log
  return invoiceNumber;
};

// --- Route: Ambil semua transaksi penjualan ---
app.get('/api/penjualan', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT tp.*, p.nama_pelanggan, u.nama as nama_kasir
      FROM transaksi_penjualan tp
      LEFT JOIN pelanggan p ON tp.id_pelanggan = p.id
      LEFT JOIN users u ON tp.id_user = u.id
      ORDER BY tp.tanggal DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching penjualan:', error);
    res.status(500).json({ message: 'Server error' });
  }
});
// GET detail penjualan berdasarkan ID
app.get('/api/penjualan/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Ambil header transaksi
    const headerResult = await pool.query(`
      SELECT tp.*, p.nama_pelanggan, u.nama AS nama_kasir
      FROM transaksi_penjualan tp
      LEFT JOIN pelanggan p ON tp.id_pelanggan = p.id
      LEFT JOIN users u ON tp.id_user = u.id
      WHERE tp.id = $1
    `, [id]);

    if (headerResult.rowCount === 0) {
      return res.status(404).json({ message: `Transaksi penjualan dengan ID ${id} tidak ditemukan` });
    }

    // Ambil detail barang
    const detailResult = await pool.query(`
      SELECT dp.*, b.nama_barang
      FROM detail_penjualan dp
      LEFT JOIN barang b ON dp.id_barang = b.id
      WHERE dp.id_penjualan = $1
    `, [id]);

    res.json({
      penjualan: headerResult.rows[0],
      details: detailResult.rows
    });

  } catch (error) {
    console.error('Gagal mengambil detail penjualan:', error);
    res.status(500).json({ message: 'Kesalahan server saat mengambil detail penjualan' });
  }
});

// --- Route: Ambil detail transaksi berdasarkan ID ---
app.post('/api/penjualan', authenticateToken, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const { id_pelanggan, total_harga, diskon, metode_pembayaran, details } = req.body;

    // BUAT INVOICE NOMOR BARU
    const invoiceNumber = await generateInvoiceNumber();

    // INSERT header transaksi_penjualan
    const headerResult = await client.query(
      `INSERT INTO transaksi_penjualan (id_user, id_pelanggan, total_harga, diskon, metode_pembayaran, invoice)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [req.user.id, id_pelanggan, total_harga, diskon, metode_pembayaran, invoiceNumber]
    );

    // Pastikan headerResult mengembalikan id transaksi
    if (!headerResult.rows.length) {
      throw new Error('Gagal menyimpan transaksi header.');
    }

    const penjualanId = headerResult.rows[0].id;
    console.log(`Transaksi ID: ${penjualanId} - Invoice: ${invoiceNumber}`);  // Debugging log

    // INSERT detail penjualan dan update stok
    for (const detail of details) {
      const { id_barang, jumlah, harga_satuan, subtotal } = detail;

      const stockResult = await client.query('SELECT stok FROM barang WHERE id = $1', [id_barang]);
      if (stockResult.rows.length === 0 || stockResult.rows[0].stok < jumlah) {
        throw new Error(`Stok tidak mencukupi untuk barang ID ${id_barang}`);
      }

      await client.query(
        `INSERT INTO detail_penjualan (id_penjualan, id_barang, jumlah, harga_satuan, subtotal)
         VALUES ($1, $2, $3, $4, $5)`,
        [penjualanId, id_barang, jumlah, harga_satuan, subtotal]
      );

      await client.query(
        `UPDATE barang SET stok = stok - $1 WHERE id = $2`,
        [jumlah, id_barang]
      );
    }

    await client.query('COMMIT');

    res.status(201).json({
      message: 'Transaksi penjualan berhasil',
      id: penjualanId,
      invoice: invoiceNumber
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error creating penjualan:', error);
    res.status(500).json({ message: error.message || 'Server error' });
  } finally {
    client.release();
  }
});



// Dashboard Data
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    // Total transaksi per hari (7 hari terakhir)
    const transaksiHarian = await pool.query(`
      SELECT 
        DATE(tanggal) as tanggal, 
        COUNT(*) as jumlah_transaksi, 
        SUM(total_harga) as total_penjualan
      FROM transaksi_penjualan
      WHERE tanggal >= NOW() - INTERVAL '7 days'
      GROUP BY DATE(tanggal)
      ORDER BY DATE(tanggal)
    `);
    
    // Total pendapatan per kategori
    const penjualanPerKategori = await pool.query(`
      SELECT 
        k.nama_kategori, 
        SUM(dp.subtotal) as total_penjualan
      FROM detail_penjualan dp
      JOIN barang b ON dp.id_barang = b.id
      JOIN kategori_barang k ON b.id_kategori = k.id
      JOIN transaksi_penjualan tp ON dp.id_penjualan = tp.id
      WHERE tp.tanggal >= NOW() - INTERVAL '30 days'
      GROUP BY k.nama_kategori
    `);
    
    // Barang hampir habis
    const barangHampirHabis = await pool.query(`
      SELECT id, nama_barang, stok
      FROM barang
      WHERE stok <= 10
      ORDER BY stok
      LIMIT 10
    `);
    
    // Metode pembayaran count
    const metodePembayaran = await pool.query(`
      SELECT metode_pembayaran, COUNT(*) as jumlah
      FROM transaksi_penjualan
      WHERE tanggal >= NOW() - INTERVAL '30 days'
      GROUP BY metode_pembayaran
    `);
    
    // Total summary
    const totalPenjualanBulan = await pool.query(`
      SELECT SUM(total_harga) as total
      FROM transaksi_penjualan
      WHERE tanggal >= DATE_TRUNC('month', CURRENT_DATE)
    `);
    
    const totalPembelianBulan = await pool.query(`
      SELECT SUM(total_harga) as total
      FROM transaksi_pembelian
      WHERE tanggal >= DATE_TRUNC('month', CURRENT_DATE)
    `);
    
    const totalTransaksiBulan = await pool.query(`
      SELECT COUNT(*) as total
      FROM transaksi_penjualan
      WHERE tanggal >= DATE_TRUNC('month', CURRENT_DATE)
    `);
    
    const totalBarang = await pool.query(`
      SELECT COUNT(*) as total
      FROM barang
    `);
    
    res.json({
      transaksiHarian: transaksiHarian.rows,
      penjualanPerKategori: penjualanPerKategori.rows,
      barangHampirHabis: barangHampirHabis.rows,
      metodePembayaran: metodePembayaran.rows,
      summary: {
        totalPenjualanBulan: totalPenjualanBulan.rows[0]?.total || 0,
        totalPembelianBulan: totalPembelianBulan.rows[0]?.total || 0,
        totalTransaksiBulan: totalTransaksiBulan.rows[0]?.total || 0,
        totalBarang: totalBarang.rows[0]?.total || 0
      }
    });
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/reports/penjualan', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    const result = await pool.query(`
      SELECT tp.*, p.nama_pelanggan, u.nama as nama_kasir
      FROM transaksi_penjualan tp
      LEFT JOIN pelanggan p ON tp.id_pelanggan = p.id
      LEFT JOIN users u ON tp.id_user = u.id
      WHERE tp.tanggal >= $1 AND tp.tanggal < ($2::date + INTERVAL '1 day')
      ORDER BY tp.tanggal DESC
    `, [start_date, end_date]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching penjualan report:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/reports/pembelian', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    const result = await pool.query(`
      SELECT tp.*, s.nama_supplier
      FROM transaksi_pembelian tp
      LEFT JOIN supplier s ON tp.id_supplier = s.id
     WHERE tp.tanggal >= $1 AND tp.tanggal < ($2::date + INTERVAL '1 day')
      ORDER BY tp.tanggal DESC
    `, [start_date, end_date]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching pembelian report:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/reports/stok', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT b.*, k.nama_kategori, j.nama_jenis
      FROM barang b
      LEFT JOIN kategori_barang k ON b.id_kategori = k.id
      LEFT JOIN jenis_barang j ON b.id_jenis = j.id
      ORDER BY b.stok ASC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching stok report:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Serve static assets if in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../dist')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../dist', 'index.html'));
  });
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
