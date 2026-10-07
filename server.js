const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      telefono VARCHAR(15) UNIQUE NOT NULL,
      pin VARCHAR(255) NOT NULL,
      debe_cambiar_pin BOOLEAN DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
      usuario_id INT REFERENCES usuarios(id),
      comercio VARCHAR(100) NOT NULL,
      fecha TIMESTAMP NOT NULL,
      total DECIMAL(10, 2) NOT NULL
    );
  `);

  const pinHash = await bcrypt.hash('1234', 10);
  await pool.query(`
    INSERT INTO usuarios (telefono, pin, debe_cambiar_pin)
    VALUES ('644009960', $1, TRUE), ('671215286', $1, TRUE)
    ON CONFLICT (telefono) DO NOTHING;
  `, [pinHash]);
}

initDB();

app.post('/api/login', async (req, res) => {
  const { telefono, pin } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE telefono = $1', [telefono]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Teléfono no autorizado' });

    const usuario = result.rows[0];
    const pinValido = await bcrypt.compare(pin, usuario.pin);
    if (!pinValido) return res.status(401).json({ error: 'PIN incorrecto' });

    res.json({ id: usuario.id, telefono: usuario.telefono, debeCambiarPin: usuario.debe_cambiar_pin });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cambiar-pin', async (req, res) => {
  const { telefono, nuevoPin } = req.body;
  try {
    const nuevoHash = await bcrypt.hash(nuevoPin, 10);
    await pool.query('UPDATE usuarios SET pin = $1, debe_cambiar_pin = FALSE WHERE telefono = $2', [nuevoHash, telefono]);
    res.json({ success: true, message: 'PIN actualizado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/gastos', async (req, res) => {
  const { usuarioId, comercio, fecha, total } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO tickets (usuario_id, comercio, fecha, total) VALUES ($1, $2, $3, $4) RETURNING *',
      [usuarioId, comercio, fecha, total]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/gastos', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tickets ORDER BY fecha DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor listo en puerto ${PORT}`));
