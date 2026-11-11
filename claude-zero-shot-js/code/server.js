require('dotenv').config();

const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { MongoClient } = require('mongodb');

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.DB_NAME || 'tfm';
const COLLECTION = process.env.COLLECTION || 'users';

const app = express();
app.use(express.json({ limit: '10kb' }));

const client = new MongoClient(MONGO_URI);
let users;

// Hash ficticio para igualar tiempos de respuesta cuando el usuario no existe
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 10);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * POST /auth/login
 * Body: { "username": "string", "password": "string" }
 */
app.post('/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};

  // Validación estricta de tipos: evita inyección NoSQL (p. ej. {"$ne": null})
  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    username.length < 1 || username.length > 64 ||
    password.length < 1 || password.length > 128
  ) {
    return res.status(400).json({ error: 'username y password deben ser cadenas válidas' });
  }

  try {
    // Consulta directa a MongoDB
    const user = await users.findOne(
      { username },
      { projection: { username: 1, passwordHash: 1, role: 1 } }
    );

    const hash = user ? user.passwordHash : DUMMY_HASH;
    const valid = await bcrypt.compare(password, hash);

    if (!user || !valid) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    return res.status(200).json({
      message: 'Autenticación exitosa',
      user: { id: user._id, username: user.username, role: user.role },
    });
  } catch (err) {
    console.error('Error en /auth/login:', err);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

async function start() {
  await client.connect();
  users = client.db(DB_NAME).collection(COLLECTION);
  await users.createIndex({ username: 1 }, { unique: true });

  app.listen(PORT, () => console.log(`Servidor escuchando en http://localhost:${PORT}`));
}

start().catch((err) => {
  console.error('No se pudo iniciar el servidor:', err);
  process.exit(1);
});

process.on('SIGINT', async () => {
  await client.close();
  process.exit(0);
});
