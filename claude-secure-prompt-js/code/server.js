require('dotenv').config();

const { MongoClient } = require('mongodb');
const { createApp } = require('./src/app');

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.DB_NAME || 'tfm';
const COLLECTION = process.env.COLLECTION || 'users';

const client = new MongoClient(MONGO_URI);

async function start() {
  await client.connect();
  const users = client.db(DB_NAME).collection(COLLECTION);
  await users.createIndex({ username: 1 }, { unique: true });

  const app = createApp(users);
  app.listen(PORT, () => console.log(`Servidor escuchando en http://localhost:${PORT}`));
}

start().catch((err) => {
  console.error('No se pudo iniciar el servidor:', err.message);
  process.exit(1);
});

process.on('SIGINT', async () => {
  await client.close();
  process.exit(0);
});
