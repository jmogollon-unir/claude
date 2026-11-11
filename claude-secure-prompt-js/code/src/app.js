const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const bcrypt = require('bcrypt');

const { AppError, AuthenticationError } = require('./errors');
const { loginSchema, registerSchema, validateBody } = require('./validation');

const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 12;

// Hash ficticio para igualar tiempos de respuesta cuando el usuario no existe (anti timing attack)
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', BCRYPT_ROUNDS);

function createApp(users) {
  const app = express();

  app.disable('x-powered-by');
  app.use(helmet());
  app.use(express.json({ limit: '10kb' }));

  // Capa 1 de defensa CWE-943: elimina claves con "$" o "." del body/query/params
  app.use(mongoSanitize({ allowDots: false }));

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, _res, next) => next(new AppError(429, 'Demasiadas solicitudes, intente más tarde')),
  });

  // POST /auth/register: almacena el hash bcrypt, nunca la contraseña
  app.post('/auth/register', authLimiter, validateBody(registerSchema), async (req, res, next) => {
    try {
      const { username, password } = req.body;
      const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

      await users.insertOne({
        username,
        passwordHash,
        role: 'user',
        createdAt: new Date(),
      });

      res.status(201).json({ message: 'Usuario registrado' });
    } catch (err) {
      if (err && err.code === 11000) {
        return next(new AppError(409, 'No se pudo completar el registro'));
      }
      next(err);
    }
  });

  // POST /auth/login
  app.post('/auth/login', authLimiter, validateBody(loginSchema), async (req, res, next) => {
    try {
      const { username, password } = req.body; // ya validados: strings con lista blanca

      // Capa 2 de defensa: consulta con valor escalar y proyección mínima
      const user = await users.findOne(
        { username: { $eq: username } },
        { projection: { username: 1, passwordHash: 1, role: 1 } }
      );

      const hash = user ? user.passwordHash : DUMMY_HASH;
      const passwordOk = await bcrypt.compare(password, hash);

      if (!user || !passwordOk) {
        throw new AuthenticationError();
      }

      res.status(200).json({
        message: 'Autenticación exitosa',
        user: { id: user._id, username: user.username, role: user.role },
      });
    } catch (err) {
      next(err);
    }
  });

  // 404
  app.use((_req, _res, next) => next(new AppError(404, 'Recurso no encontrado')));

  // Manejador central de errores: nunca expone stack, mensajes internos ni datos de entrada
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    // JSON mal formado o body demasiado grande
    if (err.type === 'entity.parse.failed') {
      err = new AppError(400, 'JSON inválido');
    } else if (err.type === 'entity.too.large') {
      err = new AppError(413, 'Solicitud demasiado grande');
    }

    if (err instanceof AppError) {
      const body = { error: err.publicMessage };
      if (err.details) body.details = err.details;
      return res.status(err.status).json(body);
    }

    // Error inesperado: se registra internamente (sin body) y se responde genérico
    console.error(`[${new Date().toISOString()}] ${req.method} ${req.path}`, err.name, err.message);
    return res.status(500).json({ error: 'Error interno del servidor' });
  });

  return app;
}

module.exports = { createApp };
