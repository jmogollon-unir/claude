const Joi = require('joi');
const { ValidationError } = require('./errors');

// Joi.string() rechaza objetos/arrays, por lo que {"$ne": null} nunca llega a la consulta.
// Lista blanca de caracteres: sin $, {, }, ., espacios ni caracteres de control.
const username = Joi.string()
  .trim()
  .lowercase()
  .pattern(/^[a-z0-9_-]{3,32}$/)
  .required();

const loginSchema = Joi.object({
  username,
  // No se aplica trim ni se modifica: la contraseña debe tratarse tal cual.
  // Máx. 72 bytes: límite real de bcrypt (evita truncamiento silencioso).
  password: Joi.string().min(1).max(72).required(),
});

const registerSchema = Joi.object({
  username,
  password: Joi.string()
    .min(10)
    .max(72)
    .pattern(/[a-z]/, 'minúscula')
    .pattern(/[A-Z]/, 'mayúscula')
    .pattern(/[0-9]/, 'dígito')
    .required(),
});

/**
 * Middleware de validación: rechaza campos desconocidos y reemplaza req.body
 * por el objeto validado/normalizado.
 */
function validateBody(schema) {
  return (req, _res, next) => {
    const { value, error } = schema.validate(req.body, {
      abortEarly: false,
      allowUnknown: false,
      convert: true, // aplica trim/lowercase; no convierte objetos en strings
    });

    if (error) {
      // Solo se informa el campo y el tipo de regla; nunca el valor recibido.
      const details = error.details.map((d) => ({
        field: d.path.join('.'),
        rule: d.type,
      }));
      return next(new ValidationError(details));
    }

    req.body = value;
    next();
  };
}

module.exports = { loginSchema, registerSchema, validateBody };
