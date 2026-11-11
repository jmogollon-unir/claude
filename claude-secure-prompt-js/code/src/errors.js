/**
 * Errores controlados de la aplicación.
 * `publicMessage` es lo único que se expone al cliente.
 */
class AppError extends Error {
  constructor(status, publicMessage, details) {
    super(publicMessage);
    this.name = 'AppError';
    this.status = status;
    this.publicMessage = publicMessage;
    this.details = details; // solo para errores de validación (sin datos sensibles)
  }
}

// Mensaje único para cualquier fallo de autenticación (evita enumeración de usuarios)
class AuthenticationError extends AppError {
  constructor() {
    super(401, 'Credenciales inválidas');
    this.name = 'AuthenticationError';
  }
}

class ValidationError extends AppError {
  constructor(details) {
    super(400, 'Datos de entrada inválidos', details);
    this.name = 'ValidationError';
  }
}

module.exports = { AppError, AuthenticationError, ValidationError };
