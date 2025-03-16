import * as Joi from 'joi';

export const validationSchema = Joi.object({
  // Environment
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  
  // Server
  PORT: Joi.number().default(3000),
  
  // Database
  DATABASE_URL: Joi.string().required(),
  
  // JWT Authentication
  JWT_SECRET: Joi.string().required().min(32)
    .description('JWT secret key - should be at least 32 characters long'),
  JWT_ACCESS_EXPIRATION: Joi.string().default('15m')
    .description('JWT access token expiration (e.g., 15m, 1h)'),
  JWT_REFRESH_EXPIRATION: Joi.string().default('7d')
    .description('JWT refresh token expiration (e.g., 7d, 30d)'),
  
  // Email (for verification)
  EMAIL_HOST: Joi.string()
    .when('NODE_ENV', { is: 'production', then: Joi.required() }),
  EMAIL_PORT: Joi.number()
    .when('NODE_ENV', { is: 'production', then: Joi.required() }),
  EMAIL_USER: Joi.string()
    .when('NODE_ENV', { is: 'production', then: Joi.required() }),
  EMAIL_PASSWORD: Joi.string()
    .when('NODE_ENV', { is: 'production', then: Joi.required() }),
  EMAIL_FROM: Joi.string()
    .when('NODE_ENV', { is: 'production', then: Joi.required() }),
  FRONTEND_URL: Joi.string().default('http://localhost:3000')
    .description('Frontend URL for email verification links'),
  
  // Rate limiting
  THROTTLE_TTL: Joi.number().default(60)
    .description('Rate limit window in seconds'),
  THROTTLE_LIMIT: Joi.number().default(10)
    .description('Maximum requests per TTL window'),
  
  // Security
  BCRYPT_SALT_ROUNDS: Joi.number().default(10)
    .description('Number of salt rounds for password hashing'),
  
  // Account lockout
  MAX_LOGIN_ATTEMPTS: Joi.number().default(5)
    .description('Maximum failed login attempts before account lockout'),
  ACCOUNT_LOCKOUT_TIME: Joi.number().default(15)
    .description('Account lockout time in minutes'),
}); 