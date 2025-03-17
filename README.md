<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>

<p align="center">
  <a href="https://nestjs.com" target="_blank"><img src="https://img.shields.io/badge/NestJS-E0234E?style=for-the-badge&logo=nestjs&logoColor=white" alt="NestJS" /></a>
  <a href="https://supabase.com" target="_blank"><img src="https://img.shields.io/badge/Supabase-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white" alt="Supabase" /></a>
  <a href="https://www.prisma.io" target="_blank"><img src="https://img.shields.io/badge/Prisma-2D3748?style=for-the-badge&logo=prisma&logoColor=white" alt="Prisma" /></a>
  <a href="https://www.typescriptlang.org" target="_blank"><img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" /></a>
  <a href="https://jwt.io" target="_blank"><img src="https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white" alt="JWT" /></a>
</p>

# NestJS Authentication API

A robust, secure authentication and user management API built with NestJS, Prisma, and Supabase. This API provides complete authentication flows including signup with email verification, login with rate limiting, password reset, and token-based authentication.

## Features

- 🔐 Complete authentication flow (signup, login, logout)
- ✉️ Email verification
- 🔑 Password reset functionality
- 🔄 Refresh token rotation
- 🛡️ Rate limiting and brute force protection
- 📝 Extensive API documentation with Swagger
- 🔒 JWT-based authentication
- 🗄️ Supabase database with Prisma ORM

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Supabase account for database
- SMTP server for email functionality

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/nestjs-auth-api.git
   cd nestjs-auth-api
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up environment variables:
   - Copy the `.env.example` file to `.env`
   - Fill in the required values (see Environment Configuration below)

4. Run database migrations:
   ```bash
   npx prisma migrate dev
   ```

5. Start the application:
   ```bash
   npm run start:dev
   ```

## Environment Configuration

Configure the following environment variables in your `.env` file:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | Supabase connection string with pgBouncer for connection pooling |
| `DIRECT_URL` | Direct Supabase connection string (for migrations) |
| `OPENAI_API_KEY` | Your OpenAI API key (if using AI features) |
| `PORT` | Port the server runs on (default: 3000) |
| `JWT_SECRET` | Secret key for JWT token generation |
| `NODE_ENV` | Environment (development/production) |
| `FRONTEND_URL` | URL of the frontend application (for email links) |
| `EMAIL_HOST` | SMTP host for sending emails |
| `EMAIL_PORT` | SMTP port |
| `EMAIL_USER` | SMTP username |
| `EMAIL_PASSWORD` | SMTP password |
| `EMAIL_FROM` | From address for sent emails |
| `THROTTLE_TTL` | Rate limiting time window in seconds |
| `THROTTLE_LIMIT` | Maximum requests in time window |
| `BCRYPT_SALT_ROUNDS` | Rounds of hashing for passwords |
| `MAX_LOGIN_ATTEMPTS` | Max failed login attempts before lockout |
| `ACCOUNT_LOCKOUT_TIME` | Account lockout duration in minutes |

## API Documentation

Once the application is running, access Swagger documentation at:


### Key Endpoints

- **POST /auth/signup** - Register a new user
- **POST /auth/login** - Authenticate a user
- **POST /auth/refresh** - Refresh access token
- **POST /auth/logout** - Log out user (revoke tokens)
- **GET /auth/verify-email** - Verify email with token
- **POST /auth/resend-verification** - Resend verification email
- **POST /auth/forgot-password** - Request password reset
- **POST /auth/reset-password** - Reset password with token
- **GET /auth/profile** - Get user profile (protected)

## Development

### Running Tests

```bash
npm run test
```

### Linting

### e2e tests

```bash
npm run test:e2e
```

### Cleanup

```bash
npm run cleanup
```


### Run migrations

```bash
npx prisma migrate dev
```

### Run seed

```bash
npx prisma db seed
```

### Reset database 

```bash
npx prisma db reset
```


## Security Features

- Password hashing with bcrypt
- JWT token-based authentication
- Account lockout after failed login attempts
- Email verification
- CSRF protection
- Rate limiting
- Secure HTTP headers

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Useful Links

- [NestJS Documentation](https://docs.nestjs.com/)
- [Prisma Documentation](https://www.prisma.io/docs/)
- [Supabase Documentation](https://supabase.com/docs)