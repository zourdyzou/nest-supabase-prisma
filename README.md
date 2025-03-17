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

# Nest Supabase Starter

A robust, secure authentication starter kit built with NestJS, Prisma, and Supabase. This starter kit provides complete authentication flows including signup with email verification, login with rate limiting, password reset, and token-based authentication.

## Features

- 🔐 Complete authentication flow (signup, login, logout)
- ✉️ Email verification
- 🔑 Password reset functionality
- 🔄 Refresh token rotation
- 🛡️ Rate limiting and brute force protection
- 📝 Extensive API documentation with Swagger
- 🔒 JWT-based authentication
- 🗄️ Supabase database with Prisma ORM
- 🔐 Two-Factor Authentication (TOTP)
- 🛡️ CSRF Protection
- 🔒 Advanced password policy enforcement
- 📱 Device management and active sessions
- ⚙️ Comprehensive test suite (unit and e2e)

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

4. Set up the database and start the application:
   ```bash
   npm run setup    # Install dependencies and set up the database
   npm run dev      # Start development server with Prisma client generation
   ```

## Environment Configuration

Configure the following environment variables in your `.env` file:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | Supabase connection string with pgBouncer for connection pooling |
| `DIRECT_URL` | Direct Supabase connection string (for migrations) |
| `PORT` | Port the server runs on (default: 3000) |
| `JWT_SECRET` | Secret key for JWT token generation |
| `JWT_ACCESS_EXPIRATION` | Access token expiration time (e.g., 15m, 1h) |
| `JWT_REFRESH_EXPIRATION` | Refresh token expiration in days (e.g., 7) |
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

## Security Features

### Two-Factor Authentication

The API supports TOTP-based two-factor authentication:

1. **Setup 2FA**: Users can generate a secret and QR code for authentication apps
2. **Enable 2FA**: After scanning the QR code, users verify with a code to enable 2FA
3. **2FA Login Flow**: When 2FA is enabled, login requires additional verification
4. **Disable 2FA**: Users can disable 2FA with password verification

```bash
# Generate 2FA Secret and QR code
POST /auth/2fa/generate

# Verify and Enable 2FA
POST /auth/2fa/verify
{ "code": "123456" }

# Complete login with 2FA
POST /auth/2fa/authenticate
{ "tempToken": "...", "code": "123456" }

# Disable 2FA
POST /auth/2fa/disable
{ "password": "yourpassword" }
```

### Password Policies

The API enforces strong password requirements:

- Minimum length (8 characters)
- Mix of uppercase and lowercase letters
- Numbers and special characters
- Checks against common passwords
- Contextual validation (avoids using personal information)

### CSRF Protection

Cross-Site Request Forgery protection is enabled for all state-changing operations:

1. Request a CSRF token: `GET /auth/csrf-token`
2. Include the token in the `csrf-token` header for all POST/PUT/DELETE requests

### Session Management

Users can manage their active sessions:

```bash
# View active sessions
GET /auth/sessions

# Terminate specific session
DELETE /auth/sessions/:id

# Terminate all other sessions
DELETE /auth/sessions
```

## API Documentation

Once the application is running, access Swagger documentation at:
```
http://localhost:3000/api
```

### Key Endpoints

#### Authentication
- **POST /auth/signup** - Register a new user
- **POST /auth/login** - Authenticate a user
- **POST /auth/refresh** - Refresh access token
- **POST /auth/logout** - Log out user (revoke tokens)
- **GET /auth/profile** - Get user profile (protected)

#### Email Verification
- **GET /auth/verify-email** - Verify email with token
- **POST /auth/resend-verification** - Resend verification email

#### Password Management
- **POST /auth/forgot-password** - Request password reset
- **POST /auth/reset-password** - Reset password with token

#### Two-Factor Authentication
- **POST /auth/2fa/generate** - Generate 2FA secret and QR code
- **POST /auth/2fa/verify** - Verify and enable 2FA
- **POST /auth/2fa/authenticate** - Complete login with 2FA
- **POST /auth/2fa/disable** - Disable 2FA

#### Security
- **GET /auth/csrf-token** - Get CSRF token
- **GET /auth/sessions** - List active sessions
- **DELETE /auth/sessions/:id** - Terminate specific session
- **DELETE /auth/sessions** - Terminate all other sessions

## Development Commands

### Application
```bash
# Run development server
npm run dev

# Build for production
npm run build

# Run in production mode
npm run start:prod

# Complete setup (install dependencies + db setup)
npm run setup
```

### Database Management
```bash
# Generate Prisma client
npm run prisma:generate

# Run migrations
npm run prisma:migrate

# Reset database
npm run prisma:reset

# Seed database
npm run prisma:seed

# Open Prisma Studio
npm run prisma:studio

# Complete database setup (generate, migrate, seed)
npm run db:setup

# Reset and reseed database
npm run db:reset
```

### Testing
```bash
# Run unit tests
npm test

# Run tests with coverage
npm run test:cov

# Run end-to-end tests
npm run test:e2e

# Watch mode
npm run test:watch
```

## Testing

The API includes comprehensive test coverage:

### Unit Tests
- Authentication service and guards
- Password policy enforcement
- Two-factor authentication logic

### Integration Tests
- Complete authentication flows
- Email verification process
- Password reset functionality
- Two-factor authentication flow
- CSRF protection

## Email Service with Resend

This API uses [Resend](https://resend.com) for reliable email delivery with beautiful HTML templates. Resend provides:

- Superior email deliverability rates
- Email analytics and tracking
- Beautiful, responsive HTML email templates
- Developer-friendly API
- Reliable infrastructure

### Email Templates

The application includes professionally designed, responsive email templates for:
- Email verification
- Password reset
- Welcome emails
- Account notifications

Templates are built using Handlebars for dynamic content injection and support both desktop and mobile email clients.

### Using the Mail Service

To send emails using the templates, inject the `MailService` into your service or controller:

```typescript
constructor(private mailService: MailService) {}
```

Then use the `sendMail` method with the appropriate template and context:

```typescript
// Send welcome email
await this.mailService.sendMail({
  to: user.email,
  subject: 'Welcome to Our Platform!',
  template: 'welcome',
  context: {
    name: user.name,
    dashboardUrl: `${this.configService.get('FRONTEND_URL')}/dashboard`
  }
});

// Send verification email
await this.mailService.sendMail({
  to: user.email,
  subject: 'Please Verify Your Email',
  template: 'email-verification',
  context: {
    name: user.name,
    verificationUrl: `${this.configService.get('FRONTEND_URL')}/verify?token=${verifyToken}`
  }
});

// Send password reset email
await this.mailService.sendMail({
  to: user.email,
  subject: 'Reset Your Password',
  template: 'password-reset',
  context: {
    resetUrl: `${this.configService.get('FRONTEND_URL')}/reset-password?token=${resetToken}`
  }
});

// Send account notification
await this.mailService.sendMail({
  to: user.email,
  subject: 'Account Security Alert',
  template: 'account-notification',
  context: {
    name: user.name,
    notificationTitle: 'New Login Detected',
    notificationMessage: 'A new login was detected from an unknown device.',
    notificationDate: new Date().toLocaleString(),
    ipAddress: '192.168.1.1',
    deviceInfo: 'Chrome on Windows',
    actionRequired: true,
    securitySettingsUrl: `${this.configService.get('FRONTEND_URL')}/settings/security`
  }
});
```

Each template requires specific context variables to fill in the dynamic content of the email.

### Email Configuration

Configure the email service in your `.env` file:

```
# Email Configuration
RESEND_API_KEY=re_your_api_key_here
EMAIL_FROM=noreply@yourdomain.com
```

### Development Mode

In development mode, emails are not actually sent - they are logged to the console for easy debugging.

### Custom Templates

Email templates are located in `src/mail/templates` as `.hbs` files. You can customize these templates to match your brand identity without changing any code.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Useful Links

- [NestJS Documentation](https://docs.nestjs.com/)
- [Prisma Documentation](https://www.prisma.io/docs/)
- [Supabase Documentation](https://supabase.com/docs)
- [JWT.io](https://jwt.io/)
- [TOTP RFC](https://datatracker.ietf.org/doc/html/rfc6238)

## Contributing

Thank you for considering contributing to this project! Here's how you can help make this project better.

### Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) to understand what actions will and will not be tolerated.

### Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/nestjs-auth-api.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`
4. Install dependencies: `npm install`
5. Copy .env.example to .env and configure for local development
6. Start the development server: `npm run dev`

### Development Process

1. Make your changes and ensure they follow the project's coding style
2. Add or update tests as necessary
3. Make sure all tests pass: `npm test`
4. Update documentation if needed
5. Commit your changes following the commit message convention

### Pull Request Process

1. Update the README.md or relevant documentation with details of your changes if applicable
2. Make sure your PR passes all CI checks
3. The PR will be merged once it receives approval from a maintainer

### Commit Message Convention

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Examples:
- `feat: add two-factor authentication`
- `fix: correct email template rendering`
- `docs: update API documentation`
- `test: add missing test for auth controller`

### Types:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Changes that don't affect the code's meaning (white-space, formatting, etc)
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `perf`: A code change that improves performance
- `test`: Adding missing tests or correcting existing tests
- `build`: Changes that affect the build system or external dependencies
- `ci`: Changes to our CI configuration files and scripts
- `chore`: Other changes that don't modify src or test files

### Reporting Bugs

When reporting bugs, please use the bug report template and include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Screenshots if applicable
- Environment details (OS, Node.js version, etc.)

### Feature Requests

Feature requests are welcome! Please use the feature request template and provide:

- A clear and descriptive title
- A detailed description of the proposed feature
- Any relevant examples or mockups
- Explanation of why this feature would be useful to most users

### Code Style

This project uses ESLint and Prettier to enforce a consistent code style. Before committing, please ensure your code follows these standards:

```bash
# Run linting
npm run lint

# Fix linting issues
npm run lint:fix

# Format code with Prettier
npm run format
```

### Testing Requirements

All new features must include appropriate tests:

- Unit tests for individual components
- Integration tests for API endpoints
- E2E tests for complete flows

Test coverage should not decrease with new contributions.

Thank you for contributing!