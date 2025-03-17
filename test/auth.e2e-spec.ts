import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import * as cookieParser from 'cookie-parser';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let csrfToken: string;
  let cookies: string[];

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    prismaService = app.get<PrismaService>(PrismaService);
    
    app.use(cookieParser());
    app.useGlobalPipes(new ValidationPipe());
    
    await app.init();
    
    // Clean up database before tests
    await prismaService.token.deleteMany({});
    await prismaService.user.deleteMany({});
  });

  afterAll(async () => {
    await prismaService.$disconnect();
    await app.close();
  });

  it('should get CSRF token', async () => {
    const response = await request(app.getHttpServer())
      .get('/auth/csrf-token')
      .expect(200);
    
    expect(response.body).toHaveProperty('csrfToken');
    csrfToken = response.body.csrfToken;
    cookies = Array.isArray(response.headers['set-cookie']) 
      ? response.headers['set-cookie'] 
      : [response.headers['set-cookie']];
  });

  describe('Authentication Flow', () => {
    const testUser = {
      email: 'test@example.com',
      password: 'StrongP@ssword123!',
      name: 'Test User'
    };
    
    let accessToken: string;
    let refreshToken: string;
    let verifyToken: string;
    
    it('should register a new user', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/signup')
        .set('Cookie', cookies)
        .set('csrf-token', csrfToken)
        .send(testUser)
        .expect(201);
      
      expect(response.body).toHaveProperty('access_token');
      expect(response.body).toHaveProperty('refresh_token');
      expect(response.body.user).toHaveProperty('email', testUser.email);
      expect(response.body.user).toHaveProperty('name', testUser.name);
      
      accessToken = response.body.access_token;
      refreshToken = response.body.refresh_token;
      
      // Get verification token from database for testing
      const user = await prismaService.user.findUnique({
        where: { email: testUser.email }
      });
      verifyToken = user.verifyToken;
    });

    it('should not allow login before email verification', async () => {
      await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password
        })
        .expect(401);
    });

    it('should verify email with token', async () => {
      await request(app.getHttpServer())
        .get(`/auth/verify-email?token=${verifyToken}`)
        .expect(200);
    });

    it('should login with verified email', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password
        })
        .expect(200);
      
      expect(response.body).toHaveProperty('access_token');
      expect(response.body).toHaveProperty('refresh_token');
    });

    it('should get user profile with token', async () => {
      await request(app.getHttpServer())
        .get('/auth/profile')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('email', testUser.email);
          expect(res.body).toHaveProperty('name', testUser.name);
        });
    });

    it('should refresh token', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', cookies)
        .set('csrf-token', csrfToken)
        .send({ refresh_token: refreshToken })
        .expect(200);
      
      expect(response.body).toHaveProperty('access_token');
      expect(response.body).toHaveProperty('refresh_token');
      
      // Update tokens for subsequent tests
      accessToken = response.body.access_token;
      refreshToken = response.body.refresh_token;
    });

    it('should not allow access with expired token', async () => {
      // Create an expired token
      const payload = { 
        sub: 1, 
        email: testUser.email, 
        iat: Math.floor(Date.now() / 1000) - 3600,
        exp: Math.floor(Date.now() / 1000) - 1800 // Expired 30 minutes ago
      };
      
      const jwtService = app.get('JwtService');
      const expiredToken = jwtService.sign(payload);
      
      await request(app.getHttpServer())
        .get('/auth/profile')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
    });

    it('should logout', async () => {
      await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('Cookie', cookies)
        .set('csrf-token', csrfToken)
        .expect(200);
    });
  });
  
  describe('Password Reset Flow', () => {
    const testUser = {
      email: 'reset@example.com',
      password: 'InitialP@ssword123!',
      name: 'Reset User'
    };
    
    let resetToken: string;
    
    beforeAll(async () => {
      // Create a user for password reset tests
      const saltRounds = 10;
      const bcrypt = require('bcryptjs');
      const hashedPassword = await bcrypt.hash(testUser.password, saltRounds);
      
      await prismaService.user.create({
        data: {
          email: testUser.email,
          name: testUser.name,
          password: hashedPassword,
          isVerified: true
        }
      });
    });
    
    it('should request password reset', async () => {
      await request(app.getHttpServer())
        .post('/auth/forgot-password')
        .send({ email: testUser.email })
        .expect(201);
      
      // Get reset token from database
      const user = await prismaService.user.findUnique({
        where: { email: testUser.email }
      });
      
      resetToken = user.resetToken;
      expect(resetToken).toBeDefined();
      expect(user.resetTokenExpiry).toBeInstanceOf(Date);
    });
    
    it('should reset password with token', async () => {
      const newPassword = 'NewStrongP@ssword456!';
      
      await request(app.getHttpServer())
        .post('/auth/reset-password')
        .send({
          token: resetToken,
          password: newPassword
        })
        .expect(201);
      
      // Verify token is cleared
      const user = await prismaService.user.findUnique({
        where: { email: testUser.email }
      });
      
      expect(user.resetToken).toBeNull();
      expect(user.resetTokenExpiry).toBeNull();
      
      // Verify login works with new password
      await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: newPassword
        })
        .expect(200);
    });
  });
}); 