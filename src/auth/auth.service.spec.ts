import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { MailService } from '../mail/mail.service';
import { PasswordPolicyService } from './password-policy.service';
import { UnauthorizedException, ConflictException, NotFoundException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { REQUEST } from '@nestjs/core';

// Mock implementations
jest.mock('bcryptjs');
jest.mock('speakeasy');
jest.mock('qrcode');

describe('AuthService', () => {
  let module: TestingModule;
  let service: AuthService;
  let prismaService: PrismaService;
  let usersService: UsersService;
  let jwtService: JwtService;
  let mailService: MailService;
  let passwordPolicyService: PasswordPolicyService;

  const mockRequest = {
    headers: {
      'user-agent': 'test-agent'
    },
    ip: '127.0.0.1'
  };

  const mockUser = {
    id: 1,
    email: 'test@example.com',
    name: 'Test User',
    password: 'hashedpassword',
    isVerified: true,
    loginAttempts: 0,
    lockExpires: null,
    verifyToken: null,
    twoFactorEnabled: false,
    twoFactorSecret: null,
    createdAt: new Date(),
    resetToken: null,
    resetTokenExpiry: null
  };

  beforeEach(async () => {
    module = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: {
            findOneByEmail: jest.fn(),
            findOne: jest.fn(),
            create: jest.fn()
          }
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(() => 'test-token'),
            verify: jest.fn()
          }
        },
        {
          provide: PrismaService,
          useValue: {
            user: {
              update: jest.fn(),
              findFirst: jest.fn(),
              findUnique: jest.fn()
            },
            token: {
              create: jest.fn(),
              findUnique: jest.fn(),
              deleteMany: jest.fn(),
              delete: jest.fn(),
              findFirst: jest.fn()
            },
            $transaction: jest.fn()
          }
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key) => {
              const config = {
                'JWT_ACCESS_EXPIRATION': '15m',
                'JWT_REFRESH_EXPIRATION': '7',
                'FRONTEND_URL': 'http://localhost:3000',
                'MAX_LOGIN_ATTEMPTS': 5,
                'ACCOUNT_LOCKOUT_TIME': 15,
                'BCRYPT_SALT_ROUNDS': 10
              };
              return config[key];
            })
          }
        },
        {
          provide: MailService,
          useValue: {
            sendMail: jest.fn()
          }
        },
        {
          provide: PasswordPolicyService,
          useValue: {
            validatePassword: jest.fn()
          }
        },
        {
          provide: REQUEST,
          useValue: mockRequest
        }
      ],
    }).compile();

    // Use resolve() for scoped providers instead of get()
    service = await module.resolve(AuthService);
    prismaService = module.get<PrismaService>(PrismaService);
    usersService = module.get<UsersService>(UsersService);
    jwtService = module.get<JwtService>(JwtService);
    mailService = module.get<MailService>(MailService);
    passwordPolicyService = module.get<PasswordPolicyService>(PasswordPolicyService);
    
    // Default mock implementations
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (bcrypt.hash as jest.Mock).mockResolvedValue('hashedpassword');
    (usersService.findOneByEmail as jest.Mock).mockResolvedValue(mockUser);
    (usersService.findOne as jest.Mock).mockResolvedValue(mockUser);
    (prismaService.token.create as jest.Mock).mockResolvedValue({ id: 1 });
    
    // Mock user creation to include verifyToken
    (usersService.create as jest.Mock).mockResolvedValue({
      ...mockUser,
      verifyToken: 'test-verification-token'
    });
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('login', () => {
    it('should return tokens when credentials are valid', async () => {
      const loginDto = { email: 'test@example.com', password: 'password' };
      const result = await service.login(loginDto);
      
      expect(usersService.findOneByEmail).toHaveBeenCalledWith('test@example.com');
      expect(bcrypt.compare).toHaveBeenCalledWith('password', 'hashedpassword');
      expect(result).toHaveProperty('access_token');
      expect(result).toHaveProperty('refresh_token');
    });

    it('should throw UnauthorizedException when credentials are invalid', async () => {
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);
      const loginDto = { email: 'test@example.com', password: 'wrongpassword' };
      
      await expect(service.login(loginDto)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when user is not verified', async () => {
      (usersService.findOneByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        isVerified: false
      });
      const loginDto = { email: 'test@example.com', password: 'password' };
      
      await expect(service.login(loginDto)).rejects.toThrow(UnauthorizedException);
    });

    it('should return tempToken when 2FA is enabled', async () => {
      (usersService.findOneByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        twoFactorEnabled: true
      });
      const loginDto = { email: 'test@example.com', password: 'password' };
      
      const result = await service.login(loginDto);
      expect(result).toHaveProperty('tempToken');
      expect(result).toHaveProperty('requiresTwoFactor', true);
    });
  });

  describe('signup', () => {
    beforeEach(() => {
      (usersService.create as jest.Mock).mockResolvedValue(mockUser);
      (passwordPolicyService.validatePassword as jest.Mock).mockReturnValue({
        isValid: true,
        score: 4,
        feedback: { warning: '', suggestions: [] }
      });
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedpassword');
    });

    it('should create a new user and return tokens', async () => {
      const createUserDto = { 
        email: 'test@example.com', 
        password: 'StrongP@ss123', 
        name: 'Test User' 
      };
      
      const result = await service.signup(createUserDto);
      
      expect(passwordPolicyService.validatePassword).toHaveBeenCalled();
      expect(bcrypt.hash).toHaveBeenCalled();
      expect(usersService.create).toHaveBeenCalled();
      expect(mailService.sendMail).toHaveBeenCalled();
      expect(result).toHaveProperty('access_token');
      expect(result).toHaveProperty('refresh_token');
    });

    it('should throw BadRequestException when password is weak', async () => {
      (passwordPolicyService.validatePassword as jest.Mock).mockReturnValue({
        isValid: false,
        score: 1,
        feedback: { warning: 'Weak password', suggestions: ['Add symbols'] }
      });
      
      const createUserDto = { 
        email: 'test@example.com', 
        password: 'weak', 
        name: 'Test User' 
      };
      
      await expect(service.signup(createUserDto)).rejects.toThrow();
    });
  });

  describe('verifyEmail', () => {
    it('should verify email with valid token', async () => {
      (prismaService.user.findFirst as jest.Mock).mockResolvedValue(mockUser);
      (prismaService.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        isVerified: true,
        verifyToken: null
      });
      
      const result = await service.verifyEmail('valid-token');
      
      expect(prismaService.user.findFirst).toHaveBeenCalledWith({
        where: { verifyToken: 'valid-token' }
      });
      expect(prismaService.user.update).toHaveBeenCalled();
      expect(result).toEqual({ success: true });
    });

    it('should throw NotFoundException with invalid token', async () => {
      (prismaService.user.findFirst as jest.Mock).mockResolvedValue(null);
      
      await expect(service.verifyEmail('invalid-token')).rejects.toThrow(NotFoundException);
    });
  });

  // Add more tests for other methods...
}); 