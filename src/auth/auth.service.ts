import { Injectable, ConflictException, InternalServerErrorException, UnauthorizedException, NotFoundException, Inject, Scope, BadRequestException } from '@nestjs/common';
import { REQUEST } from '@nestjs/core';
import { Request } from 'express';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { PrismaService } from '../prisma/prisma.service';
import { TokenResponseDto } from './dto/token-response.dto';
import { v4 as uuidv4 } from 'uuid';
import { ConfigService } from '@nestjs/config';
import { MailService } from '../mail/mail.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { UserEntity } from '../users/entities/user.entity';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { TwoFactorLoginDto } from './dto/two-factor.dto';
import { PasswordPolicyService } from './password-policy.service';

@Injectable({ scope: Scope.REQUEST })
export class AuthService {
  constructor(
    @Inject(REQUEST) private readonly request: Request,
    private usersService: UsersService,
    private jwtService: JwtService,
    private prisma: PrismaService,
    private configService: ConfigService,
    private mailService: MailService,
    private passwordPolicyService: PasswordPolicyService
  ) {}

  async login(loginDto: LoginDto): Promise<TokenResponseDto | { tempToken: string, requiresTwoFactor: true }> {
    const { email, password } = loginDto;
    const user = await this.usersService.findOneByEmail(email);
    
    // Check if account is locked
    if (user?.lockExpires && user.lockExpires > new Date()) {
      const remainingMinutes = Math.ceil((user.lockExpires.getTime() - Date.now()) / 60000);
      throw new UnauthorizedException(`Account is temporarily locked. Try again in ${remainingMinutes} minutes.`);
    }
    
    // Validate credentials
    if (!user || !(await bcrypt.compare(password, user.password))) {
      if (user) {
        // Increment attempts
        const maxAttempts = this.configService.get('MAX_LOGIN_ATTEMPTS');
        const lockoutTime = this.configService.get('ACCOUNT_LOCKOUT_TIME');
        const attempts = user.loginAttempts + 1;
        
        // Lock account after max attempts
        if (attempts >= maxAttempts) {
          const lockExpires = new Date();
          lockExpires.setMinutes(lockExpires.getMinutes() + lockoutTime);
          
          await this.prisma.user.update({
            where: { id: user.id },
            data: { 
              loginAttempts: 0, // Reset counter
              lockExpires: lockExpires,
            },
          });
          throw new UnauthorizedException(`Too many failed attempts. Account locked for ${lockoutTime} minutes.`);
        }
        
        // Update attempts counter
        await this.prisma.user.update({
          where: { id: user.id },
          data: { loginAttempts: attempts },
        });
      }
      throw new UnauthorizedException('Invalid credentials');
    }
    
    // Check if email is verified
    if (!user.isVerified) {
      throw new UnauthorizedException('Please verify your email before logging in');
    }
    
    // Reset login attempts on successful login
    if (user.loginAttempts > 0) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { loginAttempts: 0 },
      });
    }
    
    // If 2FA is enabled, return a temporary token
    if (user.twoFactorEnabled) {
      const tempPayload: JwtPayload = { 
        sub: user.id, 
        email: user.email
      };
      
      return {
        tempToken: this.jwtService.sign(tempPayload, { expiresIn: '5m' }),
        requiresTwoFactor: true
      };
    }
    
    // Standard login flow without 2FA
    return this.generateTokens(user);
  }

  async signup(createUserDto: CreateUserDto): Promise<TokenResponseDto> {
    const { email, password, name } = createUserDto;
    
    // Validate password strength
    const passwordValidation = this.passwordPolicyService.validatePassword(password, email, name);
    
    if (!passwordValidation.isValid) {
      throw new BadRequestException({
        message: 'Password is too weak',
        score: passwordValidation.score,
        feedback: passwordValidation.feedback
      });
    }
    
    const saltRounds = this.configService.get('BCRYPT_SALT_ROUNDS');
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const verifyToken = crypto.randomBytes(32).toString('hex');

    console.log('Verification token:', verifyToken);

    try {
      const userData = {
        ...createUserDto,
        password: hashedPassword,
      };
      
      const user = await this.usersService.create(userData, verifyToken);
      
      // Send verification email
      await this.sendVerificationEmail(user);
      
      return this.generateTokens(user);
    } catch (error) {
      if (error.code === 'P2002') { // Prisma unique constraint violation
        throw new ConflictException('Email already exists');
      }
      throw new InternalServerErrorException();
    }
  }

  async refreshToken(refreshToken: string): Promise<TokenResponseDto> {
    // Find the refresh token in the database
    const token = await this.prisma.token.findUnique({
      where: { value: refreshToken },
      include: { user: true },
    });

    // Check if token exists and is not expired
    if (!token || token.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Delete the old refresh token
    await this.prisma.token.delete({ where: { id: token.id } });

    // Generate new tokens
    return this.generateTokens(token.user);
  }

  async logout(userId: number, allDevices: boolean = false): Promise<{ success: boolean }> {
    if (allDevices) {
      // Revoke all tokens for this user
      await this.prisma.token.deleteMany({
        where: { userId },
      });
    } else {
      // Delete a single token
      const token = await this.prisma.token.findFirst({
        where: { userId },
      });
      
      if (token) {
        await this.prisma.token.delete({
          where: { id: token.id },
        });
      }
    }
    return { success: true };
  }

  async verifyEmail(token: string): Promise<{ success: boolean }> {
    const user = await this.prisma.user.findFirst({
      where: { verifyToken: token },
    });

    if (!user) {
      throw new NotFoundException('Invalid verification token');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isVerified: true,
        verifyToken: null,
      },
    });

    return { success: true };
  }

  async resendVerificationEmail(email: string): Promise<{ success: boolean }> {
    const user = await this.usersService.findOneByEmail(email);
    
    if (!user) {
      throw new NotFoundException('User not found');
    }
    
    if (user.isVerified) {
      throw new ConflictException('Email is already verified');
    }
    
    // Generate new verification token
    const verifyToken = crypto.randomBytes(32).toString('hex');
    
    await this.prisma.user.update({
      where: { id: user.id },
      data: { verifyToken },
    });
    
    await this.sendVerificationEmail({...user, verifyToken});
    
    return { success: true };
  }

  // Method to clean up expired tokens (call this periodically)
  async cleanupExpiredTokens(): Promise<number> {
    const result = await this.prisma.token.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
    return result.count;
  }

  async requestPasswordReset(email: string): Promise<{ success: boolean }> {
    const user = await this.usersService.findOneByEmail(email);
    
    // Always return success to prevent email enumeration attacks
    if (!user) {
      return { success: true };
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date();
    resetTokenExpiry.setHours(resetTokenExpiry.getHours() + 1); // 1 hour expiry
    
    // Store token in database
    await this.prisma.user.update({
      where: { id: user.id },
      data: { 
        resetToken,
        resetTokenExpiry
      },
    });
    
    // Send reset email
    const frontendUrl = this.configService.get('FRONTEND_URL');
    const resetUrl = `${frontendUrl}/reset-password?token=${resetToken}`;
    
    await this.mailService.sendMail({
      to: user.email,
      subject: 'Password Reset Request',
      template: 'password-reset',
      context: {
        name: user.name,
        resetUrl,
      },
    });
    
    return { success: true };
  }

  async resetPassword(token: string, newPassword: string): Promise<{ success: boolean }> {
    // Find user with this token
    const user = await this.prisma.user.findFirst({
      where: { 
        resetToken: token,
        resetTokenExpiry: { gt: new Date() } // Token must not be expired
      },
    });
    
    if (!user) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }
    
    // Validate password strength
    const passwordValidation = this.passwordPolicyService.validatePassword(
      newPassword, 
      user.email, 
      user.name
    );
    
    if (!passwordValidation.isValid) {
      throw new BadRequestException({
        message: 'Password is too weak',
        score: passwordValidation.score,
        feedback: passwordValidation.feedback
      });
    }
    
    // Hash new password
    const saltRounds = parseInt(this.configService.get('BCRYPT_SALT_ROUNDS'));
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Update user password and clear reset token
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiry: null,
        // Reset login attempts and lock expires if they exist
        loginAttempts: 0,
        lockExpires: null
      },
    });
    
    // Invalidate all existing refresh tokens for this user for security
    await this.prisma.token.deleteMany({
      where: { userId: user.id },
    });
    
    return { success: true };
  }

  private async generateTokens(user: any): Promise<TokenResponseDto> {
    const payload: JwtPayload = { 
      email: user.email, 
      sub: user.id,
      deviceId: uuidv4()
    };
    
    // Generate refresh token
    const refreshTokenValue = uuidv4();
    const refreshExpiresAt = new Date();
    const refreshExpirationDays = parseInt(this.configService.get('JWT_REFRESH_EXPIRATION', '7'));
    refreshExpiresAt.setDate(refreshExpiresAt.getDate() + refreshExpirationDays);
    
    // Store refresh token in database
    await this.prisma.token.create({
      data: {
        value: refreshTokenValue,
        userId: user.id,
        expiresAt: refreshExpiresAt,
        deviceId: payload.deviceId,
        userAgent: this.request?.headers['user-agent'] || 'Unknown Device',
        ipAddress: this.request?.ip || 'Unknown IP',
        lastUsed: new Date()
      },
    });
    
    // Remove sensitive data from user object
    const { password, verifyToken, resetToken, twoFactorSecret, ...userWithoutSensitiveInfo } = user;
    
    return {
      access_token: this.jwtService.sign(payload, { 
        expiresIn: this.configService.get('JWT_ACCESS_EXPIRATION', '15m') 
      }),
      refresh_token: refreshTokenValue,
      user: userWithoutSensitiveInfo as Partial<UserEntity>,
    };
  }

  private async sendVerificationEmail(user: UserEntity): Promise<void> {
    // Log to debug
    console.log('Verification token:', user.verifyToken);
    
    // Make sure we have a token
    if (!user.verifyToken) {
      console.error('Missing verification token for user:', user.email);
      return;
    }
    
    const frontendUrl = this.configService.get('FRONTEND_URL');
    const verificationUrl = `${frontendUrl}/verify-email?token=${user.verifyToken}`;
    
    console.log('Verification URL:', verificationUrl);
    
    await this.mailService.sendMail({
      to: user.email,
      subject: 'Please verify your email',
      template: 'email-verification',
      context: {
        name: user.name,
        verificationUrl,
      },
    });
  }

  async generateTwoFactorSecret(userId: number): Promise<{ secret: string, otpAuthUrl: string, qrCode: string }> {
    const user = await this.usersService.findOne(userId);
    
    if (!user) {
      throw new NotFoundException('User not found');
    }
    
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `YourApp:${user.email}`
    });
    
    // Store secret in database (but don't enable 2FA yet)
    await this.prisma.user.update({
      where: { id: userId },
      data: { 
        twoFactorSecret: secret.base32,
        twoFactorEnabled: false
      }
    });
    
    // Generate QR code
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);
    
    return {
      secret: secret.base32,
      otpAuthUrl: secret.otpauth_url,
      qrCode
    };
  }

  async verifyAndEnableTwoFactor(userId: number, code: string): Promise<boolean> {
    const user = await this.usersService.findOne(userId);
    
    if (!user || !user.twoFactorSecret) {
      throw new NotFoundException('User not found or 2FA not initiated');
    }
    
    // Verify code
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code
    });
    
    if (!verified) {
      throw new UnauthorizedException('Invalid authentication code');
    }
    
    // Enable 2FA
    await this.prisma.user.update({
      where: { id: userId },
      data: { twoFactorEnabled: true }
    });
    
    return true;
  }

  async disableTwoFactor(userId: number, password: string): Promise<boolean> {
    const user = await this.usersService.findOne(userId);
    
    if (!user) {
      throw new NotFoundException('User not found');
    }
    
    // Verify password before disabling 2FA
    if (!(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid password');
    }
    
    // Disable 2FA
    await this.prisma.user.update({
      where: { id: userId },
      data: { 
        twoFactorEnabled: false,
        twoFactorSecret: null
      }
    });
    
    return true;
  }

  async verifyTwoFactorAndLogin(twoFactorDto: TwoFactorLoginDto): Promise<TokenResponseDto> {
    try {
      // Verify temp token
      const decoded = this.jwtService.verify(twoFactorDto.tempToken) as JwtPayload;
      
      const user = await this.usersService.findOne(decoded.sub);
      
      if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
        throw new UnauthorizedException('Invalid user or 2FA not enabled');
      }
      
      // Verify TOTP code
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorDto.code,
        window: 1 // Allow 1 period before/after for clock drift
      });
      
      if (!verified) {
        throw new UnauthorizedException('Invalid authentication code');
      }
      
      // Complete login
      return this.generateTokens(user);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Two-factor authentication timeout');
      }
      throw error;
    }
  }
}