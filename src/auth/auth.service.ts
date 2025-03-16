import { Injectable, ConflictException, InternalServerErrorException, UnauthorizedException, NotFoundException } from '@nestjs/common';
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

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private prisma: PrismaService,
    private configService: ConfigService,
    private mailService: MailService
  ) {}

  async login(loginDto: LoginDto): Promise<TokenResponseDto> {
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
    
    return this.generateTokens(user);
  }

  async signup(createUserDto: CreateUserDto): Promise<TokenResponseDto> {
    const { email, password } = createUserDto;
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

  private async generateTokens(user: any): Promise<TokenResponseDto> {
    const payload = { email: user.email, sub: user.id };
    
    // Generate refresh token with longer expiry
    const refreshTokenValue = uuidv4();
    const refreshExpiresAt = new Date();
    const refreshExpirationDays = parseInt(this.configService.get('JWT_REFRESH_EXPIRATION', '7d').replace('d', ''));
    refreshExpiresAt.setDate(refreshExpiresAt.getDate() + refreshExpirationDays); // 7 days
    
    // Store refresh token in database
    await this.prisma.token.create({
      data: {
        value: refreshTokenValue,
        userId: user.id,
        expiresAt: refreshExpiresAt,
      },
    });
    
    // Remove sensitive data from user object
    const { password, verifyToken, ...userWithoutSensitiveInfo } = user;
    
    // Return both tokens and user info
    return {
      access_token: this.jwtService.sign(payload, { 
        expiresIn: this.configService.get('JWT_ACCESS_EXPIRATION', '15m') 
      }),
      refresh_token: refreshTokenValue,
      user: userWithoutSensitiveInfo,
    };
  }

  private async sendVerificationEmail(user: any): Promise<void> {
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
}