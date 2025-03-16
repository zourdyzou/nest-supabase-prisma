import { Injectable, ConflictException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { PrismaService } from '../prisma/prisma.service';
import { TokenResponseDto } from './dto/token-response.dto';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private prisma: PrismaService
  ) {}

  async login(loginDto: LoginDto): Promise<TokenResponseDto> {
    const { email, password } = loginDto;
    const user = await this.usersService.findOneByEmail(email);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    return this.generateTokens(user);
  }

  async signup(createUserDto: CreateUserDto): Promise<TokenResponseDto> {
    const { email, password } = createUserDto;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const user = await this.usersService.create({
        ...createUserDto,
        password: hashedPassword,
      });
      
      return this.generateTokens(user);
    } catch (error) {
      if (error.code === 'P2002') { // Prisma unique constraint violation
        throw new ConflictException('Email already exists');
      }
      throw new InternalServerErrorException();
    }
  }

  async refreshToken(token: string): Promise<TokenResponseDto> {
    // Find the refresh token in the database
    const refreshToken = await this.prisma.token.findUnique({
      where: { token },
      include: { user: true },
    });

    // Check if token exists and is not expired
    if (!refreshToken || refreshToken.expires < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Delete the old refresh token
    await this.prisma.token.delete({ where: { id: refreshToken.id } });

    // Generate new tokens
    return this.generateTokens(refreshToken.user);
  }

  private async generateTokens(user: any): Promise<TokenResponseDto> {
    const payload = { email: user.email, sub: user.id };
    
    // Generate refresh token with longer expiry
    const refreshToken = uuidv4();
    const refreshExpires = new Date();
    refreshExpires.setDate(refreshExpires.getDate() + 7); // 7 days
    
    // Store refresh token in database
    await this.prisma.token.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expires: refreshExpires,
      },
    });
    
    // Remove password from user object
    const { password, ...userWithoutPassword } = user;
    
    // Return both tokens and user info
    return {
      access_token: this.jwtService.sign(payload, { expiresIn: '15m' }),
      refresh_token: refreshToken,
      user: userWithoutPassword,
    };
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    
    if (user && (await bcrypt.compare(password, user.password))) {
      const { password, ...result } = user;
      return result;
    }
    
    return null;
  }
}