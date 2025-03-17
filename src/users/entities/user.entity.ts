import { ApiProperty } from '@nestjs/swagger';
import { User } from '@prisma/client';

export class UserEntity implements User {
    @ApiProperty({
      description: 'Unique identifier for the user',
      example: 1
    })
    id: number;

    @ApiProperty({
      description: 'Full name of the user',
      example: 'John Doe'
    })
    name: string;

    @ApiProperty({
      description: 'Email address of the user',
      example: 'john.doe@example.com'
    })
    email: string;

    @ApiProperty({ 
      required: false, 
      description: 'Hashed password',
      example: '$2a$10$Ew8ZS.../...'
    })
    password: string | null;

    @ApiProperty({
      description: 'Number of consecutive failed login attempts',
      example: 0
    })
    loginAttempts: number;

    @ApiProperty({ 
      required: false,
      description: 'Date until which the account is locked after multiple failed login attempts',
      example: '2023-10-15T14:30:00Z'
    })
    lockExpires: Date | null;

    @ApiProperty({
      description: 'Indicates whether the user has verified their email address',
      example: true
    })
    isVerified: boolean;

    @ApiProperty({ 
      required: false,
      description: 'Token used for email verification',
      example: '7c9e6679f7ae8e421f3743b5ff54c00c'
    })
    verifyToken: string | null;

    @ApiProperty({
      description: 'Date and time when the user account was created',
      example: '2023-09-01T10:30:00Z'
    })
    createdAt: Date;

    @ApiProperty({ 
      required: false,
      description: 'Token used for password reset requests',
      example: '3f7b5e12c8a9d2f4e6b8c1a3d5e7f9a2'
    })
    resetToken: string | null;

    @ApiProperty({ 
      required: false,
      description: 'Expiration date and time for the password reset token',
      example: '2023-10-15T14:30:00Z'
    })
    resetTokenExpiry: Date | null;

    @ApiProperty({ 
      required: false, 
      description: 'Secret key for two-factor authentication',
      example: null
    })
    twoFactorSecret: string | null;

    @ApiProperty({ 
      description: 'Whether two-factor authentication is enabled for this account',
      example: false
    })
    twoFactorEnabled: boolean;
}
