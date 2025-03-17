import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length } from 'class-validator';

export class EnableTwoFactorDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ 
    description: 'Current password for verification',
    required: true 
  })
  password: string;
}

export class VerifyTwoFactorDto {
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  @ApiProperty({ 
    description: 'Six-digit code from authenticator app',
    required: true,
    minLength: 6,
    maxLength: 6,
    example: '123456'
  })
  code: string;
}

export class TwoFactorLoginDto {
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  @ApiProperty({ 
    description: 'Six-digit code from authenticator app',
    required: true,
    minLength: 6,
    maxLength: 6
  })
  code: string;
  
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ 
    description: 'JWT from initial login step',
    required: true
  })
  tempToken: string;
} 