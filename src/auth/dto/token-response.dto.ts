import { ApiProperty } from '@nestjs/swagger';
import { UserEntity } from '../../users/entities/user.entity';

export class TokenResponseDto {
  @ApiProperty()
  access_token: string;
  
  @ApiProperty()
  refresh_token: string;
  
  @ApiProperty()
  user: UserEntity;
} 