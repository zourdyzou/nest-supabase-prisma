import { ApiProperty } from '@nestjs/swagger';
import { User } from '@prisma/client';

export class UserEntity implements User {
    @ApiProperty()
    id: number;

    @ApiProperty()
    name: string;

    @ApiProperty()
    email: string;

    @ApiProperty({ required: false })
    password: string | null;

    @ApiProperty()
    loginAttempts: number;

    @ApiProperty({ required: false })
    lockExpires: Date | null;

    @ApiProperty()
    isVerified: boolean;

    @ApiProperty({ required: false })
    verifyToken: string | null;

    @ApiProperty()
    createdAt: Date;
}
