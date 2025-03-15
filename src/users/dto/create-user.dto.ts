import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, IsEmail } from "class-validator";

export class CreateUserDto {
    @IsString()
    @IsNotEmpty()
    @ApiProperty({ required: true })
    name: string;

    @IsEmail()
    @IsNotEmpty()
    @ApiProperty({ required: true })
    email: string;

    @IsString()
    @IsNotEmpty()
    @ApiProperty({ required: true })
    password: string;
}
