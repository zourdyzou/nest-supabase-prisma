import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { User } from '@prisma/client';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) { }

  async create(createUserDto: CreateUserDto, verifyToken?: string): Promise<User> {
    return this.prisma.user.create({
      data: {
        ...createUserDto,
        verifyToken,
      },
    });
  }

  findAll() {
    return this.prisma.user.findMany();
  }

  findOne(id: number) {
    return this.prisma.user.findUnique({ where: { id: id } });
  }

  findOneByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return this.prisma.user.update({
      where: { id: id },
      data: updateUserDto
    });
  }

  remove(id: number) {
    return this.prisma.user.delete({ where: { id } })
  }
}
