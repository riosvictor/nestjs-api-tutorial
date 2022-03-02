import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import { AuthDto } from './dto';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    // generate the password hash
    const hash = await argon.hash(dto.password);
    // save the new user in the db
    try {
      const user =
        await this.prismaService.user.create({
          data: {
            email: dto.email,
            hash,
          },
        });

      return this.signToken(user.id, user.email);
    } catch (error) {
      if (
        error instanceof
        PrismaClientKnownRequestError
      ) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'Credentials taken',
          );
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // find the user by email
    const user =
      await this.prismaService.user.findUnique({
        where: {
          email: dto.email,
        },
      });

    // if user not exists throw exception
    if (!user) {
      throw new ForbiddenException(
        'Credentials incorrect',
      );
    }

    // compare password
    const pwMatches = await argon.verify(
      user.hash,
      dto.password,
    );

    // if password incorrect throw exception
    if (!pwMatches) {
      throw new ForbiddenException(
        'Credentials incorrect',
      );
    }

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: string,
    email: string,
  ): Promise<{
    access_token: string;
  }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret =
      this.configService.get('JWT_SECRET');

    const token = await this.jwtService.signAsync(
      payload,
      {
        expiresIn: '15m',
        secret,
      },
    );

    return {
      access_token: token,
    };
  }
}
