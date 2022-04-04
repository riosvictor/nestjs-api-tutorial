import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import { AuthDto, RefreshAuthDto } from './dto';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  private async generateToken(
    userId: string,
    email: string,
    expireInSecs?: number,
  ): Promise<string> {
    const payload = {
      sub: userId,
      email,
    };

    const secret =
      this.configService.get('JWT_SECRET');

    const token = await this.jwtService.signAsync(
      payload,
      {
        expiresIn: expireInSecs || '15s',
        secret,
      },
    );

    return token;
  }

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
    showRefreshToken = true,
  ): Promise<{
    access_token: string;
    refresh_token: string;
  }> {
    const token = await this.generateToken(
      userId,
      email,
    );
    const refresh = await this.generateToken(
      userId,
      email,
      60 * 60 * 24 * 30,
    );

    return {
      access_token: token,
      refresh_token: showRefreshToken
        ? refresh
        : undefined,
    };
  }

  async refresh(dto: RefreshAuthDto) {
    const { sub, email } =
      await this.jwtService.verifyAsync(
        dto.refresh_token,
        {
          secret:
            this.configService.get('JWT_SECRET'),
        },
      );

    return this.signToken(sub, email, false);
  }
}
