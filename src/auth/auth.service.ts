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
    expireInSecs = 15,
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
        expiresIn: `${expireInSecs}s`,
        secret,
      },
    );

    return token;
  }

  private async generateRefreshToken(
    userId: string,
    email: string,
    expireInSecs = 60,
  ): Promise<string> {
    const payload = {
      sub: userId,
      email,
    };
    const expiresIn = new Date();
    expiresIn.setSeconds(
      expiresIn.getSeconds() + expireInSecs,
    );

    const secret = this.configService.get(
      'JWT_SECRET_REFRESH',
    );

    const token = await this.jwtService.signAsync(
      payload,
      {
        expiresIn: `${expireInSecs}s`,
        secret,
      },
    );

    await this.prismaService.refreshToken.deleteMany(
      {
        where: {
          userId,
        },
      },
    );

    await this.prismaService.refreshToken.create({
      data: {
        userId,
        token,
        expiresIn: expiresIn.getTime(),
      },
    });

    return token;
  }

  private async signToken(
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

    let refresh: string;

    if (showRefreshToken) {
      refresh = await this.generateRefreshToken(
        userId,
        email,
      );
    }

    return {
      access_token: token,
      refresh_token: refresh,
    };
  }

  async signUp(dto: AuthDto) {
    const hashPassword = await argon.hash(
      dto.password,
    );

    try {
      const user =
        await this.prismaService.user.create({
          data: {
            email: dto.email,
            hash: hashPassword,
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

  async signIn(dto: AuthDto) {
    const user =
      await this.prismaService.user.findUnique({
        where: {
          email: dto.email,
        },
      });

    if (!user) {
      throw new ForbiddenException(
        'Credentials incorrect',
      );
    }

    const isMatchPassword = await argon.verify(
      user.hash,
      dto.password,
    );

    if (!isMatchPassword) {
      throw new ForbiddenException(
        'Credentials incorrect',
      );
    }

    return this.signToken(user.id, user.email);
  }

  async refresh(dto: RefreshAuthDto) {
    const foundedToken =
      await this.prismaService.refreshToken.findUnique(
        {
          where: {
            token: dto.refresh_token,
          },
        },
      );

    if (!foundedToken) {
      throw new ForbiddenException(
        'Invalid refresh token',
      );
    }

    const user =
      await this.prismaService.user.findUnique({
        where: {
          id: foundedToken.userId,
        },
      });

    if (foundedToken.expiresIn < Date.now()) {
      return this.signToken(user.id, user.email);
    }

    const { sub, email } =
      await this.jwtService.verifyAsync(
        dto.refresh_token,
        {
          secret: this.configService.get(
            'JWT_SECRET_REFRESH',
          ),
        },
      );

    return this.signToken(sub, email, false);
  }
}
