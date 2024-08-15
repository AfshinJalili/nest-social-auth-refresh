import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { compare, hash } from 'bcryptjs';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/users/schema/user.schema';
import { Response } from 'express';
import { TokenPayload } from './token-payload.interface';
@Injectable()
export class AuthService {
  private readonly JWT_ACCESS_TOKEN_EXPIRATION_MS: number;

  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {
    this.JWT_ACCESS_TOKEN_EXPIRATION_MS = parseInt(
      this.configService.getOrThrow<string>('JWT_ACCESS_TOKEN_EXPIRATION_MS'),
    );
  }

  async verifyUser(email: string, password: string): Promise<any> {
    try {
      const user = await this.usersService.getUser({ email });
      const authenticated = await compare(password, user.password);
      if (!authenticated) {
        throw new UnauthorizedException();
      }
      return user;
    } catch (error) {
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  async login(user: User, response: Response) {
    const expiresAccessToken = new Date();
    expiresAccessToken.setMilliseconds(
      expiresAccessToken.getMilliseconds() +
        this.JWT_ACCESS_TOKEN_EXPIRATION_MS,
    );
    const tokenPayload: TokenPayload = { userId: user._id.toHexString() };
    const accessToken = this.jwtService.sign(tokenPayload, {
      expiresIn: `${this.JWT_ACCESS_TOKEN_EXPIRATION_MS}ms`,
      secret: this.configService.getOrThrow<string>('JWT_ACCESS_TOKEN_SECRET'),
    });

    const expiresRefreshToken = new Date();
    expiresRefreshToken.setMilliseconds(
      expiresRefreshToken.getMilliseconds() +
        parseInt(
          this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION_MS'),
        ),
    );
    const refreshToken = this.jwtService.sign(tokenPayload, {
      expiresIn: `${this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION_MS')}ms`,
      secret: this.configService.getOrThrow<string>('JWT_REFRESH_TOKEN_SECRET'),
    });

    await this.usersService.updateUser(
      { _id: user._id },
      { $set: { refreshToken: await hash(refreshToken, 10) } },
    );

    response.cookie('Authentication', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresAccessToken,
    });

    response.cookie('Refresh', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresRefreshToken,
    });
  }

  async verifyRefreshToken(refreshToken: string, userId: string) {
    try {
      const user = await this.usersService.getUser({ _id: userId });
      const authenticated = await compare(refreshToken, user.refreshToken);
      if (!authenticated) {
        throw new UnauthorizedException();
      }
      return user;
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}
