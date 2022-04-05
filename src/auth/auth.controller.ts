import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto, RefreshAuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
  ) {}

  @Post('signup')
  signUp(@Body() dto: AuthDto) {
    return this.authService.signUp(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  signIn(@Body() dto: AuthDto) {
    return this.authService.signIn(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('/refresh')
  public async refresh(
    @Body() body: RefreshAuthDto,
  ) {
    return this.authService.refresh(body);
  }
}
