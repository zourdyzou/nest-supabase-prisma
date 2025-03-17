import { Controller, Post, Body, UseGuards, Get, Request, Query, HttpCode } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { UsersService } from '../users/users.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody, ApiQuery } from '@nestjs/swagger';
import { TokenResponseDto } from './dto/token-response.dto';
import { Throttle } from '@nestjs/throttler';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyTwoFactorDto, TwoFactorLoginDto, EnableTwoFactorDto } from './dto/two-factor.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private usersService: UsersService
  ) {}

  @Post('login')
  @ApiOperation({ summary: 'User login' })
  @ApiResponse({ status: 200, description: 'Returns tokens and user info', type: TokenResponseDto })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async login(@Body() loginDto: LoginDto): Promise<TokenResponseDto | { tempToken: string; requiresTwoFactor: true }> {
    return this.authService.login(loginDto);
  }

  @Post('signup')
  @ApiOperation({ summary: 'User registration' })
  @ApiResponse({ status: 201, description: 'User successfully created', type: TokenResponseDto })
  @ApiResponse({ status: 409, description: 'Email already exists' })
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  async signup(@Body() createUserDto: CreateUserDto): Promise<TokenResponseDto> {
    return this.authService.signup(createUserDto);
  }
  
  @Post('refresh')
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 200, description: 'Returns new tokens', type: TokenResponseDto })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  @ApiBody({ schema: { properties: { refresh_token: { type: 'string' } } } })
  async refresh(@Body('refresh_token') token: string): Promise<TokenResponseDto> {
    return this.authService.refreshToken(token);
  }

  @Post('logout')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  @ApiOperation({ summary: 'Logout user' })
  @ApiResponse({ status: 200, description: 'Logout successful' })
  @ApiBody({ schema: { properties: { all_devices: { type: 'boolean' } } } })
  async logout(@Request() req, @Body('all_devices') allDevices: boolean = false) {
    return this.authService.logout(req.user.id, allDevices);
  }
  
  @Get('verify-email')
  @ApiOperation({ summary: 'Verify user email' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  @ApiResponse({ status: 404, description: 'Invalid verification token' })
  @ApiQuery({ name: 'token', required: true })
  async verifyEmail(@Query('token') token: string) {
    return this.authService.verifyEmail(token);
  }

  @Post('resend-verification')
  @ApiOperation({ summary: 'Resend verification email' })
  @ApiResponse({ status: 200, description: 'Verification email sent' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiBody({ schema: { properties: { email: { type: 'string' } } } })
  @Throttle({ default: { limit: 2, ttl: 60000 } })
  async resendVerification(@Body('email') email: string) {
    return this.authService.resendVerificationEmail(email);
  }
  
  @Get('profile')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({ status: 200, description: 'Returns the user profile' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getProfile(@Request() req) {
    return this.usersService.findOne(req.user.id);
  }

  @Post('forgot-password')
  @ApiOperation({ summary: 'Request password reset email' })
  @ApiResponse({ status: 200, description: 'Reset email sent if account exists' })
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.requestPasswordReset(forgotPasswordDto.email);
  }

  @Post('reset-password')
  @ApiOperation({ summary: 'Reset password with token' })
  @ApiResponse({ status: 200, description: 'Password reset successful' })
  @ApiResponse({ status: 401, description: 'Invalid or expired token' })
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.password
    );
  }

  @Post('2fa/generate')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Generate 2FA secret and QR code' })
  @ApiResponse({ status: 200, description: 'Returns 2FA setup information' })
  async generateTwoFactor(@Request() req) {
    return this.authService.generateTwoFactorSecret(req.user.id);
  }

  @Post('2fa/verify')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Verify and enable 2FA' })
  @ApiResponse({ status: 200, description: '2FA enabled successfully' })
  @ApiResponse({ status: 401, description: 'Invalid verification code' })
  async verifyAndEnableTwoFactor(@Request() req, @Body() verifyDto: VerifyTwoFactorDto) {
    return this.authService.verifyAndEnableTwoFactor(req.user.id, verifyDto.code);
  }

  @Post('2fa/disable')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Disable 2FA' })
  @ApiResponse({ status: 200, description: '2FA disabled successfully' })
  @ApiResponse({ status: 401, description: 'Password verification failed' })
  async disableTwoFactor(@Request() req, @Body() disableDto: EnableTwoFactorDto) {
    return this.authService.disableTwoFactor(req.user.id, disableDto.password);
  }

  @Post('2fa/authenticate')
  @ApiOperation({ summary: 'Complete login with 2FA code' })
  @ApiResponse({ status: 200, description: 'Returns authentication tokens' })
  @ApiResponse({ status: 401, description: 'Invalid 2FA code or expired token' })
  async twoFactorAuth(@Body() twoFactorDto: TwoFactorLoginDto) {
    return this.authService.verifyTwoFactorAndLogin(twoFactorDto);
  }

  @Get('csrf-token')
  @ApiOperation({ summary: 'Get a CSRF token' })
  getCsrfToken(@Request() req) {
    return { csrfToken: req.csrfToken() };
  }
}