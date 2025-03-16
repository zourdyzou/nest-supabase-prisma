import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class TasksService {
  private readonly logger = new Logger(TasksService.name);
  
  constructor(private authService: AuthService) {}
  
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleTokenCleanup() {
    this.logger.log('Running expired token cleanup');
    const count = await this.authService.cleanupExpiredTokens();
    this.logger.log(`Removed ${count} expired tokens`);
  }
} 