import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { validationSchema } from './config/validation.schema';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { MailModule } from './mail/mail.module';
import { TasksModule } from './tasks/tasks.module';
import { ThrottlerModule } from '@nestjs/throttler';
import { csrfMiddleware } from './common/middlewares/csrf.middleware';
import * as cookieParser from 'cookie-parser';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '.env.local'],
      cache: true,
      validationSchema,
      validationOptions: {
        allowUnknown: true,
        abortEarly: true,
      },
    }),
    PrismaModule,
    UsersModule,
    AuthModule,
    MailModule,
    TasksModule,
    ThrottlerModule.forRoot([{
      ttl: 60000,
      limit: 10,
    }]),
  ],
  controllers: [],
  providers: [],
})
export class AppModule implements NestModule {
  constructor(private configService: ConfigService) {}

  configure(consumer: MiddlewareConsumer) {
    // Always apply cookie parser
    const middlewares = [cookieParser()];
    
    // Only apply CSRF in non-development environments
    const nodeEnv = this.configService.get('NODE_ENV', 'development');
    if (nodeEnv !== 'development') {
      middlewares.push(csrfMiddleware);
    }
    
    consumer.apply(...middlewares).forRoutes('*');
  }
}
