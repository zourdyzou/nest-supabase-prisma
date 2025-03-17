import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';
import * as path from 'path';
import * as handlebars from 'handlebars';
import * as fs from 'fs';

handlebars.registerHelper('currentYear', () => new Date().getFullYear());

@Injectable()
export class MailService {
  private resend: Resend;
  private readonly templateDir = path.join(process.cwd(), 'src', 'mail', 'templates');
  private readonly fromEmail: string;

  constructor(private configService: ConfigService) {
    this.fromEmail = this.configService.get<string>('EMAIL_FROM', 'noreply@yourdomain.com');
    
    // Initialize Resend in production, use dev mode in development
    if (configService.get('NODE_ENV') === 'development') {
      // In development, we'll use a mock implementation
      this.resend = {
        emails: {
          send: async (options) => {
            console.log('Email not sent in development:');
            console.log('To:', options.to);
            console.log('Subject:', options.subject);
            console.log('Content:', options.html);
            return { id: 'mock-id', from: options.from };
          }
        }
      } as any;
    } else {
      const apiKey = this.configService.get<string>('RESEND_API_KEY');
      if (!apiKey) {
        throw new Error('RESEND_API_KEY is not defined in environment variables');
      }
      this.resend = new Resend(apiKey);
    }
  }

  async sendMail({ to, subject, template, context }) {
    try {
      // Load and compile template using existing Handlebars setup
      const templatePath = path.join(this.templateDir, `${template}.hbs`);
      const templateSource = fs.readFileSync(templatePath, 'utf8');
      const compiledTemplate = handlebars.compile(templateSource);
      const html = compiledTemplate(context);

      // Send email with Resend
      const result = await this.resend.emails.send({
        from: this.fromEmail,
        to,
        subject,
        html,
      });

      if (this.configService.get('NODE_ENV') === 'development') {
        // In development, log the email instead of sending it
        console.log('Email would be sent via Resend in production');
      }

      return result;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
} 