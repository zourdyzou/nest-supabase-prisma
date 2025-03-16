import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import * as path from 'path';
import * as handlebars from 'handlebars';
import * as fs from 'fs';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly templateDir = path.join(process.cwd(), 'src', 'mail', 'templates');

  constructor(private configService: ConfigService) {
    // In development, log emails instead of sending them
    if (configService.get('NODE_ENV') === 'development') {
      this.transporter = nodemailer.createTransport({
        jsonTransport: true
      });
    } else {
      this.transporter = nodemailer.createTransport({
        host: configService.get('EMAIL_HOST'),
        port: configService.get('EMAIL_PORT'),
        secure: configService.get('EMAIL_PORT') === 465,
        auth: {
          user: configService.get('EMAIL_USER'),
          pass: configService.get('EMAIL_PASSWORD'),
        },
      });
    }
  }

  async sendMail({ to, subject, template, context }) {
    try {
      const templatePath = path.join(this.templateDir, `${template}.hbs`);
      const templateSource = fs.readFileSync(templatePath, 'utf8');
      const compiledTemplate = handlebars.compile(templateSource);
      const html = compiledTemplate(context);

      const result = await this.transporter.sendMail({
        from: this.configService.get('EMAIL_FROM'),
        to,
        subject,
        html,
      });

      if (this.configService.get('NODE_ENV') === 'development') {
        // In development, log the email instead of sending it
        console.log('Email not sent in development:');
        console.log('To:', to);
        console.log('Subject:', subject);
        console.log('Content:', html);
      }

      return result;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
} 