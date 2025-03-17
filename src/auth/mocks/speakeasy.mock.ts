import { Injectable } from '@nestjs/common';

@Injectable()
export class SpeakeasyMockService {
  private secretsMap = new Map<string, { base32: string, otpauth_url: string }>();
  private validCodes = new Map<string, string[]>();

  generateSecret(options: { name: string }): { base32: string, otpauth_url: string } {
    const secret = {
      base32: `SECRET${Math.random().toString(36).substring(2, 10)}`,
      otpauth_url: `otpauth://totp/${options.name}?secret=MOCKBASE32SECRET`
    };
    
    this.secretsMap.set(options.name, secret);
    return secret;
  }

  // For testing, set valid codes for a specific secret
  setValidCodes(secret: string, codes: string[]): void {
    this.validCodes.set(secret, codes);
  }

  totp = {
    verify: (options: { secret: string, encoding: string, token: string, window?: number }): boolean => {
      const validCodes = this.validCodes.get(options.secret) || ['123456'];
      return validCodes.includes(options.token);
    }
  };
} 