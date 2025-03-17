import { Injectable } from '@nestjs/common';
import * as zxcvbn from 'zxcvbn';

@Injectable()
export class PasswordPolicyService {
  validatePassword(password: string, email: string, name: string): {
    isValid: boolean;
    score: number;
    feedback: {
      warning: string;
      suggestions: string[];
    };
  } {
    // Check password strength using zxcvbn
    const result = zxcvbn(password, [email, name]);
    
    // Password is considered valid if score is 3 or higher (0-4 scale)
    const isValid = result.score >= 3;
    
    return {
      isValid,
      score: result.score,
      feedback: result.feedback,
    };
  }
  
  // Additional methods for specific checks
  hasMinimumLength(password: string, length = 8): boolean {
    return password.length >= length;
  }
  
  hasUppercase(password: string): boolean {
    return /[A-Z]/.test(password);
  }
  
  hasLowercase(password: string): boolean {
    return /[a-z]/.test(password);
  }
  
  hasNumbers(password: string): boolean {
    return /\d/.test(password);
  }
  
  hasSpecialCharacters(password: string): boolean {
    return /[!@#$%^&*(),.?":{}|<>]/.test(password);
  }
} 