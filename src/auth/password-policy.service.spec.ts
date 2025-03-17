import { Test, TestingModule } from '@nestjs/testing';
import { PasswordPolicyService } from './password-policy.service';

// Different approach to mocking
jest.mock('zxcvbn');

import zxcvbn from 'zxcvbn';

describe('PasswordPolicyService', () => {
  let service: PasswordPolicyService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PasswordPolicyService],
    }).compile();

    service = module.get<PasswordPolicyService>(PasswordPolicyService);
    
    // Reset mock before each test
    jest.resetAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validatePassword', () => {
    it('should consider password valid with score >= 3', () => {
      // Setup mock for this test
      (zxcvbn as jest.Mock).mockReturnValue({
        score: 3,
        feedback: { warning: '', suggestions: [] }
      });
      
      const result = service.validatePassword('StrongP@ss123', 'test@example.com', 'Test User');
      expect(result.isValid).toBe(true);
    });
    
    it('should consider password invalid with score < 3', () => {
      // Setup mock for this test
      (zxcvbn as jest.Mock).mockReturnValue({
        score: 2,
        feedback: { warning: 'Too simple', suggestions: ['Add more complexity'] }
      });
      
      const result = service.validatePassword('simple123', 'test@example.com', 'Test User');
      expect(result.isValid).toBe(false);
    });
  });

  describe('specific password validations', () => {
    it('should check minimum length', () => {
      expect(service.hasMinimumLength('12345678')).toBe(true);
      expect(service.hasMinimumLength('1234567')).toBe(false);
    });
    
    it('should check for uppercase characters', () => {
      expect(service.hasUppercase('abcDef')).toBe(true);
      expect(service.hasUppercase('abcdef')).toBe(false);
    });
    
    it('should check for lowercase characters', () => {
      expect(service.hasLowercase('ABcDEF')).toBe(true);
      expect(service.hasLowercase('ABCDEF')).toBe(false);
    });
    
    it('should check for numbers', () => {
      expect(service.hasNumbers('abc123')).toBe(true);
      expect(service.hasNumbers('abcdef')).toBe(false);
    });
    
    it('should check for special characters', () => {
      expect(service.hasSpecialCharacters('abc@123')).toBe(true);
      expect(service.hasSpecialCharacters('abc123')).toBe(false);
    });
  });
}); 