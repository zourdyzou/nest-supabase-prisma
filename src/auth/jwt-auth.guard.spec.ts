import { JwtAuthGuard } from './jwt-auth.guard';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [JwtAuthGuard],
    }).compile();

    guard = module.get<JwtAuthGuard>(JwtAuthGuard);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('handleRequest', () => {
    it('should return the user when authentication succeeds', () => {
      const user = { id: 1, email: 'test@example.com' };
      expect(guard.handleRequest(null, user, null)).toBe(user);
    });

    it('should throw UnauthorizedException when authentication fails', () => {
      expect(() => guard.handleRequest(null, null, null)).toThrow(UnauthorizedException);
    });

    it('should throw specific error message for token expiry', () => {
      const info = { name: 'TokenExpiredError' };
      expect(() => guard.handleRequest(null, null, info)).toThrow('Token expired');
    });

    it('should pass through other errors', () => {
      const error = new Error('Custom error');
      expect(() => guard.handleRequest(error, null, null)).toThrow(error);
    });
  });
}); 