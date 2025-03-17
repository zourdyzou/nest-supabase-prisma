import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as csrf from 'csurf';

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private csrfProtection = csrf({ cookie: true });

  use(req: Request, res: Response, next: NextFunction) {
    // Skip CSRF for specific paths or methods
    if (req.method === 'GET' || req.path.includes('/auth/login') || req.path.includes('/auth/signup')) {
      return next();
    }
    
    this.csrfProtection(req, res, (err) => {
      if (err) {
        return next(new UnauthorizedException('Invalid CSRF token'));
      }
      next();
    });
  }
} 