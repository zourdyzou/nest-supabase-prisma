import { Injectable } from '@nestjs/common';
import * as csurf from 'csurf';

// Export factory function for Express compatibility
export const csrfMiddleware = csurf({ 
  cookie: true,
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});
