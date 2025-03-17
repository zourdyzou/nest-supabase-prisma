export interface JwtPayload {
  sub: number;       // User ID
  email: string;     // User email
  iat?: number;      // Issued at timestamp
  exp?: number;      // Expiration timestamp
  jti?: string;      // JWT ID for blacklisting
  deviceId?: string; // For device management
} 