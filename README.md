# Toolsana API

A secure, production-ready Node.js API server with token protection, rate limiting, and advanced security features. Built specifically to handle operations that can't run on Cloudflare Pages edge runtime, such as image processing with Sharp.

## Features

### 🔐 Security
- **JWT Authentication** with refresh tokens
- **API Key Authentication** for service-to-service communication
- **Rate Limiting** with Redis support and progressive slow-down
- **Brute Force Protection** for login attempts
- **CORS Configuration** with environment-specific settings
- **Security Headers** via Helmet.js
- **XSS Protection** and input sanitization
- **SQL Injection Protection**
- **Request Size Limiting**
- **IP Whitelisting/Blacklisting**

### 📊 Monitoring & Health Checks
- **Health Check Endpoints** (`/health`, `/ready`, `/live`)
- **Detailed System Metrics** (`/metrics`)
- **Comprehensive Logging** with Winston and daily rotation
- **Performance Monitoring**
- **Error Tracking** with stack traces in development

### 🚀 Performance & Scalability
- **PM2 Cluster Mode** configuration
- **Redis Caching** support
- **Compression** middleware
- **Graceful Shutdown** handling
- **Memory Management** with automatic restarts

### 🖼️ File Processing
- **Image Processing** with Sharp
- **File Upload** handling with validation
- **File Size Limits** and type restrictions
- **Automatic File Cleanup**

## Quick Start

### Prerequisites
- Node.js >= 18.0.0
- npm >= 8.0.0
- Redis (optional, for advanced features)
- PM2 (for production deployment)

### Installation

1. **Clone and install dependencies:**
```bash
git clone <repository-url>
cd toolzyhub-api
npm install
```

2. **Environment Configuration:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Development:**
```bash
npm run dev
```

4. **Production with PM2:**
```bash
npm run pm2:start
```

## Environment Variables

### Server Configuration
```env
NODE_ENV=development
PORT=3001
HOST=localhost
```

### JWT Configuration
```env
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h
JWT_REFRESH_SECRET=your-refresh-secret
JWT_REFRESH_EXPIRES_IN=7d
```

### Rate Limiting
```env
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
SLOW_DOWN_DELAY_AFTER=50
SLOW_DOWN_DELAY_MS=500
```

### CORS Configuration
```env
CORS_ORIGIN=http://localhost:3000,https://your-app.pages.dev
CORS_CREDENTIALS=true
```

### Redis (Optional)
```env
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
```

## API Endpoints

### Health & Monitoring
- `GET /health` - Basic health check
- `GET /health/detailed` - Detailed system information
- `GET /ready` - Kubernetes readiness probe
- `GET /live` - Kubernetes liveness probe
- `GET /metrics` - System metrics
- `GET /status` - Service status
- `GET /version` - Version information

### API Information
- `GET /api` - API welcome message
- `GET /api/info` - Detailed API information
- `GET /api/docs` - API documentation

## PM2 Commands

```bash
# Start the application
npm run pm2:start

# Stop the application
npm run pm2:stop

# Restart the application
npm run pm2:restart

# Delete the application
npm run pm2:delete

# View logs
npm run pm2:logs

# Monitor processes
npm run pm2:monit
```

## Development Commands

```bash
# Start development server with nodemon
npm run dev

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Lint code
npm run lint

# Fix linting issues
npm run lint:fix
```

## Security Features

### Authentication
- JWT tokens with configurable expiration
- Refresh token mechanism
- API key authentication for services
- Token blacklisting on logout

### Rate Limiting
- Basic rate limiting for all endpoints
- Strict rate limiting for sensitive endpoints
- Progressive slow-down for suspicious activity
- Brute force protection for login attempts

### Input Validation
- Request sanitization
- XSS protection
- SQL injection prevention
- File type and size validation

## File Structure

```
toolzyhub-api/
├── src/
│   ├── config/
│   │   └── redis.js
│   ├── middleware/
│   │   ├── auth.js
│   │   ├── cors.js
│   │   ├── errorHandler.js
│   │   ├── rateLimit.js
│   │   └── security.js
│   ├── routes/
│   │   ├── health.js
│   │   └── index.js
│   ├── utils/
│   │   ├── fileSystem.js
│   │   └── logger.js
│   └── server.js
├── logs/
├── uploads/
├── .env.example
├── ecosystem.config.js
├── package.json
└── README.md
```

## Error Handling

The API uses a comprehensive error handling system:

### Error Response Format
```json
{
  "success": false,
  "message": "Error description",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "errors": [] // Optional detailed errors
}
```

### Success Response Format
```json
{
  "success": true,
  "message": "Success message",
  "data": {}, // Response data
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## Logging

The application uses Winston for comprehensive logging:

- **Console logging** in development
- **File logging** with daily rotation
- **Error logging** with stack traces
- **Access logging** for HTTP requests
- **Security event logging**

Log files are stored in the `logs/` directory:
- `combined-YYYY-MM-DD.log` - All logs
- `error-YYYY-MM-DD.log` - Error logs only
- `access-YYYY-MM-DD.log` - HTTP access logs

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Run linting and tests
6. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For support, email support@toolzyhub.com or create an issue on GitHub.
