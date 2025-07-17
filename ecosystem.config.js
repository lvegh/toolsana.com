module.exports = {
  apps: [
    {
      name: 'toolzyhub-api',
      script: './src/server.js',
      instances: 'max', // Use all available CPU cores
      exec_mode: 'cluster',
      node_args: '--expose-gc --max-old-space-size=1024',
      env: {
        NODE_ENV: 'development',
        PORT: 3001
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3001
      },
      // Logging
      log_file: './logs/combined.log',
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',

      // Auto restart settings
      watch: false, // Set to true in development if needed
      ignore_watch: ['node_modules', 'logs'],

      // Advanced PM2 features
      min_uptime: '10s', // Increased from 10s
      max_restarts: 5,   // Reduced from 10
      autorestart: true,

      // Environment variables
      env_file: '.env',

      // Graceful shutdown
      kill_timeout: 5000,     // 30 seconds (increased from 5s)
      listen_timeout: 3000,   // 10 seconds (increased from 3s)


      // Health monitoring
      health_check_grace_period: 10000,

      // Merge logs from all instances
      merge_logs: true,

      // Time zone
      time: true
    }
  ],

  // Deployment configuration (optional)
  deploy: {
    production: {
      user: 'root',
      host: 'api.toolzyhub.app',
      ref: 'origin/main',
      repo: 'git@github.com:lvegh/api.toolzyhub.app.git',
      path: '/var/www/toolzyhub-api',
      'ssh_options': 'StrictHostKeyChecking=no',
      'post-deploy': 'cd /var/www/toolzyhub-api/current && npm install && pm2 reload ecosystem.config.js --env production'
    }
  }
};
