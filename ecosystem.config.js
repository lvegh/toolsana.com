module.exports = {
  apps: [
    {
      name: 'toolzyhub-api',
      script: './src/server.js',
      instances: 1, // CHANGED: Single instance for AI processing
      exec_mode: 'fork', // CHANGED: Use fork mode instead of cluster

      // Node.js flags for better compatibility
      node_args: '--no-warnings --expose-gc --max-old-space-size=4096 --max-semi-space-size=128',

      env: {
        NODE_ENV: 'development',
        PORT: 3001
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3001
      },

      // Memory management
      max_memory_restart: '2G',

      // Logging
      log_file: './logs/combined.log',
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',

      // More conservative settings for AI workloads
      watch: false,
      ignore_watch: ['node_modules', 'logs'],
      min_uptime: '10s',
      max_restarts: 3, // Fewer restarts
      autorestart: true,

      // Environment variables
      env_file: '.env',

      // Longer timeouts for AI processing
      kill_timeout: 30000,
      listen_timeout: 10000,
      health_check_grace_period: 10000,

      // Merge logs
      merge_logs: true,
      time: true
    }
  ],

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