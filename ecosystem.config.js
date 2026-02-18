module.exports = {
  apps: [
    {
      name: 'toolzyhub-api',
      script: './src/server.js',
      cwd: __dirname,
      instances: 4,
      exec_mode: 'cluster',
      node_args: '--expose-gc --max-old-space-size=4096',
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'development',
        PORT: 3010
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3010
      },
      log_file: './logs/combined.log',
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      watch: false,
      ignore_watch: ['node_modules', 'logs'],
      min_uptime: '10s',
      max_restarts: 5,
      autorestart: true,
      kill_timeout: 5000,
      listen_timeout: 3000,
      health_check_grace_period: 10000,
      merge_logs: true,
      time: true
    }
  ]
};