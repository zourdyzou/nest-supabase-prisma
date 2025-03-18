import { resolve } from 'path';

module.exports = {
  apps: [{
    name: "nest-supabase-starter",
    script: resolve(__dirname, './dist/main.js'),
    instances: "max",
    exec_mode: "cluster",
    watch: false,
    env: {
      NODE_ENV: "production",
    },
    env_development: {
      NODE_ENV: "development",
      watch: true,
      ignore_watch: ["node_modules", "dist"]
    },
    max_memory_restart: "1G",
    exp_backoff_restart_delay: 100,
    merge_logs: true,
    log_date_format: "YYYY-MM-DD HH:mm:ss Z"
  }]
}; 