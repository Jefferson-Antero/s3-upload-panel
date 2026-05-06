module.exports = {
  apps: [{
    name: 's3-upload-panel',
    script: 'server.js',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '256M',
    env: {
      NODE_ENV: 'production',
    },
  }],
};
