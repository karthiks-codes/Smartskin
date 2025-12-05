// frontend/src/setupProxy.js
const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  const target = process.env.REACT_APP_API_URL || 'http://smartskin-backend:5000';
  app.use(
    '/api',
    createProxyMiddleware({
      target,
      changeOrigin: true,
      secure: false,
      logLevel: 'debug'
    })
  );

  // Optional: proxy static assets if backend is expected to serve them
  app.use(
    ['/favicon.ico','/logo192.png','/logo512.png'],
    createProxyMiddleware({
      target,
      changeOrigin: true,
      secure: false,
      logLevel: 'debug'
    })
  );
};
