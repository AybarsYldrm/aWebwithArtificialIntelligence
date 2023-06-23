const { APIService } = require('./services/main_services.js')
const crypto = require('crypto')

const apiService = new APIService();
const sessions = {};

apiService.addRoute('POST', '/login', (req, res) => {
  let data = '';
  req.on('data', (chunk) => {
    data += chunk;
  });
  req.on('end', () => {
    const postData = JSON.parse(data.toString());

    const username = postData.username;
    const password = postData.password;

    const users = apiService.getUsersFromFile();
    const matchedUser = users.find(u => u.username === username && u.password === password);

    if (!matchedUser) {
      res.writeHead(401, { 'Content-Type': 'text/plain' });
      res.end('Unauthorized');
    } else {
      const ip = req.socket.remoteAddress;
      const jwt = apiService.createJWT(matchedUser, ip);

      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          success: true,
          message: jwt
        })
      );
    }
  });
});

apiService.addRoute('GET', '/secure', (req, res, params, paylaod) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end(`Hello, ${paylaod.username} (${paylaod.role})! This is a secure route.`);
}, { authenticate: true });


apiService.start(443)
