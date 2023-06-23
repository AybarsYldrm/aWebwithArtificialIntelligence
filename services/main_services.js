const http2 = require('http2');
const fs = require('fs');
const crypto = require('crypto');

class APIService {
  constructor() {
    this.server = null;
    this.router = new Router();
    this.users = Object.values(this.loadUsersFromFile());
    this.sessionDuration = 300 * 1000
  }

  start(port) {
    const options = {
      key: fs.readFileSync('ssl/key.pem'),
      cert: fs.readFileSync('ssl/cert.pem'),
      allowHTTP1: true,
      keepAlive: true,
      sessionTimeout: 1000 * 300
    };

    this.server = http2.createSecureServer(options, this.handleRequest.bind(this));

    this.server.listen(port, () => {
      console.log(`API service is running on port ${port}`);
    });
  }

  handleRequest(req, res) {
    const method = req.method;
    const url = req.url;
  
    const route = this.router.matchRoute(method, url, true);
  
    if (route) {
      const handler = route.handler;
      handler(req, res, route.params);
    } else {
      res.statusCode = 404;
      res.end('route not found');
    }
  }  

  logoutHandler(req, res) {
    // Çerezleri silmek için "Set-Cookie" başlığını kullanarak geçerli zamanı geçmiş bir çerez gönderiyoruz
    res.setHeader('Set-Cookie', 'accessToken=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    res.setHeader('Content-Type', 'text/html');
    res.statusCode = 200;
    res.end('logout successful<br><a href="/referanse">return</a> <a href="/login">login</a>');
  }

  authenticateRequest(req) {
    const authHeader = req.headers.authorization;
    const cookieHeader = req.headers.cookie;
    let jwt = null;
  
    if (authHeader) {
      const [type, credentials] = authHeader.split(' ');
  
      if (type === 'Bearer') {
        jwt = credentials;
      }
    } else if (cookieHeader) {
      const jwtCookie = cookieHeader
        .split(';')
        .map(row => row.trim())
        .find(row => row.startsWith('accessToken='));
  
      if (jwtCookie) {
        jwt = jwtCookie.slice('accessToken='.length);
      }
    }
  
    if (jwt) {
      const users = this.getUsersFromFile();
      const payload = this.verifyJWT(req, jwt, users);
  
      if (payload) {
        return payload;
      }
    }
  
    return null;
  }
  

  loadUsersFromFile() {
    try {
      const fileData = fs.readFileSync('services/data/users.json', 'utf-8');
      const users = JSON.parse(fileData);
      return users;
    } catch (error) {
      console.error('file read error:', error);
      return {};
    }
  }

  deleteMessage(uuid) {
    const filePath = `services/data/questioning/${uuid}.json`;
  
    return new Promise((resolve, reject) => {
      fs.unlink(filePath, error => {
        if (error) {
          console.error('file deletion error:', error);
          reject(false);
        } else {
          console.log('message deleted successfullyi:', uuid);
          resolve(true);
        }
      });
    });
  }
  
  saveUsersToFile() {
    const jsonData = JSON.stringify(this.users, null, 2);

    fs.writeFile('services/data/users.json', jsonData, error => {
      if (error) {
        console.error('file read error:', error);
      } else {
        console.log('users have been successfully registered');
      }
    });
  }

  getUsersFromFile() {
    try {
      const fileData = fs.readFileSync('services/data/users.json', 'utf-8');
      const users = JSON.parse(fileData);
      return users;
    } catch (error) {
      console.error('file read error:', error);
      return [];
    }
  }

  getUserMessages(username) {
    const fileNames = fs.readdirSync('services/data/questioning');
    const jsonFiles = fileNames.filter(fileName => fileName.endsWith('.json'));
    const userMessages = [];
  
    jsonFiles.forEach(fileName => {
      const fileData = fs.readFileSync(`services/data/questioning/${fileName}`, 'utf-8');
      const parsedData = JSON.parse(fileData);
      if (parsedData.username === username) {
        userMessages.push(parsedData);
      }
    });
  
    return userMessages;
  } 

  addUser(username, password, token) {
    const user = {
      username: username,
      password: password,
      secret: token,
      role: 'user'
    };

    this.users.push(user);
    this.saveUsersToFile();
  }

  addRoute(method, path, handler, options = {}) {
    const { authenticate = false } = options;
    this.router.addRoute(method, path, this.authenticateHandler(handler, authenticate));
  }

  connect(url, headers, paylaod) {
    const client = http2.connect(url);
    const req = client.request(headers)
    req.write(paylaod)
    req.end()
  }
  createJWT(user, ip) {
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };

    const payload = {
      username: user.username,
      role: user.role,
      ip: ip,
      exp: Date.now() + this.sessionDuration // Oturumun sona erme zamanı
    };

    const headerBase64 = Buffer.from(JSON.stringify(header)).toString('base64');
    const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64');

    const signature = crypto.createHmac('sha256', user.secret)
      .update(`${headerBase64}.${payloadBase64}`)
      .digest('base64');

    const jwt = `${headerBase64}.${payloadBase64}.${signature}`;
    return jwt;
  }

  verifyJWT(req, jwt) {
    const [headerBase64, payloadBase64, signature] = jwt.split('.');
    const user = this.getUsersFromFile().find(u => u.secret === this.getSecretFromUsername(payloadBase64));
  
    if (!user) {
      return null;
    }
  
    const calculatedSignature = crypto.createHmac('sha256', user.secret)
      .update(`${headerBase64}.${payloadBase64}`)
      .digest('base64');
  
    if (calculatedSignature === signature) {
      const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
  
      // IP kontrolü yapılıyor
      if (payload.ip === req.socket.remoteAddress && payload.exp > Date.now()) {
        return payload;
      }
    }
  
    return null;
  }

  getSecretFromUsername(payloadBase64) {
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
    const user = this.getUsersFromFile().find(u => u.username === payload.username);
    return user ? user.secret : null;
  }

  authenticateHandler(handler, authenticate) {
    if (authenticate) {
      return (req, res, params) => {
        const paylaod = this.authenticateRequest(req);
  
        if (!paylaod) {
          res.statusCode = 401;
          res.setHeader('WWW-Authenticate', 'Bearer realm="API"');
          res.end('unauthorized');
          return;
        } 
  
        handler(req, res, params, paylaod);
      };
    } else {
      return handler;
    }
  }
}

class Router {
  constructor() {
    this.routes = [];
  }

  addRoute(method, path, handler, authenticate) {
    this.routes.push({ method, path, handler, authenticate });
  }

  matchRoute(method, url, allowDelete) {
    const urlSegments = url.split('/');
    for (const route of this.routes) {
      const routeSegments = route.path.split('/');
      if (route.method === method && routeSegments.length === urlSegments.length) {
        let match = true;
        const params = {};
        for (let i = 0; i < routeSegments.length; i++) {
          if (routeSegments[i] !== urlSegments[i] && !routeSegments[i].startsWith(':')) {
            match = false;
            break;
          } else if (routeSegments[i].startsWith(':')) {
            const paramName = routeSegments[i].substring(1);
            params[paramName] = urlSegments[i];
          }
        }
        if (match && (allowDelete || route.method !== 'DELETE')) {
          return { ...route, params };
        }
      }
    }
    return null;
  }
  
}


module.exports = { APIService, Router }