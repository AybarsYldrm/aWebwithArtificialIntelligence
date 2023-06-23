const crypto = require('crypto');
const fs = require('fs');
const { predictSentiment } = require('./services/brain_service.js')
const { APIService } = require('./services/main_services.js')

const apiService = new APIService();

apiService.addRoute('POST', '/questioning', (req, res, params, payload) => {
  let data = '';
  let byteLength = 0;

  const byteLimit = 1000; // İstediğiniz byte sınırını buraya yazın

  req.on('data', chunk => {
    // Byte sınırını kontrol et
    byteLength += chunk.length;

    if (byteLength > byteLimit) {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: false, message: 'write a message in the appropriate range 0-1000' }));
      req.destroy(); // İstek akışını sonlandır
      return;
    }

    data += chunk;
  });

  req.on('end', () => {
    // Eğer byte sınırı aşıldıysa hata yanıtı gönder
    if (byteLength > byteLimit) {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: false, message: 'write a message in the appropriate range 0-1000' }));
      return;
    }

    const postData = JSON.parse(data.toString());
    const sentiment = predictSentiment(postData.query);
    const uuid = crypto.randomUUID();
    const schema = {
      text: postData.query,
      date: new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', timeZoneName: 'short' }),
      uuid: uuid,
      sentiment: sentiment,
      username: payload.username,
      role: payload.role
    };

      const url = 'https://discord.com';
      const headers = {
        ':method': 'POST',
        ':path': '/api/webhooks/webhook_id/webhook_token', // Gönderilecek URL'nin yolu
        'Content-Type': 'application/json',
      }
      const content = JSON.stringify({
        "username": "Logger",
        "avatar_url": "",
        "embeds": [
          {
            "author": {
              "name": "Aybars Yildirim",
              "url": "https://192.168.1.16",
              "icon_url": ""
            },
            "title": "API Referanse",
            "url": "https://192.168.1.16/referanse",
            "description": "basit entegrasyonlu yapay zeka algoritmamın sonuclarıyla denemelerini buradan izleyebilirsiniz",
            "color": 16777215,
            "fields": [
              {
                "name": "message",
                "value": postData.query,
                "inline": true
              },
              {
                "name": "sentiment",
                "value": sentiment,
                "inline": true
              },           
            ],
            // "thumbnail": {
            //   "url": "https://upload.wikimedia.org/wikipedia/commons/3/38/4-Nature-Wallpapers-2014-1_ukaavUI.jpg"
            // },
            // "image": {
            //   "url": "https://upload.wikimedia.org/wikipedia/commons/5/5a/A_picture_from_China_every_day_108.jpg"
            // },
            "footer": {
              "text": `woah! so cool! ${new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', timeZoneName: 'short' })}`,
              "icon_url": "https://i.imgur.com/fKL31aD.jpg"
            }
          }
        ]
      })

      if(payload.role === 'admin') {
        apiService.connect(url, headers, content)
      }

    fs.appendFile(`services/data/questioning/${uuid}.json`, JSON.stringify(schema), error => {
      if (error) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            success: false,
            message: 'something went wrong'
          })
        );
        return;
      }

      if (postData.query) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            success: true,
            message: sentiment,
            uuid: uuid
          })
        );
      } else {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            success: false,
            message: 'error'
          })
        );
      }
    });
  });
}, { authenticate: true });

// apiService.addRoute('GET', '/questioning/:uuid', (req, res, params) => {
//   const { uuid } = params;

//   fs.readFile(`text/${uuid}.json`, 'utf-8', (error, data) => {
//     if (error) {
//       console.error('file read error:', error);
//       res.statusCode = 404;
//       res.end('not found');
//     } else {
//       const parsedData = JSON.parse(data);
//       res.setHeader('Content-Type', 'application/json');
//       res.end(JSON.stringify(parsedData));
//     }
//   });
// });

apiService.addRoute('DELETE', '/questioning/:uuid', async (req, res, params) => {
  const { uuid } = params;
  try {
    const success = await apiService.deleteMessage(uuid);

    if (success) {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: true, message: 'message deleted successfully' }));
    } else {
      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: false, message: 'message not found' }));
    }
  } catch (error) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ success: false, message: 'something went wrong' }));
  }
}, { authenticate: true });

apiService.addRoute('GET', '/referanse', (req, res) => {
  const htmlFile = fs.readFileSync('services/page/index.html', 'utf-8');

  res.setHeader('Content-Type', 'text/html');
  res.end(htmlFile);
});

apiService.addRoute('GET', '/login', (req, res) => {
  const htmlFile = fs.readFileSync('services/page/login.html', 'utf-8');

  res.setHeader('Content-Type', 'text/html');
  res.end(htmlFile);
});

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
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          success: false,
          message: 'someting is wrong'
        })
      );
    } else {
      const ip = req.socket.remoteAddress;
      const jwt = apiService.createJWT(matchedUser, ip);
      res.setHeader('Set-Cookie', `accessToken=${jwt}; HttpOnly; Max-Age=${3000 *1000 / 1000}; Secure;`);
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          success: true,
          message: 'user login successfully'
        })
      );
    }
  });
});

apiService.addRoute('GET', '/secure', (req, res, params, paylaod) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/html');
  res.end(`Hello, ${paylaod.username} (${paylaod.role})! This is a secure route.<br><a href="/referanse">return</a>`);
}, { authenticate: true });

apiService.addRoute('GET', '/about', (req, res) => {
  const htmlFile = fs.readFileSync('services/page/about.html', 'utf-8');

  res.setHeader('Content-Type', 'text/html');
  res.end(htmlFile);
});

apiService.addRoute('GET', '/discover', (req, res) => {
  const fileNames = fs.readdirSync('services/data/questioning');
  const jsonFiles = fileNames.filter(fileName => fileName.endsWith('.json'));
  const jsonData = [];

  jsonFiles.forEach(fileName => {
    const fileData = fs.readFileSync(`services/data/questioning/${fileName}`, 'utf-8');
    const parsedData = JSON.parse(fileData);
    jsonData.push(parsedData);
  });

  const html = generateDiscoverPage(jsonData);

  res.setHeader('Content-Type', 'text/html');
  res.end(html);
});

apiService.addRoute('GET', '/logout', apiService.logoutHandler.bind(apiService), { authenticate: true });

apiService.addRoute('GET', '/profile', (req, res) => {
  const payload = apiService.authenticateRequest(req);
  const userMessages = apiService.getUserMessages(payload.username);
  const usersData = apiService.getUsersFromFile()
  const filteredData = usersData.filter(data => data.username === payload.username);
  filteredData.forEach(user => {
    const token = user.secret;
    const html = generateProfilePage(payload, userMessages, token);
    res.setHeader('Content-Type', 'text/html');
    res.end(html);
  });
}, { authenticate: true });


apiService.addRoute('GET', '/create', (req, res) => {
  const htmlFile = fs.readFileSync('services/page/create.html', 'utf-8');

  res.setHeader('Content-Type', 'text/html');
  res.end(htmlFile);
});

apiService.addRoute('POST', '/create', (req, res, params) => {
  let data = '';

  req.on('data', chunk => {
    data += chunk;
  });

  req.on('end', () => {
    const postData = JSON.parse(data.toString());

    // Kullanıcı adı ve şifreyi alın
    const username = postData.username;
    const password = postData.password;

    // Kullanıcıyı kullanıcı listesine ekleyin
    if (!username && !password) {
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          success: false,
          message: 'someting is wrong'
        })
    )}
    else {
      const hmac = crypto.createHmac('sha256', password).update(username).digest('hex');
      apiService.addUser(username, password, hmac);

      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          success: true,
          message: 'user registered successfully'
        })
      );
    }
  });
});

function generateDiscoverPage(jsonData) {
  let html = '<html><head><meta charset="UTF-8"><title>discover page</title></head><body><h1>discover page</h1>';
  html += '<br><a href="/referanse">return</a></body></html>';
  jsonData.forEach(data => {
    html += '<hr>'; // Paragraf aralarına çizgi ekliyoruz
    for (const key in data) {
      if (key !== 'uuid') {
        html += `<p><strong>${key}:</strong> ${data[key]}</p>`; // Her özelliği paragraf olarak ekliyoruz
      }
    }
  });
  return html
}

function generateProfilePage(payload, userMessages, token) {
  let html = `<html><head><meta charset="UTF-8"><title>profile page</title></head><body><h1>hello ${payload.username} (${payload.role})</h1>`;
  html += `<p>your token: ${token}</p>`
  html += '<br><a href="/referanse">return</a></body></html>';

  userMessages.forEach(data => {
    html += '<hr>'; // Paragraf aralarına çizgi ekliyoruz
    for (const key in data) {
      if (key !== 'uuid') {
        html += `<p><strong>${key}:</strong> ${data[key]}</p>`; // Her özelliği paragraf olarak ekliyoruz
      }
    }

    html += `<button onclick="deleteMessage('${data.uuid}')">delete</button>`;
  });
  html += `<script>async function deleteMessage(uuid) {
    try {
      const response = await fetch('questioning/'+ uuid, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        // Başarı durumunda işlemler
        console.log('Mesaj başarıyla silindi.');
        // İstenirse sayfayı yenileyebilir veya diğer işlemleri gerçekleştirebilirsiniz.
      } else {
        // Hata durumunda işlemler
        console.log('Mesaj silinirken bir hata oluştu.');
        // Hata mesajını kullanıcıya gösterebilir veya diğer işlemleri gerçekleştirebilirsiniz.
      }
    } catch (error) {
      // Hata durumunda işlemler
      console.error('Mesaj silinirken bir hata oluştu:', error);
      // Hata mesajını kullanıcıya gösterebilir veya diğer işlemleri gerçekleştirebilirsiniz.
    }
  }
  </script>`
  return html;
}

apiService.start(443);
