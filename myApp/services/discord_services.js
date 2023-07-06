const url = 'https://discord.com';
const token = 'Bot <token>'
const { APIService } = require('./main_services.js')
const apiService = new APIService();

function getMessages(channelId, rateLimit) {
    apiService.connect(url, {
        ':method': 'GET',
        ':path': `/api/v10/channels/${channelId}/messages?limit=${rateLimit}`, // Gönderilecek URL'nin yolu
        'Authorization': `${token}`,
        'Content-Type': 'application/json'
      })
}
function getGuild(guildId) {
    apiService.connect(url, {
        ':method': 'GET',
        ':path': `/api/v10/guilds/${guildId}`, // Gönderilecek URL'nin yolu
        'Authorization': `${token}`,
        'Content-Type': 'application/json'
      })
}
function getUser() {
    apiService.connect(url, {
        ':method': 'GET',
        ':path': '/api/v10/users/@me', // Gönderilecek URL'nin yolu
        'Authorization': `${token}`,
        'Content-Type': 'application/json'
      })
}
function getInvites(channelId) {
    apiService.connect(url, {
        ':method': 'GET',
        ':path': `/api/v10/guilds/${channelId}/invites`, // Gönderilecek URL'nin yolu
        'Authorization': `${token}`,
        'Content-Type': 'application/json'
      })
}

module.exports = { getGuild, getInvites, getMessages, getUser }