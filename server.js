require('dotenv').config();
[
'CURRENT_KEY',
'AUTH0_CALLBACK',
'SIGNATURE_KEY_' + process.env.CURRENT_KEY,
'ENCRYPTION_KEY_' + process.env.CURRENT_KEY,
'AUTH0_DOMAIN',
'AUTH0_CLIENT_ID',
'AUTH0_CLIENT_SECRET',
'COOKIE_SECRET'
].forEach(function (v) { 
    require('assert').ok(process.env[v] !== undefined, v + ' environment variable not set.'); 
});

var logger = require('./logger')
    , app = require('./app');

const https = require('https');
const fs = require('fs');

// serve the API with signed certificate on 443 (SSL/HTTPS) port
const httpsServer = https.createServer({
  key: fs.readFileSync('server.key'),       //('/etc/letsencrypt/live/my_api_url/privkey.pem'),
  cert: fs.readFileSync('server.cert')		 //('/etc/letsencrypt/live/my_api_url/fullchain.pem'),
}, app);

// httpsServer.listen(443, () => {
//     console.log('HTTPS Server running on port 443');
// });


app.set('port', process.env.PORT || 3000);

logger.info({ port: app.get('port') }, 'setting up HTTP listener');
// var server = app.listen(app.get('port'), function (error) {
var app = httpsServer.listen(3000, function (error) {
    if (error) throw error;
    logger.info({ port: 3000, current_key: process.env.CURRENT_KEY }, 'listening');
});
