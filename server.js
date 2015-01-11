require('dotenv').load();
['SIGNATURE_KEY', 'ENCRYPTION_KEY', 'AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET', 'COOKIE_SECRET']
    .forEach(function (v) { 
        require('assert').ok(process.env[v] !== undefined, v + ' environment variable not set.'); 
    });

var logger = require('./logger')
    , app = require('./app');

app.set('port', process.env.PORT || 3000);

logger.info({ port: app.get('port') }, 'setting up HTTP listener');
var server = app.listen(app.get('port'), function (error) {
    if (error) throw error;
    logger.info({ port: app.get('port') }, 'listening');
});