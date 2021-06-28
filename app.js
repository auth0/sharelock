var express = require('express')
    , path = require('path')
    , favicon = require('serve-favicon')
    , cookieParser = require('cookie-parser')
    , bodyParser = require('body-parser')
    , session = require('express-session')
    , passport = require('passport')
    , swig = require('swig')
    , Auth0Strategy = require('passport-auth0')
    , logger = require('./logger')
    , crypto = require('crypto')
    , base64url = require('base64url')
    , cryptiles = require('cryptiles');

var keys = {};

var provider_friendly_name = {
    'facebook': 'Facebook',
    'google-oauth2': 'Google',
    'windowslive': 'Microsoft Account',
    'twitter': 'Twitter',
    'github': 'GitHub',
    'yahoo': 'Yahoo'
};

var strategy = new Auth0Strategy({
    domain: process.env.AUTH0_DOMAIN,
    clientID: process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET,
    callbackURL: process.env.AUTH0_CALLBACK,
    redirectUri: process.env.AUTH0_CALLBACK,    // <!-- upgrade to Lock 9 -->
    scope: "openid email profile"                       // <!-- upgrade to Lock 9 -->
}, function(accessToken, refreshToken, extraParams, profile, done) {
    // accessToken is the token to call Auth0 API (not needed in the most cases)
    // extraParams.id_token has the JSON Web Token
    // profile has all the information from the user
    return done(null, profile);
});

passport.use(strategy);

// This is not a best practice, but we want to keep things simple for now
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', swig.renderFile);

if ('development' === app.get('env')) {
    app.set('view cache', false);
    swig.setDefaults({ cache: false });
}

app.set('trust proxy', true);

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(function (req, res, next) {
    req.start_time = Date.now();
    res.on('finish', function () {
        var meta = {
            code: res.statusCode,
            time: new Date(),
            duration: Date.now() - req.start_time,
            path: req.path,
            method: req.method
        };
        if (res.statusCode >= 400)
            logger.warn(meta, res.statusCode);
        else
            logger.info(meta, res.statusCode);
    });
    next();
});

if (process.env.FORCE_HTTPS === '1') {
    logger.info('turning on HTTPS enforcement');
    if (!process.env.AUTH0_CALLBACK.includes('https')) logger.error('AUTH0_CALLBACK must be https when FORCE_HTTPS is on');

    app.use(function (req, res, next) {
        if (req.protocol === 'https'|| req.headers['x-arr-ssl'] || req.headers['x-forwarded-proto'] === 'https') {
            next();}
        else
            {return res.redirect('https://' + req.hostname + req.url);}
    });
}

app.use(cookieParser());
app.use(session({ secret: process.env.COOKIE_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public'), { index: false, redirect: false }));
app.use(contextualLocals);

app.get('/', function (req, res, next) {
    res.render('home.html');
});

app.get('/home', function(req,res,next){
    res.redirect('/');
})

app.get('/download', function(req,res,next){
    res.render('download.html');
})

app.get('/tos', function(req,res,next){
    res.render('tos.html');
})

app.get('/about', function(req,res,next){
    res.render('about.html');
})

app.get('/security', function(req,res,next){
    res.render('security.html');
})

app.get('/privacy', function(req,res,next){
    res.render('privacy.html');
})

app.get('/cookies', function(req,res,next){
    res.render('cookies.html');
})

app.get('/callback',
    passport.authenticate('auth0', { failureRedirect: '/unauthorized' }),
    function (req, res, next) {
        if (!req.user)
            res.send(403);
        else {
            var url = req.session.bookmark || '/';
            delete req.session.bookmark;
            res.redirect(url);
        }
    }
);

app.get('/logout',
    function (req, res, next) {
        req.session.destroy();
        res.redirect(req.query.r || '/');
    });

app.get('/new', function (req, res) {
    res.setHeader('Sunset', 'August 1st, 2021');
    res.status(410).render('410')
});

app.post('/create', (req, res) => {
  res.setHeader('Sunset', 'August 1st, 2021');
  res.status(410).json({message: "New secrets creation has been disabled. Sharelock.io is being ended and the service will be shut down August 1st, 2021. After this date Sharelock will no longer be available, and you will not be able to retrieve any previously shared secrets."})
}

    // bodyParser.json(),
    // bodyParser.urlencoded({ extended: false }),
    // current_create()

    );

// app.get('/test/500', function(req, res, next) {
//     if (app.get('env') === 'development') {
//         throw new Error('Internal Server Error');
//     }
//     next();
// });

app.get(/^\/(\w{1,10})\/(.+)$/,
    v1_get());



// catch 404 and forward to error handler
app.use(function(req, res, next) {
    res.status(404);
    res.render('404');
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        console.error(err);
        res.status(err.status || 500);
        res.render('500', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('500', {
        message: err.message,
        error: {}
    });
});

function normalize_gmail(email) {
    // Gmail emails don't allow @'s in name, so only one will be present
    var split = email.split('@');
    var name = split[0];
    var domain = split[1];
    return name.toLowerCase().replace(/\./g, '') + '@' + domain;
}

function current_create() {

    // current signature, encryption keys, and version
    var current_keys = ensure_key(process.env.CURRENT_KEY);
    var version_prefix = '/' + process.env.CURRENT_KEY + '/';

    return function (req, res, next) {
        if (!req.body.d)
            req.body.d = req.query.d;
        if (!req.body.a)
            req.body.a = req.query.a;
        if (typeof req.body.d !== 'string' || req.body.d.length === 0)
            return res.status(400).send('Missing data to secure. Use `d` parameter.');
        if (req.body.d.length > 500)
            return res.status(400).send('Data too large. Max 500 characters.');
        if (typeof req.body.a !== 'string' || req.body.a.length === 0)
            return res.status(400).send('Missing ACLs. Use `a` parameter.');
        if (req.body.a.length > 200)
            return res.status(400).send('ACLs too long. Max 200 characters.');

        var resource = {
            d: req.body.d,
            a: []
        };

        var tokens = req.body.a.split(/[\ \n\,\r]/);
        for (var i in tokens) {
            var token = tokens[i].trim();

            if (token.length === 0)
                continue;

            var match = token.match(/^\@([^\.]+)$/);
            if (match) {
                // twitter
                resource.a.push({
                    k: 't',
                    v: match[1]
                });
                continue;
            }

            match = token.match(/^\@([^\.]+\..+)$/);
            if (match) {
                // email domain
                resource.a.push({
                    k: 'd',
                    v: token
                });
                continue;
            }

            gmail_token = normalize_gmail(token);
            match = gmail_token.match('^[a-z0-9](\.?[a-z0-9]){5,}@g(oogle)?mail\.com$');
            if (match) {
                // gmail
                resource.a.push({
                    k: 'g',
                    v: gmail_token
                });
                continue;
            }

            match = token.match(/^[^\@]+\@[^\.]+\..+$/);
            if (match) {
                // email
                resource.a.push({
                    k: 'e',
                    v: token
                });
                continue;
            }

            return res.status(400).send('I don\'t understand what `' + token + '` means. You can say `@johnexample` for Twitter handle, `john@example.com` for e-mail address, or `@example.com` for e-mail domain.');
        }

        if (resource.a.length === 0)
            return res.status(400).send('At least one person allowed to access the secret must be specified.');

        var plaintext = JSON.stringify(resource);
        var iv = crypto.randomBytes(16);
        var cipher = crypto.createCipheriv('aes-256-ctr', current_keys.encryption_key, iv);
        var encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        var signature = crypto.createHmac('sha256', current_keys.signature_key).update(encrypted).update(iv).digest('base64');
        resource =
            base64url.fromBase64(signature)
            + '.' + base64url.fromBase64(encrypted.toString('base64'))
            + '.' + base64url.fromBase64(iv.toString('base64'));

        var split_resource = version_prefix;
        for (var i = 0; i < resource.length; i++) {
            split_resource += resource[i];
            if (((i + 1) % 50) === 0)
                split_resource += '/';
        }

        res.status(200).send(split_resource);
    };
}

function v1_get() {
    return function (req, res, next) {
        res.set('Cache-Control', 'no-cache');

        logger.info({ user: req.user ? req.user._json : undefined }, 'sharelock access request');
        typeof req.user !== 'undefined' ? req.user.provider=req.user._json.sub.match("^.*\\|")[0].replace("\|", "") : 'undefined';
        if (req.user && req.user.provider !== 'twitter' && !req.user._json.email_verified) {
            return res.render('invalid', { details: 'Your e-mail has not been verified'});
        }

        var request_keys;
        try {
            request_keys = ensure_key(req.params[0]);
        }
        catch (e) {
            return res.render('invalid', { details: 'For security reasons this sharelock is no longer supported.'});
        }

        var resource = req.params[1].replace(/\//g, '');
        var tokens = resource.split('.');
        if (tokens.length !== 3 || tokens[0].length === 0 || tokens[1].length === 0 || tokens[2].length === 0)
            return res.render('invalid', { details: 'The URL is malformed and cannot be processed.'});

        try {
            tokens[0] = base64url.toBase64(tokens[0]); // signature
            tokens[1] = new Buffer.from(base64url.toBase64(tokens[1]), 'base64'); // encrypted data
            tokens[2] = new Buffer.from(base64url.toBase64(tokens[2]), 'base64'); // iv
            var signature = crypto.createHmac('sha256', request_keys.signature_key).update(tokens[1]).update(tokens[2]).digest('base64');
            if (!cryptiles.fixedTimeComparison(signature, tokens[0]))
                throw null;
        }
        catch (e) {
            return res.render('invalid', { details: 'Signature verification failed: the data could have been tampered with.'});
        }

        try {
            var cipher = crypto.createDecipheriv('aes-256-ctr', request_keys.encryption_key, tokens[2]);
            var plaintext = cipher.update(tokens[1], 'base64', 'utf8') + cipher.final('utf8');
            resource = JSON.parse(plaintext);
            if (!resource || typeof resource !== 'object' || typeof resource.d !== 'string'
                || !Array.isArray(resource.a))
                throw null;
        }
        catch (e) {
            return res.render('invalid', { details: 'Encrypted data is malformed.' });
        }

        var allowed;
        var email = get_email(req.user);
        var aliases = get_aliases(req.user);
        var twitter;
        var email_domains = {};
        for (var i in resource.a) {
            var acl = resource.a[i];
            if (acl.k === 'g') {
                if (email && normalize_gmail(email) === acl.v) {
                    allowed = true;
                } else {
                    email_domains[acl.v.substring(acl.v.indexOf('@'))] = 1;
                }
            }
            else if (acl.k === 'e') {
                if (email === acl.v || aliases.indexOf(acl.v) >= 0) {
                    allowed = true;
                }
                else {
                    email_domains[acl.v.substring(acl.v.indexOf('@'))] = 1;
                }
            }
            else if (acl.k === 'd') {
                if (email && email.indexOf(acl.v, email.length - acl.v.length) !== -1) {
                    allowed = true;
                }
                else {
                    email_domains[acl.v] = 1;
                }
            }
            else if (acl.k === 't') {
                if (req.user && req.user.provider === 'twitter' && req.user._json.nickname.toLowerCase() === acl.v) {
                    allowed = true;
                }
                else {
                    twitter = true;
                }
            }

            if (allowed) break;
        }

        if (allowed) {
            var model = {
                data: resource.d,
                user: req.user,
                provider: provider_friendly_name[req.user.provider] || req.user.provider,
                logout_url: '/logout'
            };
            res.render('data', model);
        }
        else {
            email_domains = Object.getOwnPropertyNames(email_domains);
            var model = {
                auth0_client_id: process.env.AUTH0_CLIENT_ID,
                auth0_domain: process.env.AUTH0_DOMAIN,
                auth0_callback: process.env.AUTH0_CALLBACK,
                user: req.user,
                email: req.user ? get_email(req.user) : undefined,
                providers: get_provider_config(twitter, email_domains, req.user ? req.user.provider : undefined),
                allow_twitter: twitter,
                allow_domains: email_domains,
                provider: req.user ? (provider_friendly_name[req.user.provider] || req.user.provider) : undefined,
                logout_url: '/logout?r=' + req.originalUrl,
                provider_friendly_name: provider_friendly_name
            };

            req.session.bookmark = req.originalUrl;
            res.render('login', model);
        }
    };
}

var gmail_providers = ['google-oauth2', 'facebook', 'windowslive'];
var domain_provider_map = {
    '@googlemail.com': gmail_providers,
    '@gmail.com': gmail_providers,
    '@hotmail.com': ['windowslive', 'facebook'],
    '@live.com': ['windowslive', 'facebook'],
    '@outlook.com': ['windowslive', 'facebook'],
    '@msn.com': ['windowslive', 'facebook']
};

function get_provider_config(twitter, email_domains, provider) {
    var config = {
        preferred: []
    };

    if (twitter && provider !== 'twitter')
        config.preferred.push('twitter');

    email_domains.forEach(function (domain) {
        if (domain_provider_map[domain.toLowerCase()]) {
            config.preferred = config.preferred.concat(domain_provider_map[domain.toLowerCase()]);
        }
    });

    config.preferred = distinct(config.preferred);
    return config;
}

function get_aliases(user) {
    if (user && Array.isArray(user._json.aliases))
        return user._json.aliases;
    else
        return [];
}

function get_email(user) {
    if (user && (user._json.email_verified || user.provider === 'windowslive'))
        return user._json.email;
    else
        return undefined;
}

function ensure_key(key_name) {
    if (!keys[key_name]) {
        if (!process.env['SIGNATURE_KEY_' + key_name] || !process.env['ENCRYPTION_KEY_' + key_name])
            throw new Error('Cryptographic credentials are not available.');
        keys[key_name] = {
            signature_key: new Buffer.from(process.env['SIGNATURE_KEY_' + process.env.CURRENT_KEY], 'hex'),
            encryption_key: new Buffer.from(process.env['ENCRYPTION_KEY_' + process.env.CURRENT_KEY], 'hex')
        };
    }
    return keys[key_name];
}

function distinct(source) {
    var u = {}, a = [];
   for(var i = 0, l = source.length; i < l; ++i){
      if(u.hasOwnProperty(source[i])) {
         continue;
      }
      a.push(source[i]);
      u[source[i]] = 1;
   }

   return a;
}

function contextualLocals(req, res, next) {
    res.locals = res.locals || {};
    res.locals.context = res.locals.context || {};
    res.locals.context.protocol = req.protocol;
    res.locals.context.path = req.path;
    res.locals.context.url = req.url;
    res.locals.context.hostname = req.hostname;
    next();
}

module.exports = app;
