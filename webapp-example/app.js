var express = require('express');
var passport = require('passport');
//var util = require('util');
var fs = require('fs')
const https = require('https')

//var ensureLoggedIn=require('connect-ensure-login').ensureLoggedIn();

//cfenv provides access to your Cloud Foundry environment
//for more info, see: https://www.npmjs.com/package/cfenv
var cfenv = require('cfenv');

//read IBMID SSO settings.js
var settings = { 
  credentials: {
    webApp_URL: 'https://localhost:3000',
    GOOGLE: {
      clientId: 'YourGoogleClientId',
      clientSecret: 'YourGoogleClientsecret'
    },
    TWITTER: {
      consumerKey: 'YourTwitterKey',
      consumerSecret: 'YourTwitterSecret'
    },
    FACEBOOK: {
      clientId: 'YourFacebookClientId',
      clientSecret: 'YourGoogleClientSecret'
    },
    LINKEDIN: {
      clientID: 'YourLinkedInClientId',
      clientSecret: 'YourLinkedInClientSecret'
    },
    IBMID: {
      client_id: 'YourIBMIDClientID',
      client_secret: 'YourIBMIDCLientSecret',
      discovery_url: 'https://www.discoveryendpoint.com/someendpointpathhere'
    }
  }
}
//get the app environment from Cloud Foundry
var appEnv = cfenv.getAppEnv();
if (appEnv.isLocal) {
  settings = require('./settings_local.js');
}

//work around intermediate CA issue
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

if(process.env.GOOGLE_clientId)
	settings.credentials.GOOGLE.clientId= process.env.GOOGLE_clientId;
if(process.env.GOOGLE_clientSecret)
	settings.credentials.GOOGLE.clientSecret= process.env.GOOGLE_clientSecret;

if(process.env.TWITTER_consumerKey)
	settings.credentials.TWITTER.consumerKey= process.env.TWITTER_consumerKey;
if(process.env.TWITTER_consumerSecret)
	settings.credentials.TWITTER.consumerSecret= process.env.TWITTER_consumerSecret;

if(process.env.FACEBOOK_clientId)
	settings.credentials.FACEBOOK.clientId= process.env.FACEBOOK_clientId;
if(process.env.FACEBOOK_clientSecret)
	settings.credentials.FACEBOOK.clientSecret= process.env.FACEBOOK_clientSecret;

if(process.env.LINKEDIN_clientID)
	settings.credentials.LINKEDIN.clientID= process.env.LINKEDIN_clientID;
if(process.env.LINKEDIN_clientSecret)
	settings.credentials.LINKEDIN.clientSecret= process.env.LINKEDIN_clientSecret;

if(process.env.IBMID_client_id)
		settings.credentials.IBMID.client_id= process.env.IBMID_client_id;
if(process.env.IBMID_client_secret)
		settings.credentials.IBMID.client_secret= process.env.IBMID_client_secret;
if(process.env.IBMID_discovery_url)
	settings.credentials.IBMID.discovery_url= process.env.IBMID_discovery_url;
if (process.env.webApp_URL)
	settings.credentials.webApp_URL= process.env.webApp_URL;


// Configure the Google strategy for use by Passport.
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the Google API on the user's
// behalf, along with the user's profile.  The function must invoke `cb`
// with a user object, which will be set at `req.user` in route handlers after
// authentication.
// app registration: https://console.developers.google.com/apis/credentials
var GoogleStrategy = require('passport-google-oauth20').Strategy;
passport.use(new GoogleStrategy({
    clientID: settings.credentials.GOOGLE.clientId,
    clientSecret: settings.credentials.GOOGLE.clientSecret,
    callbackURL: settings.credentials.webApp_URL+"/login/google/return"
  },
  function(accessToken, refreshToken, profile, cb) {
    //User.findOrCreate({ googleId: profile.id }, function (err, user) {
    //  return cb(err, user);
    //});
    return cb(null, profile);
  }
));


// Twitter Application Management (https://apps.twitter.com)
var TwitterStrategy = require('passport-twitter').Strategy;
passport.use(new TwitterStrategy({
    consumerKey: settings.credentials.TWITTER.consumerKey,
    consumerSecret: settings.credentials.TWITTER.consumerSecret,
    callbackURL: settings.credentials.webApp_URL+"/login/twitter/return"
  },
  function(token, tokenSecret, profile, cb) {
    // In this example, the user's Twitter profile is supplied as the user
    // record.  In a production-quality application, the Twitter profile should
    // be associated with a user record in the application's database, which
    // allows for account linking and authentication with other identity
    // providers.
    return cb(null, profile);
  }));

// facebook https://developers.facebook.com/apps/
var FacebookStrategy = require('passport-facebook').Strategy;
passport.use(new FacebookStrategy({
    clientID: settings.credentials.FACEBOOK.clientId,
    clientSecret: settings.credentials.FACEBOOK.clientSecret,
    callbackURL: settings.credentials.webApp_URL+"/login/facebook/return"
  },
  function(accessToken, refreshToken, profile, cb) {
    // In this example, the user's Facebook profile is supplied as the user
    // record.  In a production-quality application, the Facebook profile should
    // be associated with a user record in the application's database, which
    // allows for account linking and authentication with other identity
    // providers.
    return cb(null, profile);
  }));

// linkedin https://www.linkedin.com/developer/apps
var LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
passport.use(new LinkedInStrategy({
	clientID: settings.credentials.LINKEDIN.clientID,
	clientSecret: settings.credentials.LINKEDIN.clientSecret,
    callbackURL: settings.credentials.webApp_URL+"/login/linkedin/return",
	scope: ['r_emailaddress', 'r_basicprofile'],
	state: true
  },
  function(accessToken, refreshToken, profile, cb) {
    //User.findOrCreate({ linkedinId: profile.id }, function (err, user) {
    //    return done(err, user);
    //});
    return cb(null, profile);
  }
));

// IBMID SSO Self
var OpenIDConnectStrategy = require('passport-ci-oidc').IDaaSOIDCStrategy;
passport.use(new OpenIDConnectStrategy({
        discoveryURL: settings.credentials.IBMID.discovery_url,
        clientID: settings.credentials.IBMID.client_id,
        scope: 'email',
        response_type: 'code',
        clientSecret: settings.credentials.IBMID.client_secret,
		    callbackURL : settings.credentials.webApp_URL+'/login/ibmid/return',
        skipUserProfile: true},
        function (iss, sub, profile, accessToken, refreshToken, params, done) {
                process.nextTick(function () {
                        profile.accessToken = accessToken;
                        profile.refreshToken = refreshToken;
                        done(null, profile);
                })
        }
))


// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  In a
// production-quality application, this would typically be as simple as
// supplying the user ID when serializing, and querying the user record by ID
// from the database when deserializing.  However, due to the fact that this
// example does not have a database, the complete Facebook profile is serialized
// and deserialized.
passport.serializeUser(function(user, cb) {
	cb(null, user);
});
  
passport.deserializeUser(function(obj, cb) {
	cb(null, obj);
});


// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: true, saveUninitialized: true }));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());


// Define routes.
app.get('/',
  function(req, res) {
    res.render('home', { navbartext: 'Welcome',user: req.user});
  });

app.get('/login',
  function(req, res){
    res.render('login', {navbartext: 'Choose your login provider'});
  });

app.get('/login/google',
  passport.authenticate('google', { scope: ['profile'] }));
app.get('/login/google/return', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

app.get('/login/twitter',
		passport.authenticate('twitter'));
app.get('/login/twitter/return', 
	  passport.authenticate('twitter', { failureRedirect: '/login' }),
	  function(req, res) {
	    res.redirect('/');
});

app.get('/login/linkedin',
		passport.authenticate('linkedin'));
app.get('/login/linkedin/return', 
	  passport.authenticate('linkedin', { failureRedirect: '/login' }),
	  function(req, res) {
	    res.redirect('/');
});

app.get('/login/facebook',
		  passport.authenticate('facebook'));
app.get('/login/facebook/return', 
	  passport.authenticate('facebook', { failureRedirect: '/login' }),
		  function(req, res) {
		    res.redirect('/');
});

app.get('/login/ibm', passport.authenticate('openidconnect', {}));
//handle callback, if authentication succeeds redirect to
app.get('/login/ibmid/return',function(req, res, next) {
	//original requested url, otherwise go to /failure
	//var redirect_url = req.session.originalUrl;
	//var redirect_url = '/profileibmid';
	var redirect_url = '/profile';
	passport.authenticate('openidconnect', {
		successRedirect: redirect_url,
		failureRedirect: '/failure',
	})(req,res,next);
});
//IBMID SSO login failure page
app.get('/failure', function(req, res) {
	res.send('login failed'); 
});


app.get('/profile',isLoggedIn, function(req, res){
  let html="";
  let navbartext="Your profile";
  if(req.user && req.user['_json'] && req.user['_json'].realmName) {
    let claims_json = req.user['_json'];
    let claims = req.user;
    //console.log(claims);
    // test realm and extract corresponding infos
    if(claims_json.realmName == 'www.ibm.com') { // authentication IBMID
      req.user.provider = 'IBMID (www.ibm.com)'
      html ="<h2>Hello " + claims_json.given_name + " " + claims_json.family_name + " (authentication IBMID with IBMID user)</h2>";
      //html += "<hr> <a href=\"/\">home</a>";
      //html += "<br /> <a href=\"/logoutibmid\">Logout</a>";
      //html += "<br /><h3>Json response from ibmid</h3><pre>" + JSON.stringify(req.user, null, 4) + "</pre>";
    } else if(claims_json.realmName == 'https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20' || claims_json.realmName == 'https://w3id.alpha.sso.ibm.com/auth/sps/samlidp2/saml20') {  // authentication federated w3id (prod or staging)
      if(claims_json.realmName == 'https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20') {
        req.user.provider = 'IBMID (w3id.sso.ibm.com)'
      } else {
        req.user.provider = 'IBMID (w3id.alpha.sso.ibm.com)'
      } 
      html ="<h2>Hello " + claims_json.given_name + " " + claims_json.family_name + " (authentication IBMID with federated W3Id user)</h2>";
      var grp148100_found=false;
      if(claims.blueGroups) {
        for(i=0;i<claims.blueGroups.length;i++)
          if(claims.blueGroups[i]=='148100')
            grp148100_found=true;
        if(grp148100_found) {
          //console.log(claims);
          html +="<p>Congratulation, you are a member of 148100 bluegroup!!!</p>";
        } else {
          html +="<p>You are a not member of 148100 bluegroup!!!</p>";
        }
      }
      //html += "<hr> <a href=\"/\">home</a>";
      //html += "<br /> <a href=\"/logoutibmid\">Logout</a>";
      //html += "<br /><h3>Json response from ibmid</h3><pre>" + JSON.stringify(req.user, null, 4) + "</pre>";
    } else { // other autentication not supported by this application
      console.log(claims_json.realmName+' Not suppported !!!');
      html="<p>Hello your authentication is not supported: " + claims_json.realmName+"</p>"
      html += "<hr> <a href=\"/\">home</a>";
    }
    navbartext=`Your ${claims_json.realmName} profile`
  }
  html += "<br /><h3>Json response from auth provider</h3><pre style='font-size:large;color:blue'>" + JSON.stringify(req.user, null, 4) + "</pre>";
  //res.render('profile',{navbartext: 'Your profile', user: req.user, moredata: JSON.stringify(req.user, null, 4) });
  //res.render('profile',{navbartext: 'Your profile', user: req.user, moredata: JSON.stringify(req.user, null, 4) });
  res.render('profile',{navbartext: navbartext, user: req.user, htmlcontent: html});
});

/*
app.get('/profileibmid', isLoggedIn, function(req, res) {
	var claims_json = req.user['_json'];
	var claims = req.user;
	//console.log(claims);
	// test realm and extract corresponding infos
	var html="";
	if(claims_json.realmName == 'www.ibm.com') { // authentication IBMID
		html ="<h1>Hello " + claims_json.given_name + " " + claims_json.family_name + " (authentication IBMID with IBMID user)</h1>";
		html += "<hr> <a href=\"/\">home</a>";
		html += "<br /> <a href=\"/logoutibmid\">Logout</a>";
    html += "<br /><h2>Json response from ibmid</h2><pre>" + JSON.stringify(req.user, null, 4) + "</pre>";
	} else if(claims_json.realmName == 'https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20' || claims_json.realmName == 'https://w3id.alpha.sso.ibm.com/auth/sps/samlidp2/saml20') {  // authentication federated w3id (prod or staging)
	  html ="<h1>Hello " + claims_json.given_name + " " + claims_json.family_name + " (authentication IBMID with federated W3Id user)</h1>";
		var grp148100_found=false;
		if(claims.blueGroups) {
			for(i=0;i<claims.blueGroups.length;i++)
				if(claims.blueGroups[i]=='148100')
					grp148100_found=true;
			if(grp148100_found) {
				//console.log(claims);
				html +="<p>Congratulation, you are a member of 148100 bluegroup!!!</p>";
			} else {
				html +="<p>You are a not member of 148100 bluegroup!!!</p>";
			}
		}
		html += "<hr> <a href=\"/\">home</a>";
		html += "<br /> <a href=\"/logoutibmid\">Logout</a>";
		html += "<br /><h2>Json response from ibmid</h2><pre>" + JSON.stringify(req.user, null, 4) + "</pre>";
	} else { // other autentication not supported by this application
		console.log(claims_json.realmName+' Not suppported !!!');
		html="<p>Hello your authentication is not supported: " + claims_json.realmName+"</p>"
	}
  res.render('profileibmid',{navbartext:'Your IBMID profile', htmlcontent: html});
});
*/

// route for logging out
app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

//route for logging out (IBMID)
/*
app.get('/logoutibmid', function(req, res) {
    req.session.destroy();
    req.logout();
    //res.render('slo');
    res.redirect('/');
});
*/
//route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {
    // if user is authenticated in the session, carry on
    if (req.isAuthenticated()) {
        return next();
	} else {
		// if they aren't save requested url in session so that it can be used to access the requested page
		req.session.originalUrl = req.originalUrl;
		res.redirect('/login');
	}
}

let secure_server = {}
// run in https if local
if (appEnv.isLocal) {
	// start http and https server on localhost
  secure_server = https.createServer({
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem')
      }, app)
}

		
if (appEnv.isLocal) {
  // start secure_server on localhost
  secure_server.listen(3000, 'localhost', function(){
		console.log("secure server starting on localhost:3000")
	})
} else {
	// start server on the specified port and binding host
	app.listen(appEnv.port, '0.0.0.0', function() {
   	// print a message when the server starts listening
		console.log("server starting on " + appEnv.url)
	})
}
