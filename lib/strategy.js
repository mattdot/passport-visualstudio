"use strict";

/**
 * Module dependencies.
 */

var util = require('util');
var utils = require('./utils');
var url = require('url');
var https = require('https');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;
var AuthorizationError = require('passport-oauth2').AuthorizationError;

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://app.vssps.visualstudio.com/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://app.vssps.visualstudio.com/oauth2/token';
  options.scopeSeparator = options.scopeSeparator || ' ';
  
  OAuth2Strategy.call(this, options, verify);

  this._profileURL = options.profileURL || 'https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=1.0';

  this.name = 'visualstudio';
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);

/**
 * Authenticate request by delegating to visualstudio using OAuth 2.0.
 *
 * @param {http.IncomingMessage} req
 * @param {object} options
 * @access protected
 */
Strategy.prototype.authenticate = function(req, options) {
  OAuth2Strategy.prototype.authenticate.call(this, req, options);
};


/**
 * Return extra visualstudio-specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `display`  Display mode to render dialog, { `page`, `popup`, `touch` }.
 *
 * @param {object} options
 * @return {object}
 * @access protected
 */
Strategy.prototype.authorizationParams = function (options) {
  var params = {
    'response_type' : 'Assertion'
  };

  return params;
};

/**
 * Return extra parameters to be included in the token request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting an access token.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @return {Object}
 * @api protected
 */
Strategy.prototype.tokenParams = function (options) {
    var params = {
      'client_assertion_type' : 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      'client_assertion' : this._oauth2._clientSecret,
      'grant_type' : 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    };

    return params;
};

/**
 * Retrieve user profile from service provider.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to load the user's profile from the service provider.  This assists
 * applications (and users of those applications) in the initial registration
 * process by automatically submitting required information.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
    var providerName = this.name;
    var profileURL = url.parse(this._profileURL);
    var profileReq = {
      hostname : profileURL.hostname,
      protocol : profileURL.protocol,
      path : profileURL.path,
      port : profileURL.port,
      headers : {
        'Authorization' : 'Bearer ' + accessToken,
        'Accept': 'application/json'
      }
    };

    https.get(profileReq, function(res) {
      if(res.statusCode >= 400) {
        return done(new InternalOAuthError('Failed to fetch user profile', res.status));
      }

      var body = '';
      var json;

      res.on('data', function(d) {
        body += d;
      });

      res.on('end', function() {
        try {
            json = JSON.parse(body);
        } catch (ex) {
            return done(new Error('Failed to parse user profile.'));
        }

        var profile = {
          id: json.id,
          provider: providerName,
          displayName : json.displayName,
          emails : [{
            value : json.emailAddress
          }],
          _raw: body,
          _json: json
        };

        return done(null, profile);
      });

    }).on('error', function (e) {
      return done(new InternalOAuthError('Failed to fetch user profile', e));
    });
};

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }
  
  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId
  }

  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }
  
      var code = req.query.code;

      var params = self.tokenParams(options);
      params.assertion = code;
      if (callbackURL) { params.redirect_uri = callbackURL; }

      self._oauth2.getOAuthAccessToken(code, params,
        function(err, accessToken, refreshToken, params) {
          if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

          self._loadUserProfile(accessToken, function(err, profile) {
            if (err) { return self.error(err); }

            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }
              
              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }

            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          });
        }
      );
    }
    
    var state = req.query.state;
    try {
      var arity = this._stateStore.verify.length;
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'Assertion';
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }

    var state = options.state;
    if (state) {
      params.state = state;
      var location = this._oauth2.getAuthorizeUrl(params);
      this.redirect(location);
    } else {
      function stored(err, state) {
        if (err) { return self.error(err); }

        if (state) { params.state = state; }
        var location = self._oauth2.getAuthorizeUrl(params);
        self.redirect(location);
      }
      
      try {
        var arity = this._stateStore.store.length;
        if (arity == 3) {
          this._stateStore.store(req, meta, stored);
        } else { // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};


module.exports = Strategy;