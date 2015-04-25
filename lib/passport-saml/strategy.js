var passport = require('passport');
var util = require('util');
var saml = require('./saml');

function Strategy (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('SAML authentication strategy requires a verify function');
  }

  this.name = 'saml';

  passport.Strategy.call(this);

  this._verify = verify;
  this._samlOptions = options;
  if (!options.getOptionsForRequest) {
    this._saml = new saml.SAML(options);
  }
  this._passReqToCallback = !!options.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype._getSaml = function (req, callback) {
  if (this._samlOptions.getOptionsForRequest) {
    this._samlOptions.getOptionsForRequest(req, function (err, options) {
      if (err) {
        return callback(err);
      }
      callback(null, new saml.SAML(options));
    });
  } else {
    callback(null, this._saml);
  }
};

Strategy.prototype.authenticate = function (req, options) {
  var self = this;
  this._getSaml(req, function (err, _saml) {
    if (err) {
      return self.error(err);
    }
    options.samlFallback = options.samlFallback || 'login-request';

    function validateCallback(err, profile, loggedOut) {
      if (err) {
        return self.error(err);
      }

      if (loggedOut) {
        req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return _saml.getLogoutResponseUrl(req, redirectIfSuccess);
        }
        return self.pass();
      }

      var verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      if (self._passReqToCallback) {
        self._verify(req, profile, verified);
      } else {
        self._verify(profile, verified);
      }
    }

    function redirectIfSuccess(err, url) {
      if (err) {
        self.error(err);
      } else {
        self.redirect(url);
      }
    }

    if (req.body && req.body.SAMLResponse) {
      _saml.validatePostResponse(req.body, validateCallback);
    } else if (req.body && req.body.SAMLRequest) {
      _saml.validatePostRequest(req.body, validateCallback);
    } else {
      var operation = {
        'login-request': 'getAuthorizeUrl',
        'logout-request': 'getLogoutUrl'
      }[options.samlFallback];
      if (!operation) {
        return self.fail();
      }
      _saml[operation](req, redirectIfSuccess);
    }
  });
};

Strategy.prototype.logout = function(req, callback) {
  this._getSaml(req, function (err, _saml) {
    if (err) {
      return callback(err);
    }
    _saml.getLogoutUrl(req, callback);
  });
};

Strategy.prototype.generateServiceProviderMetadata = function(req, decryptionCert, callback) {
  this._getSaml(req, function (err, _saml) {
    if (err) {
      return callback(err);
    }
    callback(err, _saml.generateServiceProviderMetadata(decryptionCert));
  });
};

module.exports = Strategy;
