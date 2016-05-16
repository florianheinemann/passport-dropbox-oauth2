/**
 * Module dependencies.
 */
var util = require('util')
    , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
    , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Dropbox authentication strategy authenticates requests by delegating to
 * Dropbox using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `err` should be set.
 *
 * Options:
 *   - `apiVersion`    (optional) the Dropbox API version to use (either '1' or '2'). Default is '1'.
 *   - `clientID`      your Dropbox application's app key found in the App Console
 *   - `clientSecret`  your Dropbox application's app secret
 *   - `callbackURL`   URL to which Dropbox will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new DropboxStrategy({
 *         clientID: 'yourAppKey',
 *         clientSecret: 'yourAppSecret'
 *         callbackURL: 'https://www.example.net/auth/dropbox-oauth2/callback',
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  var supportedApiVersions = ['1', '2'],
      defaultOptionsByApiVersion = {
        1: {
          authorizationURL: 'https://www.dropbox.com/1/oauth2/authorize',
          tokenURL: 'https://api.dropbox.com/1/oauth2/token',
          scopeSeparator: ',',
          customHeaders: {}
        },
        2: {
          authorizationURL: 'https://www.dropbox.com/oauth2/authorize',
          tokenURL: 'https://api.dropbox.com/oauth2/token',
          scopeSeparator: ',',
          customHeaders: {
            'Content-Type': 'application/json'
          }
        }
      };

  options = options || {};

  if (options.apiVersion != null && supportedApiVersions.indexOf(options.apiVersion.toString()) === -1) {
    throw new Error('Unsupported Dropbox API version. Supported versions are "1" and "2".');
  }

  this._apiVersion = options.apiVersion || '1';

  options.authorizationURL = options.authorizationURL || defaultOptionsByApiVersion[this._apiVersion].authorizationURL;
  options.tokenURL = options.tokenURL || defaultOptionsByApiVersion[this._apiVersion].tokenURL;

  options.scopeSeparator = options.scopeSeparator || defaultOptionsByApiVersion[this._apiVersion].scopeSeparator;
  options.customHeaders = options.customHeaders || defaultOptionsByApiVersion[this._apiVersion].customHeaders;

  OAuth2Strategy.call(this, options, verify);
  this.name = 'dropbox-oauth2';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Use a different method of the OAuth2Strategy for making an external request to the selected Dropbox API version.
 * Currently API v2 supports only POST requests for retrieving the user's profile.
 *
 * @param {String} accessToken
 * @param {Function} callback
 * @private
 */
Strategy.prototype._retrieveUserProfile = function(accessToken, callback) {
  if (this._apiVersion === '1') {
    this._oauth2.get('https://api.dropbox.com/1/account/info', accessToken, callback);
  }
  else if (this._apiVersion === '2') {
    // we have to provide the string 'null' as the JSON body otherwise Dropbox will complain about it not being valid.
    this._oauth2._request('POST', 'https://api.dropboxapi.com/2/users/get_current_account',
        {'Authorization': this._oauth2.buildAuthHeader(accessToken) }, 'null', accessToken, callback);
  }
};

/**
 * Retrieve user profile from Dropbox.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `dropbox`
 *   - `id`               the user's unique Dropbox ID
 *   - `displayName`      a name that can be used directly to represent the name of a user's Dropbox account
 *   - `emails`           the user's email address
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._retrieveUserProfile(accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);

      var profile = { provider: 'dropbox' };

      if (this._apiVersion === '1') {
        profile.id = json.uid;
        profile.displayName = json.display_name;
        profile.name = {
          familyName: json.name_details.surname,
          givenName: json.name_details.given_name,
          middleName: ''
        };
        profile.emails = [{ value: json.email }];
      }
      else if (this._apiVersion === '2') {
        profile.id = json.account_id;
        profile.displayName = json.name.display_name;
        profile.name = {
          familyName: json.name.surname,
          givenName: json.name.given_name,
          middleName: ''
        };
        profile.emails = [{ value: json.email }];
      }

      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  }.bind(this));
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
