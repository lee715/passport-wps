// Load modules.
var OAuth2Strategy = require('passport-oauth2'),
  querystring = require('querystring'),
  util = require('util')

/**
 * `Strategy` constructor.
 *
 * The GitHub authentication strategy authenticates requests by delegating to
 * GitHub using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your GitHub application's Client ID
 *   - `clientSecret`  your GitHub application's Client Secret
 *   - `callbackURL`   URL to which GitHub will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'user', 'public_repo', 'repo', 'gist', or none.
 *                     (see http://developer.github.com/v3/oauth/#scopes for more info)
 *   — `userAgent`     All API requests MUST include a valid User Agent string.
 *                     e.g: domain name of your application.
 *                     (see http://developer.github.com/v3/#user-agent-required for more info)
 *
 * Examples:
 *
 *     passport.use(new GitHubStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/github/callback',
 *         userAgent: 'myapp.com'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user)
 *         })
 *       }
 *     ))
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy (options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || options.sandbox ? 'https://test-account.wps.cn/oauthLogin' : 'https://account.wps.cn/oauthLogin'
  options.tokenURL = options.tokenURL || options.sandbox ? 'https://test-account.wps.cn/oauthapi/token' : 'https://account.wps.cn/oauthapi/token'
  options.scopeSeparator = options.scopeSeparator || ','
  options.customHeaders = options.customHeaders || {}

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-wps'
  }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'wps'
  this._userProfileURL = options.userProfileURL || options.sandbox ? 'https://test-account.wps.cn/oauthapi/user' : 'https://account.wps.cn/oauthapi/user'

  // NOTE: GitHub returns an HTTP 200 OK on error responses.  As a result, the
  //       underlying `oauth` implementation understandably does not parse the
  //       response as an error.  This code swizzles the implementation to
  //       handle this condition.
  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['appid'] = this._clientId
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    params = params || {}
    params['appid'] = this._clientId
    params['appkey'] = this._clientSecret
    var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code'
    params[codeParam] = code

    var post_data = querystring.stringify(params)
    var post_headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    }

    this._request('POST', this._getAccessTokenUrl(), post_headers, post_data, null, function (error, data, response) {
      if (error) {
        callback(error)
      } else {
        var results
        try {
          // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
          // responses should be in JSON
          results = JSON.parse(data)
        } catch (e) {
          // .... However both Facebook + Github currently use rev05 of the spec
          // and neither seem to specify a content-type correctly in their response headers :(
          // clients of these services will suffer a *minor* performance cost of the exception
          // being thrown
          results = querystring.parse(data)
        }
        var access_token = results['access_token']
        var refresh_token = results['refresh_token']
        delete results['refresh_token']
        callback(null, access_token, refresh_token, results); // callback results =-=
      }
    })
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

/**
 * Retrieve user profile from GitHub.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `github`
 *   - `id`               the user's GitHub ID
 *   - `username`         the user's GitHub username
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on GitHub
 *   - `emails`           the user's email addresses
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
  var self = this
  var params = {}
  params['appid'] = this._clientId
  params['access_token'] = accessToken
  var post_data = querystring.stringify(params)
  this._request('get', this._userProfileURL, null, post_data, null, function (err, body, res) {
    var json

    if (err) {
      if (err.data) {
        try {
          json = JSON.parse(err.data)
        } catch (_) {}
      }

      if (json && json.message) {
        return done(new Error(json.message))
      }
      return done(new Error('Failed to fetch user profile'))
    }

    try {
      json = JSON.parse(body)
      return done(null, json)
    } catch (ex) {
      return done(new Error('Failed to parse user profile'))
    }
  })
}

// Expose constructor.
module.exports = Strategy
