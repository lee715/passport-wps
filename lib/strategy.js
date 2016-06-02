// Load modules.
var OAuth2Strategy = require('passport-oauth2')
var querystring = require('querystring')
var util = require('util')

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

  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['appid'] = this._clientId
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    params = params || {}
    params['appid'] = this._clientId
    params['appkey'] = this._clientSecret
    params['grant_type'] = 'authorization_code'
    // var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'authorization_code'
    params['code'] = code

    var post_data = querystring.stringify(params)

    this._request('GET', this._getAccessTokenUrl() + '?' + post_data, null, null, null, function (error, data, response) {
      if (error) {
        callback(error)
      } else {
        var results, token
        try {
          results = JSON.parse(data)
          token = results.token
        } catch (e) {
          callback(e)
        }
        var access_token = token['access_token']
        var refresh_token = token['refresh_token']
        callback(null, access_token, refresh_token, token); // callback results =-=
      }
    })
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function (accessToken, done) {
  var params = {}
  params['appid'] = this._clientId
  params['access_token'] = accessToken
  var post_data = querystring.stringify(params)
  this._oauth2._request('GET', this._userProfileURL + "?" + post_data, null, null, null, function (err, body, res) {
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
      return done(null, json.user)
    } catch (ex) {
      return done(new Error('Failed to parse user profile'))
    }
  })
}

// Expose constructor.
module.exports = Strategy
