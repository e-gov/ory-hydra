/**
 * ORY Hydra - Cloud Native OAuth 2.0 and OpenID Connect Server
 * Welcome to the ORY Hydra HTTP API documentation. You will find documentation for all HTTP APIs here. Keep in mind that this document reflects the latest branch, always. Support for versioned documentation is coming in the future.
 *
 * OpenAPI spec version: Latest
 * Contact: hi@ory.am
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 *
 * Swagger Codegen version: 2.2.3
 *
 * Do not edit the class manually.
 *
 */

;(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient'], factory)
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'))
  } else {
    // Browser globals (root is window)
    if (!root.OryHydraCloudNativeOAuth20AndOpenIdConnectServer) {
      root.OryHydraCloudNativeOAuth20AndOpenIdConnectServer = {}
    }
    root.OryHydraCloudNativeOAuth20AndOpenIdConnectServer.AcceptLoginRequest = factory(
      root.OryHydraCloudNativeOAuth20AndOpenIdConnectServer.ApiClient
    )
  }
})(this, function(ApiClient) {
  'use strict'

  /**
   * The AcceptLoginRequest model module.
   * @module model/AcceptLoginRequest
   * @version Latest
   */

  /**
   * Constructs a new <code>AcceptLoginRequest</code>.
   * @alias module:model/AcceptLoginRequest
   * @class
   */
  var exports = function() {
    var _this = this
  }

  /**
   * Constructs a <code>AcceptLoginRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/AcceptLoginRequest} obj Optional instance to populate.
   * @return {module:model/AcceptLoginRequest} The populated <code>AcceptLoginRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports()

      if (data.hasOwnProperty('acr')) {
        obj['acr'] = ApiClient.convertToType(data['acr'], 'String')
      }
      if (data.hasOwnProperty('remember')) {
        obj['remember'] = ApiClient.convertToType(data['remember'], 'Boolean')
      }
      if (data.hasOwnProperty('remember_for')) {
        obj['remember_for'] = ApiClient.convertToType(
          data['remember_for'],
          'Number'
        )
      }
      if (data.hasOwnProperty('subject')) {
        obj['subject'] = ApiClient.convertToType(data['subject'], 'String')
      }
    }
    return obj
  }

  /**
   * ACR sets the Authentication AuthorizationContext Class Reference value for this authentication session. You can use it to express that, for example, a user authenticated using two factor authentication.
   * @member {String} acr
   */
  exports.prototype['acr'] = undefined
  /**
   * Remember, if set to true, tells ORY Hydra to remember this user by telling the user agent (browser) to store a cookie with authentication data. If the same user performs another OAuth 2.0 Authorization Request, he/she will not be asked to log in again.
   * @member {Boolean} remember
   */
  exports.prototype['remember'] = undefined
  /**
   * RememberFor sets how long the authentication should be remembered for in seconds. If set to `0`, the authorization will be remembered indefinitely.
   * @member {Number} remember_for
   */
  exports.prototype['remember_for'] = undefined
  /**
   * Subject is the user ID of the end-user that authenticated.
   * @member {String} subject
   */
  exports.prototype['subject'] = undefined

  return exports
})