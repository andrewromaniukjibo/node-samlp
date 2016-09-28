var templates             = require('./templates');
var PassportProfileMapper = require('./claims/PassportProfileMapper');
var encoders              = require('./encoders');

var URL_PATH              = '/metadata.xml';

function getEndpointAddress (request, endpointPath) {
  endpointPath = endpointPath ||
    (request.originalUrl.substr(0, request.originalUrl.length - URL_PATH.length));

  var protocol = request.headers['x-iisnode-https'] && request.headers['x-iisnode-https'] == 'on' ?
                 'https' :
                 (request.headers['x-forwarded-proto'] || request.connection.info.protocol);
  
  return protocol + '://' + request.headers['host'] + endpointPath;
}

/**
 * SAML metadata endpoint
 *
 * This endpoint returns a SAML metadata document.
 * 
 * You should expose this endpoint in an address like:
 *
 * 'https://your-saml-server.com/FederationMetadata/2007-06/FederationMetadata.xml
 * 
 * options:
 * - issuer string
 * - cert the public certificate
 * - profileMapper a function that given a user returns a claim based identity, also contains the metadata. By default maps from Passport.js user schema (PassportProfile).
 * - redirectEndpointPath optional, location value for HTTP-Redirect binding (SingleSignOnService)
 * - postEndpointPath optional, location value for HTTP-POST binding (SingleSignOnService)
 * - logoutEndpointPaths.redirect optional, location value for HTTP-Redirect binding (SingleLogoutService)
 * - logoutEndpointPaths.post optional, location value for HTTP-POST binding (SingleLogoutService)
 * 
 * @param  {[type]} options [description]
 * @return {[type]}         [description]
 */
function metadataMiddleware (options) {
  options = options || {};

  if(!options.issuer) {
    throw new Error('options.issuer is required');
  }

  if(!options.cert) {
    throw new Error('options.cert is required');
  }

  var claimTypes = (options.profileMapper || PassportProfileMapper).prototype.metadata;
  var issuer = options.issuer;
  var pem = encoders.removeHeaders(options.cert);

  return function (request, reply) {
    var redirectEndpoint = getEndpointAddress(request, options.redirectEndpointPath);
    var postEndpoint = getEndpointAddress(request, options.postEndpointPath);
    
    options.logoutEndpointPaths = options.logoutEndpointPaths || { redirect: '/logout' };

    var logoutEndpoints = {};
    ['redirect', 'post'].forEach(function (binding) {
      if (options.logoutEndpointPaths[binding]) {
        logoutEndpoints[binding] = getEndpointAddress(request, options.logoutEndpointPaths[binding]);
      }
    });
    
    reply(templates.metadata({
      claimTypes: claimTypes,
      pem:              pem,
      issuer:           issuer,
      redirectEndpoint: redirectEndpoint,
      postEndpoint:     postEndpoint,
      logoutEndpoints:  logoutEndpoints
    }).replace(/\n(?:\s*\n)+/g, '\n')).header('Content-Type', 'application/xml');
  };
}

module.exports = metadataMiddleware;
