// access-token-user.js
//
// It is an overall test of access token validation for token
// created using authorization code grant.
// The process also includes a user decision step for untrusted client accounts.
// This API test script was written to explore the relationship between

// This module generate user token by submission of username and password.
// the contents of the access_token payload compared with the associated
// token meta-data that is stored in the authorization server database.
// The collab-auth server generates OAuth 2.0 access_tokens
// that are created as JWT tokens signed using an RSA private key.
// This demonstrates validation of tokens, detection of an expired access tokens,
// and expiration of token meta-data stored in the authorization server.
//
//    # Recommended test configuration
//    LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
//    LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
//    LIMITS_WEB_RATE_LIMIT_COUNT=1000
//    OAUTH2_AUTH_CODE_EXPIRES_IN_SECONDS=8
//    OAUTH2_TOKEN_EXPIRES_IN_SECONDS=10
//    OAUTH2_REFRESH_TOKEN_EXPIRES_IN_SECONDS=15
//
// The tests are limited in scope and not comprehensive of all possible security risks.
// -----------------------------------------------------------
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');

const Tokens = require('../../collab-auth/node_modules/@dr.pogodin/csurf/tokens.js');
const tokens = new Tokens({});

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/access-token-user.js');
  process.exit(1);
}

const path = require('path');
const uuid = require('../../collab-auth/node_modules/uuid');
const jwt = require('../../collab-auth/node_modules/jsonwebtoken');

/** Private certificate used for signing JSON WebTokens */
const privateKey = fs.readFileSync(path.join(__dirname, '../../collab-auth/data/token-certs/privatekey.pem'));

/** Public certificate used for verification.  Note: you could also use the private key */
const publicKey = fs.readFileSync(path.join(__dirname, '../../collab-auth/data/token-certs/certificate.pem'));

const testEnv = require('./modules/import-config.js').testEnv;
const {
  config
  // clients
  // users
} = require('./modules/import-config.js');

const managedFetch = require('./modules/managed-fetch').managedFetch;

const {
  logRequest,
  showChain,
  showHardError,
  showJwtToken,
  showJwtMetaData,
  check404PossibleVhostError
} = require('./modules/test-utils');

const chainObj = Object.create(null);

/**
 * Promise based sleep timer
 * @param {Object} chain - Chain object passed from promise to promise
 * @param {Boolean} chain.abortSleepTimer - Flag, abort time if true
 * @param {Number} timeSeconds - Timer expiration in seconds
 * @param {String} logMessage - Optional message to print into log
 * @returns {Promise} resolving to chain object
 */
const sleep = (chain, timeSeconds, logMessage) => {
  let messageStr = '';
  if ((logMessage != null) && (logMessage.length > 0)) {
    messageStr = ' (' + logMessage + ')';
  }
  if (chain.abortSleepTimer) {
    delete chain.abortSleepTimer;
    return Promise.resolve(chain);
  } else {
    console.log('\nWaiting for ' + timeSeconds.toString() + ' seconds' + messageStr);
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        resolve(chain);
      }, timeSeconds * 1000);
    });
  }
}; // sleep()

/**
 * Decode JWT token payload and verify signature
 * @param {String} accessToken - Raw access token that was parsed from server's response
 * @returns {Object} Returns object containing de-compiled token data
 * @throws Error if unable to decode token
 */
const deCompileAccessToken = (accessToken) => {
  const tokenData = {};
  tokenData.rawToken = accessToken;
  tokenData.header =
    JSON.parse(Buffer.from(accessToken.split('.')[0], 'base64').toString('utf-8'));
  tokenData.decodedToken = jwt.decode(accessToken);
  console.log('\tExpect: JWT token decodes without error');
  assert.ok((tokenData.decodedToken != null));
  console.log('\tExpect: JWT token has valid signature');
  // jwt.verify will throw error
  tokenData.verifiedToken = jwt.verify(accessToken, publicKey);
  if ((tokenData.verifiedToken == null) ||
    (tokenData.verifiedToken === false) || (tokenData.verifiedToken.length < 1)) {
    throw new Error('JWT token has invalid signature');
  }
  // console.log('token', JSON.stringify(tokenData, null, 2));
  return tokenData;
}; // deCompileAccessToken()

/**
 * Mint a new access token using JTI and RSA signing key.
 * @param {String} jti - JWT token Id
 * @param {String} sub - Client or User UUID
 * @param {Number} expiresInSec - Token expiration in seconds
 * @param {Buffer} signingKey - Buffer containing RSA private key
 * @returns {String} - Returns new signed OAuth 2.0 JWT access_token
 */
const mintNewAccessToken = (jti, sub, expiresInSec, signingKey) => {
  // console.log(jti, sub, expiresInSec, signingKey);
  if ((typeof jti !== 'string') || (jti.length === 0) ||
    (typeof expiresInSec !== 'number') ||
    (!Buffer.isBuffer(signingKey)) || (signingKey.length === 0)) {
    throw new Error('Function mintNewAccessToken received invalid arguments');
  }
  const newToken = {
    jti: jti,
    sub: sub
  };
  const newSignedToken = jwt.sign(
    newToken,
    signingKey,
    {
      algorithm: 'RS256',
      expiresIn: expiresInSec
    }
  );
  return newSignedToken;
}; // mintNewAccessToken()

const generateRandomNonce = (nonceLength) => {
  if ((typeof nonceLength !== 'number') || (nonceLength < 3)) {
    throw new Error('generateRandonNonce() length too short');
  }
  const intNonceLength = parseInt(nonceLength);
  let nonce = '';
  const charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < intNonceLength; i++) {
    nonce += charSet.charAt(parseInt(Math.random() * charSet.length));
  }
  return nonce;
};

/**
 * Initialize shared variables used in chain of promises
 * @param {Object} chain - Data variables passed from promise to promise.
 * @returns {Promise} resolving to chain object
 */
const setup = (chain) => {
  chain.requestAuthorization = 'none';
  chain.requestBasicAuthCredentials =
    Buffer.from(testEnv.clientId + ':' +
    testEnv.clientSecret).toString('base64');
  chain.requestAcceptType = 'application/json';
  chain.requestContentType = 'application/json';
  chain.parsedAccessToken = null;
  chain.deCompiledToken = null;
  return Promise.resolve(chain);
};

//
// Main Promise Chain
//
// Calling setup() returns a Promise to initialize variables.
// The resolved promise .then is used to call the next function
// returning the next promise in a chain of asynchronous promises.
// Each promise performs a testing function. Testing related values
// are stored in a shared object "chain".
// The chain object is the argument of each function.
// The modified chain object is returned by the resolved promise.
//
setup(chainObj)
  // ---------------------------------------------------------
  // 1 GET /status - Check authorization server is running
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '1 GET /status - Check authorization server is running';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/status');
    chain.requestAuthorization = 'none';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    return Promise.resolve(chain);
  })

  // ----------------------------------------------------------
  //         Section 2 to 7
  //
  //    - Submit username/password
  //    - Store valid cookie
  //    - Store new access token
  //
  // ----------------------------------------------------------
  // 2 GET /dialog/authorize - Authorization Check #1 (before login)
  //
  // At this stage, the request is made WITHOUT a valid cookie.
  // The authorization server will store full request URL with query parameters
  // into the user's session. A 302 redirect will tell the browser
  // to load the login password entry form. The 302 redirect response
  // will include a cookie to identify the session.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '2 GET /dialog/authorize - Authorization Check #1 (before login)';
    chain.requestMethod = 'GET';
    let query = '';
    chain.randomStateNonce = 'A' + Math.floor((Math.random() * 1000000)).toString();
    query += '?redirect_uri=' + testEnv.redirectURI;
    query += '&response_type=code';
    query += '&client_id=' + testEnv.clientId;
    query += '&scope=api.read api.write';
    query += '&state=' + chain.randomStateNonce;
    // save for future redirect
    chain.savedAuthorizationPath = encodeURI('/dialog/authorize' + query);
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize' + query);
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    check404PossibleVhostError(chain);
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/login"');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    console.log('\tExpect: response returned set-cookie');
    assert.ok((chain.parsedSetCookieHeader != null) && (chain.parsedSetCookieHeader.length > 0));
    //
    // Parse Data
    //
    return Promise.resolve(chain);
  }) // 2 GET /dialog/authorize

  // -------------------------------
  // 3 GET /login - Get login form
  //
  // This request is expected to return a HTML login form for
  // the user to enter username and password. The form will
  // include an embedded CSRF token that must be submitted
  // with the username, password form submission. If the request
  // included a valid cookie, it will be returned in the response,
  // else a new cookie will be generated.
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '3 GET /login - Get login form';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(chain.responseRawData );

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "<title>collab-auth</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>collab-auth</title>') >= 0);
    console.log('\tExpect: body contains "name="_csrf""');
    assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
    //
    // Parse Data
    //
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    }
  }) // 3 GET /login

  // -----------------------------------------------
  // 4 POST /login - Submit username and password
  //
  // The submit button in the HTML form is intended
  // to submit the username, password, and CSRF token
  // to the authorization server using x-www-form-urlencoded
  // POST request. If the password is not valid, then a 302
  // redirect will tell the browser to reload a
  // new login form. If credentials are validated,
  // a 302 redirect will send the browser back to the original
  // authorization URL. The cookie will be used to retrieve
  // the original URL with query parameters from the user session.
  // Since the user authentication represents a change in
  // authentication identity, a new cookie and session will be created
  // and the new cookie sent in the 302 redirect response headers.
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '4 POST /login - Submit username and password';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    // The user login represents a change in user authentication status
    // so a new session cookie will be issued. The old cookie is saved
    // to verify the change in a test.
    chain.tempLastSessionCookie = chain.currentSessionCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Response includes set-cookie header');
    assert.ok(((chain.parsedSetCookieHeader != null) &&
      (chain.parsedSetCookieHeader.length > 0)));
    console.log('\tExpect: Session cookie replaced after successful login');
    assert.notEqual(
      chain.tempLastSessionCookie,
      chain.parsedSetCookieHeader);
    console.log('\tExpect: Redirect URI to match previously save value');
    assert.strictEqual(
      chain.savedAuthorizationPath,
      chain.parsedLocationHeader);
    // Temporary variable no longer needed
    delete chain.tempLastSessionCookie;
    return Promise.resolve(chain);
  }) // 4 POST /login

  // ----------------------------------------------------------
  // 5 /dialog/authorize - Authorization Check #2 (after login)
  //
  // In this case, the authorization request is made with a valid cookie.
  // Depending on the configuration of the client account, two different
  // responses are possible. If the client is configured with
  // trustedClient=true, a 302 redirect to the Oauth 2.0 callback URI
  // with an authorization code included in the 302 Location header.
  // Alternately, if the client is configured with trustedClient=false,
  // the authentication request will return a HTML form for the user
  // to 'Accept' or 'Deny' the application to access the specified resource.
  // The form will also include an embedded CSRF token. An OAuth2.0
  // transaction code (random nonce) is also embedded in the form to
  // validate that the response is from the intended user.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '5 /dialog/authorize - Authorization Check #2 (after login)';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: body contains "<title>Resource Decision</title>"');
      assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
      console.log('\tExpect: body contains "name="_csrf""');
      assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
      console.log('\tExpect: body contains "name="transaction_id""');
      assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

      //
      // Parse Data
      //
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      chain.parsedTransactionId =
        chain.responseRawData.split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    } // not skipped, untrusted client
  })

  // --------------------------------------------------------
  // 6 POST /dialog/authorize/decision - Submit accept/deny
  //
  // This request will confirm the user's acceptance
  // by submitting the transaction code and CSRF token.
  // The response will be a 302 redirect to the Oauth 2.0 callback URI
  // with an authorization code included in the 302 Location header.
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '6 POST /dialog/authorize/decision - Submit accept/deny';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        _csrf: chain.parsedCsrfToken
        // Uncomment to emulate cancel button
        // cancel: 'deny'
      };
      delete chain.parsedTransactionId;
      return Promise.resolve(chain);
    } // untrusted client
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    // console.log('parsedLocationHeader: ', chain.parsedLocationHeader);
    console.log('\tExpect: parsedLocationHeader has authorization code');
    assert.ok(chain.parsedLocationHeader.indexOf('code=') >= 0);
    console.log('\tExpect: parsedLocationHeader header has state nonce');
    assert.ok(chain.parsedLocationHeader.indexOf('state=') >= 0);

    //
    // Parse Data
    //
    chain.parsedAuthCode =
      chain.parsedLocationHeader.split('code=')[1].split('&state')[0];
    chain.parsedStateNonce =
      chain.parsedLocationHeader.split('state=')[1];
    console.log('\tExpect: parsed state nonce match previous');
    assert.deepEqual(chain.parsedStateNonce, chain.randomStateNonce);
    if (testEnv.trustedClient) {
      console.log('\nTest: 6 POST /dialog/authorize/decision - Submit accept/deny');
      console.log('\tTest aborted, client account configuration trustedClient=true');
    }
    return Promise.resolve(chain);
  }) // 6 POST /dialog/authorize/decision

  // -----------------------------------------
  // 7 POST /oauth/token - Get access_token using authorization code
  //
  // In this request, the authorization code obtained
  // in step #6 will be set to the server.
  // In response to a valid authorization code,
  // the server will return both an OAuth 2.0 access_token
  // and a refresh_token in the body of the response.
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '7 POST /oauth/token - Get access_token using authorization code';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // No cookie, auth in body of request
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    chain.requestBody = {
      code: chain.parsedAuthCode,
      redirect_uri: testEnv.redirectURI,
      client_id: testEnv.clientId,
      client_secret: testEnv.clientSecret,
      grant_type: 'authorization_code'
    };
    delete chain.parsedTransactionId;
    delete chain.parsedAuthCode;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: Content-type === "application/json"');
    assert.strictEqual(chain.parsedContentType, 'application/json');
    console.log('\tExpect: response token_type === "Bearer"');
    assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
    console.log('\tExpect: response grantType === "authorization_code"');
    assert.strictEqual(chain.responseRawData.grant_type, 'authorization_code');

    // Evaluate times in server response
    const timeNowSec = Math.floor(Date.now() / 1000);
    console.log('\tExpect: expires_in value close to expected');
    const expDelta = Math.abs(config.oauth2.tokenExpiresInSeconds -
       chain.responseRawData.expires_in);
    assert.ok((expDelta < 3));
    console.log('\tExpect: auth_time value close to expected');
    const authDelta = Math.abs(timeNowSec - chain.responseRawData.auth_time);
    assert.ok((authDelta < 3));
    console.log('\tExpect: response has scope property (value not evaluated)');
    assert.ok(Object.hasOwn(chain.responseRawData, 'scope'));
    console.log('\tExpect: response has access_token property');
    assert.ok(Object.hasOwn(chain.responseRawData, 'access_token'));
    console.log('\tExpect: access_token 3 parts (xxx.xxx.xxx)');
    assert.strictEqual(chain.responseRawData.access_token.split('.').length, 3);

    if (!config.oauth2.disableRefreshTokenGrant) {
      console.log('\tExpect: response has refresh_token property');
      assert.ok(Object.hasOwn(chain.responseRawData, 'refresh_token'));
      console.log('\tExpect: refresh_token 3 parts (xxx.xxx.xxx)');
      assert.strictEqual(chain.responseRawData.refresh_token.split('.').length, 3);
    }

    //
    // Parse Data
    //
    chain.parsedAccessToken = chain.responseRawData.access_token;
    chain.parsedRefreshToken = chain.responseRawData.refresh_token;
    chain.deCompiledToken = deCompileAccessToken(chain.parsedAccessToken);

    //
    // More tests
    //
    console.log('\tExpect: access_token header has token type "JWT"');
    assert.strictEqual(chain.deCompiledToken.header.typ, 'JWT');
    console.log('\tExpect: access_token header has algorithm "RS256"');
    assert.strictEqual(chain.deCompiledToken.header.alg, 'RS256');
    //
    // Show Token
    //
    showJwtToken(chain);

    return Promise.resolve(chain);
  }) // 7 POST /oauth/token

  // ----------------------------------------------------------
  //
  //         Section 100 to 106
  //
  //    - Confirm stored token functions correctly
  //    - Mutate the token different ways and check for errors
  //
  // ----------------------------------------------------------
  // 100 POST /oauth/introspect - Submit token, verify active and meta-data before further tests
  //
  // This request will submit the access_token obtained in step #7
  // to the authentication server. A set of valid client credentials are
  // required to submit the request. The authentication server
  // will check the signature of the access token, if valid and
  // not expired, the meta-data associated with the access_token
  // will be looked up in the token database and returned in the response
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '100 POST /oauth/introspect - Submit token, verify active and meta-data before further tests';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    chain.requestBody = {
      access_token: chain.parsedAccessToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: active === true');
    assert.strictEqual(chain.responseRawData.active, true);
    console.log('\tExpect: The grant_type value matches "authorization_code"');
    assert.strictEqual(chain.responseRawData.grant_type, 'authorization_code');
    console.log('\tExpect: value of user.username is as expected');
    assert.strictEqual(chain.responseRawData.user.username, testEnv.username);
    console.log('\tExpect: value of client.clientId is as expected');
    assert.strictEqual(chain.responseRawData.client.clientId, testEnv.clientId);
    console.log('\tExpect: The issuer value matches config auth URL');
    assert.strictEqual(chain.responseRawData.issuer, config.site.authURL + '/oauth/token');
    console.log('\tExpect: The jti value in token matches meta-data in response');
    assert.strictEqual(chain.responseRawData.jti, chain.deCompiledToken.decodedToken.jti);

    // Evaluate times in server response
    const timeNowSec = Math.floor(Date.now() / 1000);
    console.log('\tExpect: expires_in value close to expected');
    const expiresInDelta = Math.abs(config.oauth2.tokenExpiresInSeconds -
       chain.responseRawData.expires_in);
    assert.ok((expiresInDelta < 3));
    console.log('\tExpect: auth_time value close to expected');
    const authDelta = Math.abs(timeNowSec - chain.responseRawData.auth_time);
    assert.ok((authDelta < 3));
    console.log('\tExpect: exp value close to expected');
    const expDelta = Math.abs((timeNowSec + config.oauth2.tokenExpiresInSeconds) -
      chain.responseRawData.exp);
    assert.ok((expDelta < 3));
    console.log('\tExpect: The exp value in token matches meta-data in response');
    assert.strictEqual(chain.responseRawData.exp, chain.deCompiledToken.decodedToken.exp);
    console.log('\tExpect: The iat value in token matches meta-data in response');
    assert.strictEqual(chain.responseRawData.exp, chain.deCompiledToken.decodedToken.exp);
    console.log('\tExpect: The iat value (from token) and auth_time (from database) value match');
    assert.strictEqual(chain.responseRawData.iat, chain.responseRawData.auth_time);
    console.log('\tExpect: response has scope property (value not evaluated)');
    assert.ok(Object.hasOwn(chain.responseRawData, 'scope'));

    showJwtMetaData(chain);
    return Promise.resolve(chain);
  }) // 100 POST /oauth/introspect

  // ----------------------------------------------------------
  // 101 POST /oauth/introspect - Mint new access token, confirm accepted
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '101 POST /oauth/introspect - Mint new access token, confirm accepted';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      chain.deCompiledToken.decodedToken.jti,
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.tokenExpiresInSeconds,
      privateKey
    );
    // console.log('newSignedTokenDecoded', jwt.decode(newToken));
    chain.requestBody = {
      access_token: newToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: active === true');
    assert.strictEqual(chain.responseRawData.active, true);
    showJwtMetaData(chain);
    return Promise.resolve(chain);
  }) // 101 POST /oauth/introspect

  // ----------------------------------------------------------
  // 102 POST /oauth/introspect - Mint expired access token (expires = -3600 sec)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '102 POST /oauth/introspect - Mint expired access token (expires = -3600 sec)';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      chain.deCompiledToken.decodedToken.jti,
      chain.deCompiledToken.decodedToken.sub,
      -3600,
      privateKey
    );
    // console.log('newSignedTokenDecoded', jwt.decode(newToken));
    chain.requestBody = {
      access_token: newToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 401 });
    // Note: this first test verifies the minted token actually expires in the past
    console.log('\tExpect: Minted token "exp" property expires in past');
    const timeNowSec = Math.floor(Date.now() / 1000);
    // Calculate ime until token expires (-3600 negative since expired in past)
    const timeUntilExpire = jwt.decode(chain.requestBody.access_token).exp - timeNowSec;
    assert.ok((timeUntilExpire < -3597));
    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);
    showJwtMetaData(chain);
    return Promise.resolve(chain);
  }) // 102 POST /oauth/introspect

  // ----------------------------------------------------------
  // 103 POST /oauth/introspect - Mint access token with random JTI
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '103 POST /oauth/introspect - Mint access token with random JTI';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      // Generate random JTI using same method as server
      uuid.v4(),
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.tokenExpiresInSeconds,
      privateKey
    );
    // console.log('newSignedTokenDecoded', jwt.decode(newToken));
    chain.requestBody = {
      access_token: newToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 401 });
    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);
    showJwtMetaData(chain);
    return Promise.resolve(chain);
  }) // 103 POST /oauth/introspect

  // ----------------------------------------------------------
  // 104 POST /oauth/introspect - Concatenate a character at start of access token header
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '104 POST /oauth/introspect - Concatenate a character at start of access token header';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      chain.deCompiledToken.decodedToken.jti,
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.tokenExpiresInSeconds,
      privateKey
    );
    const malformedToken = 'A' + newToken;
    chain.requestBody = {
      access_token: malformedToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 401 });
    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);
    showJwtMetaData(chain);
    return Promise.resolve(chain);
  }) // 104 POST /oauth/introspect

  // ----------------------------------------------------------
  // 105 POST /oauth/introspect - Concatenate a character at start of access token payload
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '105 POST /oauth/introspect - Concatenate a character at start of access token payload';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      chain.deCompiledToken.decodedToken.jti,
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.tokenExpiresInSeconds,
      privateKey
    );
    const malformedToken =
      newToken.split('.')[0] + '.' + 'A' +
      newToken.split('.')[1] + '.' +
      newToken.split('.')[2];
    chain.requestBody = {
      access_token: malformedToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 401 });
    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);
    showJwtMetaData(chain);
    return Promise.resolve(chain);
  }) // 105 POST /oauth/introspect

  // ----------------------------------------------------------
  // 106 POST /oauth/introspect - Done mutated tokens, confirm JTI still accepted
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '106 POST /oauth/introspect - Done mutated tokens, confirm JTI still accepted';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      chain.deCompiledToken.decodedToken.jti,
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.tokenExpiresInSeconds,
      privateKey
    );
    chain.requestBody = {
      access_token: newToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: active === true');
    assert.strictEqual(chain.responseRawData.active, true);
    showJwtMetaData(chain);
    return Promise.resolve(chain);
  }) // 106 POST /oauth/introspect

  // ----------------------------------------------------------
  //
  //         Section 200 to 205
  //
  //    - Obtain new access token
  //    - Wait for timer
  //    - Confirm access token is expired
  //
  // ----------------------------------------------------------
  // 200 /dialog/authorize - Test access token expires, request authcode
  //
  // Challenge access_token expiration time
  //
  // This is a copy/paste of step #5 above, this time we still have a valid cookie
  // so the login form can be skipped.
  //
  // In this case, the authorization request is made with a valid cookie.
  // Depending on the configuration of the client account, two different
  // responses are possible. If the client is configured with
  // trustedClient=true, a 302 redirect to the Oauth 2.0 callback URI
  // with an authorization code included in the 302 Location header.
  // Alternately, if the client is configured with trustedClient=false,
  // the authentication request will return a HTML form for the user
  // to 'Accept' or 'Deny' the application to access the specified resource.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '200 /dialog/authorize - Test access token expires, request authcode';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    if (config.oauth2.tokenExpiresInSeconds === 10) {
      return Promise.resolve(chain);
    } else {
      console.log('\nTo test access token expiration, ' +
        'configure server: OAUTH2_TOKEN_EXPIRES_IN_SECONDS=10');
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      if (testEnv.trustedClient) {
        return Promise.resolve(chain);
      } else {
        logRequest(chain);
        // console.log(JSON.stringify(chain.responseRawData, null, 2));

        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
        console.log('\tExpect: body contains "<title>Resource Decision</title>"');
        assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
        console.log('\tExpect: body contains "name="_csrf""');
        assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
        console.log('\tExpect: body contains "name="transaction_id""');
        assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

        //
        // Parse Data
        //
        chain.parsedCsrfToken =
          chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
        chain.parsedTransactionId =
          chain.responseRawData
            .split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
        return Promise.resolve(chain);
      } // untrusted client
    }
  }) // 200 /dialog/authorize

  // --------------------------------------------------------
  // 201 POST /dialog/authorize/decision - User submits accept/deny
  //
  // Challenge access_token expiration time
  //
  // This is a copy/paste of step #6 above
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      if (config.oauth2.tokenExpiresInSeconds === 10) {
        return Promise.resolve(chain);
      } else {
        if (!testEnv.trustedClient) {
          chain.abortManagedFetch = true;
        }
        chain.skipInlineTests = true;
        return Promise.resolve(chain);
      }
    } else {
      chain.testDescription =
        '201 POST /dialog/authorize/decision - User submits accept/deny';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      if (config.oauth2.tokenExpiresInSeconds === 10) {
        chain.requestBody = {
          transaction_id: chain.parsedTransactionId,
          _csrf: chain.parsedCsrfToken
          // Uncomment to emulate cancel button
          // cancel: 'deny'
        };
        delete chain.parsedTransactionId;
        return Promise.resolve(chain);
      } else {
        chain.abortManagedFetch = true;
        chain.skipInlineTests = true;
        return Promise.resolve(chain);
      }
    } // untrusted client
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      delete chain.abortManagedFetch;
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      // console.log('parsedLocationHeader: ', chain.parsedLocationHeader);
      console.log('\tExpect: parsedLocationHeader has authorization code');
      assert.ok(chain.parsedLocationHeader.indexOf('code=') >= 0);
      console.log('\tExpect: parsedLocationHeader header has state nonce');
      assert.ok(chain.parsedLocationHeader.indexOf('state=') >= 0);

      //
      // Parse Data
      //
      chain.parsedAuthCode =
        chain.parsedLocationHeader.split('code=')[1].split('&state')[0];
      chain.parsedStateNonce =
        chain.parsedLocationHeader.split('state=')[1];
      console.log('\tExpect: parsed state nonce match previous');
      assert.deepEqual(chain.parsedStateNonce, chain.randomStateNonce);
      if (testEnv.trustedClient) {
        console.log('\n201 POST /dialog/authorize/decision - User submits accept/deny');
        console.log('\tTest aborted, client account configuration trustedClient=true');
      }
      return Promise.resolve(chain);
    } // not skipped
  }) // 201 POST /dialog/authorize/decision

  // -----------------------------------------
  // 202 POST /oauth/token - Test access token expires, new token request
  //
  // Challenge access_token expiration time
  //
  // This is a copy/paste of step #7 above
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '202 POST /oauth/token - Test access token expires, new token request';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // No cookie, auth in body of request
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    if (config.oauth2.tokenExpiresInSeconds === 10) {
      chain.requestBody = {
        code: chain.parsedAuthCode,
        redirect_uri: testEnv.redirectURI,
        client_id: testEnv.clientId,
        client_secret: testEnv.clientSecret,
        grant_type: 'authorization_code'
      };
      delete chain.parsedTransactionId;
      delete chain.parsedAuthCode;
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.abortSleepTimer = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: Content-type === "application/json"');
      assert.strictEqual(chain.parsedContentType, 'application/json');
      console.log('\tExpect: response token_type === "Bearer"');
      assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
      console.log('\tExpect: response grantType === "authorization_code"');
      assert.strictEqual(chain.responseRawData.grant_type, 'authorization_code');

      // Evaluate times in server response
      console.log('\tExpect: expires_in value close to expected');
      const expDelta = Math.abs(config.oauth2.tokenExpiresInSeconds -
        chain.responseRawData.expires_in);
      assert.ok((expDelta < 3));

      //
      // Parse Data
      //
      chain.parsedAccessToken = chain.responseRawData.access_token;
      chain.parsedRefreshToken = chain.responseRawData.refresh_token;
      chain.deCompiledToken = deCompileAccessToken(chain.parsedAccessToken);
      //
      // Show Token
      //
      showJwtToken(chain);

      return Promise.resolve(chain);
    } // not skipped
  }) // 202 POST /oauth/token

  // --------------------------------
  // Wait for before successful access token request
  // --------------------------------
  .then((chain) => sleep(
    chain,
    // Set timer 4 + 8 = 12 seconds, expire in 10 seconds
    4,
    'Delay before successful test of access token expiration'
  ))

  // ----------------------------------------------------------
  // 203 POST /oauth/introspect - Verify token accepted before time delay
  //
  // Challenge access_token expiration time
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '203 POST /oauth/introspect - Verify token accepted before time delay';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    if (config.oauth2.tokenExpiresInSeconds === 10) {
      chain.requestBody = {
        // access_token: newToken
        access_token: chain.parsedAccessToken
      };
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: active === true');
      assert.strictEqual(chain.responseRawData.active, true);
      showJwtMetaData(chain);
      return Promise.resolve(chain);
    }
  }) // 203 POST /oauth/introspect

  // --------------------------------
  // Wait for access token to expire
  // --------------------------------
  .then((chain) => sleep(
    chain,
    // Set timer 4 + 8 = 12 seconds, expire in 10 seconds
    8,
    'Waiting for access token to expire'
  ))

  // ----------------------------------------------------------
  // 204 POST /oauth/introspect - Expect access token expired after delay
  //
  // Challenge access_token expiration time
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '204 POST /oauth/introspect - Expect access token expired after delay';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    if (config.oauth2.tokenExpiresInSeconds === 10) {
      chain.requestBody = {
        access_token: chain.parsedAccessToken
      };
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 401 });
      console.log('\tExpect: status === 401 (access token expired)');
      assert.strictEqual(chain.responseStatus, 401);
      showJwtMetaData(chain);
      return Promise.resolve(chain);
    } // not skipped
  }) // 204 POST /oauth/introspect

  // ----------------------------------------------------------
  // 205 POST /oauth/introspect - Confirm database meta data expired also
  //
  // Challenge access_token expiration time
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '205 POST /oauth/introspect - Confirm database meta data expired also';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    if (config.oauth2.tokenExpiresInSeconds === 10) {
      //
      // build new access token
      //
      const newToken = mintNewAccessToken(
        // uuid.v4(),
        chain.deCompiledToken.decodedToken.jti,
        chain.deCompiledToken.decodedToken.sub,
        config.oauth2.tokenExpiresInSeconds,
        privateKey
      );
      // const newSignedTokenDecoded = jwt.decode(newSignedToken);
      // console.log('new iat', newSignedTokenDecoded.iat, 'new exp', newSignedTokenDecoded.exp);
      // console.log('newSignedTokenDecoded', newSignedTokenDecoded);
      chain.requestBody = {
        access_token: newToken
      };
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 401 });
      console.log('\tExpect: status === 401 (New access_token valid, but database record expired)');
      assert.strictEqual(chain.responseStatus, 401);
      showJwtMetaData(chain);
      return Promise.resolve(chain);
    } // not skipped
  }) // 205 POST /oauth/introspect
  // ----------------------------------------------------------
  //
  //         Section 210 to 212
  //
  //    - Request authorization code
  //    - Wait for timer
  //    - Confirm authorization code not accepted
  //
  // ----------------------------------------------------------
  // 210 /dialog/authorize - Check auth code expires, request auth code
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #5 above, this time we still have a valid cookie
  // so the login form can be skipped.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '210 /dialog/authorize - Check auth code expires, request auth code';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      return Promise.resolve(chain);
    } else {
      console.log('\nTo test authorization code expiration, ' +
        'configure server: OAUTH2_AUTH_CODE_EXPIRES_IN_SECONDS=8');
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      if (testEnv.trustedClient) {
        return Promise.resolve(chain);
      } else {
        logRequest(chain);
        // console.log(JSON.stringify(chain.responseRawData, null, 2));

        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
        console.log('\tExpect: body contains "<title>Resource Decision</title>"');
        assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
        console.log('\tExpect: body contains "name="_csrf""');
        assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
        console.log('\tExpect: body contains "name="transaction_id""');
        assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

        //
        // Parse Data
        //
        chain.parsedCsrfToken =
          chain.responseRawData
            .split('name="_csrf"')[1].split('value="')[1].split('">')[0];
        chain.parsedTransactionId =
          chain.responseRawData
            .split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
        return Promise.resolve(chain);
      } // untrusted client
    } // not skipped
  }) // 210 /dialog/authorize

  // --------------------------------------------------------
  // 211 POST /dialog/authorize/decision - User submits accept/deny
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #6 above
  // --------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '211 POST /dialog/authorize/decision - User submits accept/deny';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        _csrf: chain.parsedCsrfToken
        // Uncomment to emulate cancel button
        // cancel: 'deny'
      };
      delete chain.parsedTransactionId;
      return Promise.resolve(chain);
    } else {
      console.log('\nTest: 211 POST /dialog/authorize/decision - User submits accept/deny');
      console.log('\tTest aborted, client account configuration trustedClient=true');
      chain.abortSleepTimer = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => {
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      if (testEnv.trustedClient) {
        return Promise.resolve(chain);
      } else {
        return managedFetch(chain);
      }
    } else {
      return Promise.resolve(chain);
    }
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      // console.log('parsedLocationHeader: ', chain.parsedLocationHeader);
      console.log('\tExpect: parsedLocationHeader has authorization code');
      assert.ok(chain.parsedLocationHeader.indexOf('code=') >= 0);
      console.log('\tExpect: parsedLocationHeader header has state nonce');
      assert.ok(chain.parsedLocationHeader.indexOf('state=') >= 0);

      //
      // Parse Data
      //
      chain.parsedAuthCode =
        chain.parsedLocationHeader.split('code=')[1].split('&state')[0];
      chain.parsedStateNonce =
        chain.parsedLocationHeader.split('state=')[1];
      console.log('\tExpect: parsed state nonce match previous');
      assert.deepEqual(chain.parsedStateNonce, chain.randomStateNonce);
      if (testEnv.trustedClient) {
        console.log('\nTest: 211 POST /dialog/authorize/decision - User submits accept/deny');
        console.log('\tTest aborted, client account configuration trustedClient=true');
      }
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      return Promise.resolve(chain);
    }
  }) // 211 POST /dialog/authorize/decision

  // --------------------------------
  // Wait for authorization code to expire
  // --------------------------------
  // Add 5 seconds to authorization code expiration time
  .then((chain) => sleep(
    chain,
    config.oauth2.authCodeExpiresInSeconds + 2,
    'Waiting for authorization code to expire'
  ))

  // -----------------------------------------
  // 212 POST /oauth/token - Get token with (expired) authorization code
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #7 above
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '212 POST /oauth/token - Get token with (expired) authorization code';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // No cookie, auth in body of request
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      chain.requestBody = {
        code: chain.parsedAuthCode,
        redirect_uri: testEnv.redirectURI,
        client_id: testEnv.clientId,
        client_secret: testEnv.clientSecret,
        grant_type: 'authorization_code'
      };
      chain.rememberedAuthCode = chain.parsedAuthCode;
      delete chain.parsedTransactionId;
      delete chain.parsedAuthCode;
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 403 });
      // console.log(chain.responseRawData);
      // console.log(chain.responseErrorMessage);

      console.log('\tExpect: status === 403');
      assert.strictEqual(chain.responseStatus, 403);
      console.log('\tExpect: Error message contains \'"error":"invalid_grant"\'');
      assert.ok(chain.responseErrorMessage.indexOf('"error":"invalid_grant"') >= 0);
      console.log('\tExpect: Error message contains \'"error_description":"Invalid authorization code"\'');
      assert.ok(chain.responseErrorMessage.indexOf('"error_description":"Invalid authorization code"') >= 0);
      return Promise.resolve(chain);
    } // not skipped
  }) // 212 POST /oauth/token

  // ----------------------------------------------------------
  // 213 /dialog/authorize - Restarting token request
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #5 above, this time we still have a valid cookie
  // so the login form can be skipped.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '213 /dialog/authorize - Restarting token request';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log(chain.responseErrorMessage);
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      if (testEnv.trustedClient) {
        return Promise.resolve(chain);
      } else {
        logRequest(chain);

        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
        console.log('\tExpect: body contains "<title>Resource Decision</title>"');
        assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
        console.log('\tExpect: body contains "name="_csrf""');
        assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
        console.log('\tExpect: body contains "name="transaction_id""');
        assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

        //
        // Parse Data
        //
        chain.parsedCsrfToken =
          chain.responseRawData
            .split('name="_csrf"')[1].split('value="')[1].split('">')[0];
        chain.parsedTransactionId =
          chain.responseRawData
            .split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
        return Promise.resolve(chain);
      } // untrusted client
    } // not skipped
  }) // 213 /dialog/authorize

  // --------------------------------------------------------
  // 214 POST /dialog/authorize/decision - User submits accept/deny
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #6 above
  // --------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '214 POST /dialog/authorize/decision - User submits accept/deny';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        _csrf: chain.parsedCsrfToken
        // Uncomment to emulate cancel button
        // cancel: 'deny'
      };
      delete chain.parsedTransactionId;
      return Promise.resolve(chain);
    } else {
      console.log('\nTest: 214 POST /dialog/authorize/decision - User submits accept/deny');
      console.log('\tTest aborted, client account configuration trustedClient=true');
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } // untrusted client
  })
  .then((chain) => {
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      if (testEnv.trustedClient) {
        return Promise.resolve(chain);
      } else {
        return managedFetch(chain);
      }
    } else {
      return Promise.resolve(chain);
    }
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      // console.log('parsedLocationHeader: ', chain.parsedLocationHeader);
      console.log('\tExpect: parsedLocationHeader has authorization code');
      assert.ok(chain.parsedLocationHeader.indexOf('code=') >= 0);
      console.log('\tExpect: parsedLocationHeader header has state nonce');
      assert.ok(chain.parsedLocationHeader.indexOf('state=') >= 0);

      //
      // Parse Data
      //
      chain.parsedAuthCode =
        chain.parsedLocationHeader.split('code=')[1].split('&state')[0];
      chain.parsedStateNonce =
        chain.parsedLocationHeader.split('state=')[1];
      console.log('\tExpect: parsed state nonce match previous');
      assert.deepEqual(chain.parsedStateNonce, chain.randomStateNonce);
      if (testEnv.trustedClient) {
        console.log('\nTest: 214 POST /dialog/authorize/decision - User submits accept/deny');
        console.log('\tTest aborted, client account configuration trustedClient=true');
      }
      return Promise.resolve(chain);
    } else {
      return Promise.resolve(chain);
    }
  }) // 214 POST /dialog/authorize/decision

  // -----------------------------------------
  // 215 POST /oauth/token - Use previous auth code (expired)
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #7 above
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '215 POST /oauth/token - Use previous auth code (expired)';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // No cookie, auth in body of request
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    if (config.oauth2.authCodeExpiresInSeconds === 8) {
      chain.requestBody = {
        code: chain.rememberedAuthCode,
        redirect_uri: testEnv.redirectURI,
        client_id: testEnv.clientId,
        client_secret: testEnv.clientSecret,
        grant_type: 'authorization_code'
      };
      delete chain.rememberedAuthCode;
      delete chain.parsedTransactionId;
      delete chain.parsedAuthCode;
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 403 });
      // console.log(chain.responseRawData);
      // console.log(chain.responseErrorMessage);

      console.log('\tExpect: status === 403');
      assert.strictEqual(chain.responseStatus, 403);
      console.log('\tExpect: Error message contains \'"error":"invalid_grant"\'');
      assert.ok(chain.responseErrorMessage.indexOf('"error":"invalid_grant"') >= 0);
      console.log('\tExpect: Error message contains \'"error_description":"Invalid authorization code"\'');
      assert.ok(chain.responseErrorMessage.indexOf('"error_description":"Invalid authorization code"') >= 0);
      return Promise.resolve(chain);
    }
  }) // 215 POST /oauth/token

  // ----------------------------------------------------------
  //
  //         Section 220-227
  //
  //    - Decision submitted with valid transaction ID or CSRF token
  //    - Aborted decision submitted by user
  //
  // ----------------------------------------------------------
  // 220 /dialog/authorize - Check decision with invalid transaction ID
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #5 above, this time we still have a valid cookie
  // so the login form can be skipped.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '220 /dialog/authorize - Check decision with invalid transaction ID';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    if (testEnv.trustedClient) {
      chain.abortManagedFetch = true;
    }
    return Promise.resolve(chain);
  })

  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(chain.responseRawData);

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: body contains "<title>Resource Decision</title>"');
      assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
      console.log('\tExpect: body contains "name="_csrf""');
      assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
      console.log('\tExpect: body contains "name="transaction_id""');
      assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

      //
      // Parse Data
      //
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      chain.parsedTransactionId =
        chain.responseRawData.split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    } // untrusted client
  }) // 220 /dialog/authorize

  // --------------------------------------------------------
  // 221 POST /dialog/authorize/decision - Submit with invalid transaction ID
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #6 above
  // --------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '221 POST /dialog/authorize/decision - Submit with invalid transaction ID';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    if (testEnv.trustedClient) {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } else {
      chain.requestBody = {
        // transaction_id: chain.parsedTransactionId,
        // Generate invalid transactionid
        transaction_id: generateRandomNonce(16),
        _csrf: chain.parsedCsrfToken
        // Uncomment to emulate cancel button
        // cancel: 'deny'
      };
      delete chain.parsedTransactionId;
      return Promise.resolve(chain);
    } // untrusted client
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 403 });
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log(chain.responseErrorMessage);

      console.log('\tExpect: status === 403');
      assert.strictEqual(chain.responseStatus, 403);

      console.log('\tExpect: Error message contains \'"error":"server_error"\'');
      assert.ok(chain.responseErrorMessage.indexOf('"error":"server_error"') >= 0);
      console.log('\tExpect: Error message contains "Unable to load OAuth 2.0 transaction"');
      assert.ok(chain.responseErrorMessage.indexOf('Unable to load OAuth 2.0 transaction') >= 0);
      return Promise.resolve(chain);
    } // not skipped
  }) // 221 POST /dialog/authorize/decision

  // ----------------------------------------------------------
  // 222 /dialog/authorize - Check decision with invalid CSRF token
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #5 above, this time we still have a valid cookie
  // so the login form can be skipped.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '222 /dialog/authorize - Check decision with invalid CSRF token';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    if (testEnv.trustedClient) {
      chain.abortManagedFetch = true;
    }
    return Promise.resolve(chain);
  })

  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(chain.responseRawData);

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: body contains "<title>Resource Decision</title>"');
      assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
      console.log('\tExpect: body contains "name="_csrf""');
      assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
      console.log('\tExpect: body contains "name="transaction_id""');
      assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

      //
      // Parse Data
      //
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      chain.parsedTransactionId =
        chain.responseRawData.split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    } // untrusted client
  }) // 222 /dialog/authorize

// --------------------------------------------------------
  // 223 POST /dialog/authorize/decision - Submit with invalid CSRF token
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #6 above
  // --------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '223 POST /dialog/authorize/decision - Submit with invalid CSRF token';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    if (testEnv.trustedClient) {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } else {
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        _csrf: tokens.create('abcdefghijklmnop')
        // Uncomment to emulate cancel button
        // cancel: 'deny'
      };
      delete chain.parsedTransactionId;
      return Promise.resolve(chain);
    } // untrusted client
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 403 });
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log(chain.responseErrorMessage);

      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: parsedLocationHeader has "error=EBADCSRFTOKEN"');
      assert.ok(chain.parsedLocationHeader.indexOf('error=EBADCSRFTOKEN') >= 0);
      console.log('\tExpect: parsedLocationHeader does not include authorization code');
      assert.ok(chain.parsedLocationHeader.indexOf('code=') < 0);
      return Promise.resolve(chain);
    } // not skipped
  }) // 223 POST /dialog/authorize/decision

  // ----------------------------------------------------------
  // 224 /dialog/authorize - Check decision with missing properties
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #5 above, this time we still have a valid cookie
  // so the login form can be skipped.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '224 /dialog/authorize - Check decision with missing properties';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    if (testEnv.trustedClient) {
      chain.abortManagedFetch = true;
    }
    return Promise.resolve(chain);
  })

  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(chain.responseRawData);

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: body contains "<title>Resource Decision</title>"');
      assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
      console.log('\tExpect: body contains "name="_csrf""');
      assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
      console.log('\tExpect: body contains "name="transaction_id""');
      assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

      //
      // Parse Data
      //
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      chain.parsedTransactionId =
        chain.responseRawData.split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    } // untrusted client
  }) // 224 /dialog/authorize

  // --------------------------------------------------------
  // 225 POST /dialog/authorize/decision - Submit decision without transaction ID
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #6 above
  // --------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '225 POST /dialog/authorize/decision - Submit decision without transaction ID';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    if (testEnv.trustedClient) {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } else {
      chain.requestBody = {
        // transaction_id: chain.parsedTransactionId,
        _csrf: chain.parsedCsrfToken
        // Uncomment to emulate cancel button
        // cancel: 'deny'
      };
      return Promise.resolve(chain);
    } // untrusted client
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 400 });
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log(chain.responseErrorMessage);

      console.log('\tExpect: status === 400');
      assert.strictEqual(chain.responseStatus, 400);
      console.log('\tExpect: Error message contains \'"msg":"Required value","path":"transaction_id"\'');
      assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"transaction_id"') >= 0);
      return Promise.resolve(chain);
    } // not skipped
  }) // 225 POST /dialog/authorize/decision

  // ----------------------------------------------------------
  // 226 /dialog/authorize - User submit decision: abort (cancel)
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #5 above, this time we still have a valid cookie
  // so the login form can be skipped.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '226 /dialog/authorize - User submit decision abort';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    if (testEnv.trustedClient) {
      chain.abortManagedFetch = true;
    }
    return Promise.resolve(chain);
  })

  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(chain.responseRawData);

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: body contains "<title>Resource Decision</title>"');
      assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
      console.log('\tExpect: body contains "name="_csrf""');
      assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
      console.log('\tExpect: body contains "name="transaction_id""');
      assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

      //
      // Parse Data
      //
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      chain.parsedTransactionId =
        chain.responseRawData.split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    } // untrusted client
  }) // 226 /dialog/authorize

  // --------------------------------------------------------
  // 227 POST /dialog/authorize/decision - Submit decision with Cancel: deny
  //
  // Challenge authorization code expiration
  //
  // This is a copy/paste of step #6 above
  // --------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '227 POST /dialog/authorize/decision - Submit decision with Cancel: deny';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    if (testEnv.trustedClient) {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } else {
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        _csrf: chain.parsedCsrfToken,
        // emulate cancel button
        cancel: 'deny'
      };
      return Promise.resolve(chain);
    } // untrusted client
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 400 });
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log(chain.responseErrorMessage);

      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: parsedLocationHeader has "error=access_denied"');
      assert.ok(chain.parsedLocationHeader.indexOf('error=access_denied') >= 0);
      console.log('\tExpect: parsedLocationHeader does not include authorization code');
      assert.ok(chain.parsedLocationHeader.indexOf('code=') < 0);

      return Promise.resolve(chain);
    } // not skipped
  }) // 227 POST /dialog/authorize/decision

  // ----------------------------------------------------------
  // 300 /dialog/authorize - Test refresh token expires, request authcode
  //
  // Challenge refresh_token expiration time
  //
  // This is a copy/paste of step #5 above, this time we still have a valid cookie
  // so the login form can be skipped.
  //
  // In this case, the authorization request is made with a valid cookie.
  // Depending on the configuration of the client account, two different
  // responses are possible. If the client is configured with
  // trustedClient=true, a 302 redirect to the Oauth 2.0 callback URI
  // with an authorization code included in the 302 Location header.
  // Alternately, if the client is configured with trustedClient=false,
  // the authentication request will return a HTML form for the user
  // to 'Accept' or 'Deny' the application to access the specified resource.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '300 /dialog/authorize - Test refresh token expires, request authcode';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.parsedAccessToken = null;
    chain.parsedRefreshToken = null;
    chain.deCompiledToken = null;

    if ((config.oauth2.refreshTokenExpiresInSeconds === 15) &&
      (!config.oauth2.disableRefreshTokenGrant)) {
      return Promise.resolve(chain);
    } else {
      console.log('\nTo test refresh token expiration, ' +
        'configure server: OAUTH2_REFRESH_TOKEN_EXPIRES_IN_SECONDS=15');
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      if (testEnv.trustedClient) {
        return Promise.resolve(chain);
      } else {
        logRequest(chain);
        // console.log(JSON.stringify(chain.responseRawData, null, 2));

        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
        console.log('\tExpect: body contains "<title>Resource Decision</title>"');
        assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
        console.log('\tExpect: body contains "name="_csrf""');
        assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
        console.log('\tExpect: body contains "name="transaction_id""');
        assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

        //
        // Parse Data
        //
        chain.parsedCsrfToken =
          chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
        chain.parsedTransactionId =
          chain.responseRawData
            .split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
        return Promise.resolve(chain);
      } // untrusted client
    }
  }) // 300 /dialog/authorize

  // --------------------------------------------------------
  // 301 POST /dialog/authorize/decision - User submits accept/deny
  //
  // Challenge access_token expiration time
  //
  // This is a copy/paste of step #6 above
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      if ((config.oauth2.refreshTokenExpiresInSeconds === 15) &&
        (!config.oauth2.disableRefreshTokenGrant)) {
        return Promise.resolve(chain);
      } else {
        if (!testEnv.trustedClient) {
          chain.abortManagedFetch = true;
        }
        chain.skipInlineTests = true;
        return Promise.resolve(chain);
      }
    } else {
      chain.testDescription =
        '301 POST /dialog/authorize/decision - User submits accept/deny';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      if ((config.oauth2.refreshTokenExpiresInSeconds === 15) &&
        (!config.oauth2.disableRefreshTokenGrant)) {
        chain.requestBody = {
          transaction_id: chain.parsedTransactionId,
          _csrf: chain.parsedCsrfToken
          // Uncomment to emulate cancel button
          // cancel: 'deny'
        };
        delete chain.parsedTransactionId;
        return Promise.resolve(chain);
      } else {
        chain.abortManagedFetch = true;
        chain.skipInlineTests = true;
        return Promise.resolve(chain);
      }
    } // untrusted client
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      delete chain.abortManagedFetch;
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      // console.log('parsedLocationHeader: ', chain.parsedLocationHeader);
      console.log('\tExpect: parsedLocationHeader has authorization code');
      assert.ok(chain.parsedLocationHeader.indexOf('code=') >= 0);
      console.log('\tExpect: parsedLocationHeader header has state nonce');
      assert.ok(chain.parsedLocationHeader.indexOf('state=') >= 0);

      //
      // Parse Data
      //
      chain.parsedAuthCode =
        chain.parsedLocationHeader.split('code=')[1].split('&state')[0];
      chain.parsedStateNonce =
        chain.parsedLocationHeader.split('state=')[1];
      console.log('\tExpect: parsed state nonce match previous');
      assert.deepEqual(chain.parsedStateNonce, chain.randomStateNonce);
      if (testEnv.trustedClient) {
        console.log('\n301 POST /dialog/authorize/decision - User submits accept/deny');
        console.log('\tTest aborted, client account configuration trustedClient=true');
      }
      return Promise.resolve(chain);
    } // not skipped
  }) // 301 POST /dialog/authorize/decision

  // -----------------------------------------
  // 302 POST /oauth/token - Get access_token and refresh_token
  //
  // In this request, the authorization code obtained
  // in step #6 will be set to the server.
  // In response to a valid authorization code,
  // the server will return both an OAuth 2.0 access_token
  // and a refresh_token in the body of the response.
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '302 POST /oauth/token - Get access_token and refresh_token';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // No cookie, auth in body of request
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    if ((config.oauth2.refreshTokenExpiresInSeconds === 15) &&
      (!config.oauth2.disableRefreshTokenGrant)) {
      chain.requestBody = {
        code: chain.parsedAuthCode,
        redirect_uri: testEnv.redirectURI,
        client_id: testEnv.clientId,
        client_secret: testEnv.clientSecret,
        grant_type: 'authorization_code'
      };
      delete chain.parsedTransactionId;
      delete chain.parsedAuthCode;
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      chain.abortSleepTimer = true;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: Content-type === "application/json"');
      assert.strictEqual(chain.parsedContentType, 'application/json');
      console.log('\tExpect: response token_type === "Bearer"');
      assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
      console.log('\tExpect: response grantType === "authorization_code"');
      assert.strictEqual(chain.responseRawData.grant_type, 'authorization_code');

      // Evaluate times in server response
      const timeNowSec = Math.floor(Date.now() / 1000);
      console.log('\tExpect: expires_in value close to expected');
      const expDelta = Math.abs(config.oauth2.tokenExpiresInSeconds -
        chain.responseRawData.expires_in);
      assert.ok((expDelta < 3));
      console.log('\tExpect: auth_time value close to expected');
      const authDelta = Math.abs(timeNowSec - chain.responseRawData.auth_time);
      assert.ok((authDelta < 3));
      console.log('\tExpect: response has scope property (value not evaluated)');
      assert.ok(Object.hasOwn(chain.responseRawData, 'scope'));
      console.log('\tExpect: response has access_token property');
      assert.ok(Object.hasOwn(chain.responseRawData, 'access_token'));
      console.log('\tExpect: access_token 3 parts (xxx.xxx.xxx)');
      assert.strictEqual(chain.responseRawData.access_token.split('.').length, 3);

      if (!config.oauth2.disableRefreshTokenGrant) {
        console.log('\tExpect: response has refresh_token property');
        assert.ok(Object.hasOwn(chain.responseRawData, 'refresh_token'));
        console.log('\tExpect: refresh_token 3 parts (xxx.xxx.xxx)');
        assert.strictEqual(chain.responseRawData.refresh_token.split('.').length, 3);
      }

      //
      // Parse Data
      //
      chain.parsedAccessToken = chain.responseRawData.access_token;
      chain.parsedRefreshToken = chain.responseRawData.refresh_token;
      chain.deCompiledToken = deCompileAccessToken(chain.parsedAccessToken);

      //
      // More tests
      //
      console.log('\tExpect: access_token header has token type "JWT"');
      assert.strictEqual(chain.deCompiledToken.header.typ, 'JWT');
      console.log('\tExpect: access_token header has algorithm "RS256"');
      assert.strictEqual(chain.deCompiledToken.header.alg, 'RS256');
      //
      // Show Token
      //
      showJwtToken(chain);

      return Promise.resolve(chain);
    } // not skipped
  }) // 302 POST /oauth/token

  // --------------------------------
  // Wait 5 of 15 seconds
  // --------------------------------
  .then((chain) => sleep(
    chain,
    5,
    'Waiting before refresh token success confirmed'
  ))

  // -----------------------------------------
  // 303 POST /oauth/token - Verify refresh token works before expire
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '303 POST /oauth/token - Verify refresh token works before expire';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    if ((config.oauth2.refreshTokenExpiresInSeconds === 15) &&
     (!config.oauth2.disableRefreshTokenGrant)) {
      // No cookie, auth in body of request
      chain.requestAuthorization = 'none';
      chain.requestAcceptType = 'application/json';
      chain.requestContentType = 'application/json';
      chain.parsedAccessToken = null;
      chain.deCompiledToken = null;

      chain.requestBody = {
        client_id: testEnv.clientId,
        client_secret: testEnv.clientSecret,
        grant_type: 'refresh_token',
        refresh_token: chain.parsedRefreshToken
      };
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.abortSleepTimer = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      chain.abortSleepTimer = true;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: Content-type === "application/json"');
      assert.strictEqual(chain.parsedContentType, 'application/json');
      console.log('\tExpect: response has access_token property');
      assert.ok(Object.hasOwn(chain.responseRawData, 'access_token'));
      console.log('\tExpect: access_token 3 parts (xxx.xxx.xxx)');
      assert.strictEqual(chain.responseRawData.access_token.split('.').length, 3);
      console.log('\tExpect: response token_type === "Bearer"');
      assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
      console.log('\tExpect: response grantType === "refresh_token"');
      assert.strictEqual(chain.responseRawData.grant_type, 'refresh_token');
      //
      // Parse Data
      //
      chain.parsedAccessToken = chain.responseRawData.access_token;
      //
      // Show Token
      //
      showJwtToken(chain);

      return Promise.resolve(chain);
    } // not skipped
  }) // 303 POST /oauth/token

  // --------------------------------
  // Wait 5 of 15 seconds
  // --------------------------------
  .then((chain) => sleep(
    chain,
    // Already waited 5 seconds, add 2 additional
    config.oauth2.refreshTokenExpiresInSeconds - 5 + 2,
    'Waiting for refresh token to expire'
  ))

  // -----------------------------------------
  // 304 POST /oauth/token - Confirm refresh_token expired
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '304 POST /oauth/token - Confirm refresh_token expired';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    if ((config.oauth2.refreshTokenExpiresInSeconds === 15) &&
     (!config.oauth2.disableRefreshTokenGrant)) {
      // No cookie, auth in body of request
      chain.requestAuthorization = 'none';
      chain.requestAcceptType = 'application/json';
      chain.requestContentType = 'application/json';
      chain.parsedAccessToken = null;
      chain.deCompiledToken = null;

      chain.requestBody = {
        client_id: testEnv.clientId,
        client_secret: testEnv.clientSecret,
        grant_type: 'refresh_token',
        refresh_token: chain.parsedRefreshToken
      };
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      chain.abortSleepTimer = true;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 403 });
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log(chain.responseErrorMessage);
      console.log('\tExpect: Error message contains \'"error":"invalid_grant"\'');
      assert.ok(chain.responseErrorMessage.indexOf('"error":"invalid_grant"') >= 0);
      console.log('\tExpect: Error message contains \'"error_description":"Invalid refresh token"\'');
      assert.ok(chain.responseErrorMessage.indexOf('"error_description":"Invalid refresh token"') >= 0);
      //
      // Parse Data
      //
      chain.parsedAccessToken = null;
      // Show Token
      //
      showJwtToken(chain);

      return Promise.resolve(chain);
    } // not skipped
  }) // 304 POST /oauth/token

  //
  // For Debug, show chain object
  //
  .then((chain) => showChain(chain))

  //
  // Assert did not exit, assume all tests passed
  //
  .then((chain) => {
    console.log('---------------------');
    console.log('  All Tests Passed');
    console.log('---------------------');
  })

  //
  // In normal testing, no errors should be rejected in the promise chain.
  // In the case of hardware network errors, catch the error.
  .catch((err) => showHardError(err));
