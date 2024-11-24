// access-token-client.js
//
// It is an overall test of access token validation for token
// created using client credentials grant.

// This API test script was written to explore the relationship between
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
//    OAUTH2_CLIENT_TOKEN_EXPIRES_IN_SECONDS=10
//
// The tests in this module were primarily written for the author
// to better understand how JWT tokens are verified by the Oauth 2.0 server.
//
// The tests are limited in scope and not comprehensive of all possible security risks.
// -----------------------------------------------------------
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/access-token-client.js');
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

  // -----------------------------------------
  // 2 GET /oauth/token - Request access_token using client credentials
  //
  // This will submit a set of client credentials
  // to the authentication server.
  // In the case where the credentials are valid
  // and the client account has sufficient scope
  // to issue access_tokens, a new access_token
  // will be generated and returned in the response.
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription = '2 GET /oauth/token - Request access_token using client credentials';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // Note: Requested value of scope is hardcoded, matching file "example-clients-db.json"
    chain.requestAuthorization = 'basic';
    chain.requestBody = {
      grant_type: 'client_credentials',
      scope: 'api.read api.write'
    };
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
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: Content-type === "application/json"');
    assert.strictEqual(chain.parsedContentType, 'application/json');
    console.log('\tExpect: response token_type === "Bearer"');
    assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
    console.log('\tExpect: response grantType === "client_credentials"');
    assert.strictEqual(chain.responseRawData.grantType, 'client_credentials');
    // Evaluate times in server response
    const timeNowSec = Math.floor(Date.now() / 1000);
    console.log('\tExpect: expires_in value close to expected');
    const expDelta = Math.abs(config.oauth2.clientTokenExpiresInSeconds -
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
    //
    // Parse Data
    //
    chain.parsedAccessToken = chain.responseRawData.access_token;
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
  })

  // ----------------------------------------------------------
  // 3 POST /oauth/introspect - Submit token, verify active and meta-data before further tests
  //
  // This request will submit the access_token obtained in step #2
  // to the authentication server. A set of valid client credentials are
  // required to submit the request. The authentication server
  // will check the signature of the access token, if valid and
  // not expired, the meta-data associated with the access_token
  // will be looked up in the token database and returned in the response
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '3 POST /oauth/introspect - Submit token, verify active and meta-data before further tests';
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
    console.log('\tExpect: The grant_type value matches "client_credentials"');
    assert.strictEqual(chain.responseRawData.grant_type, 'client_credentials');
    console.log('\tExpect: value of client.clientId is as expected');
    assert.strictEqual(chain.responseRawData.client.clientId, testEnv.clientId);
    console.log('\tExpect: The issuer value matches config auth URL');
    assert.strictEqual(chain.responseRawData.issuer, config.site.authURL + '/oauth/token');
    console.log('\tExpect: The jti value in token matches meta-data in response');
    assert.strictEqual(chain.responseRawData.jti, chain.deCompiledToken.decodedToken.jti);
    // Evaluate times in server response
    const timeNowSec = Math.floor(Date.now() / 1000);
    console.log('\tExpect: expires_in value close to expected');
    const expiresInDelta = Math.abs(config.oauth2.clientTokenExpiresInSeconds -
       chain.responseRawData.expires_in);
    assert.ok((expiresInDelta < 3));
    console.log('\tExpect: auth_time value close to expected');
    const authDelta = Math.abs(timeNowSec - chain.responseRawData.auth_time);
    assert.ok((authDelta < 3));
    console.log('\tExpect: exp value close to expected');
    const expDelta = Math.abs((timeNowSec + config.oauth2.clientTokenExpiresInSeconds) -
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
  })

  // ----------------------------------------------------------
  // 4 POST /oauth/introspect - Mint new access token, confirm accepted
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '4 POST /oauth/introspect - Mint new access token, confirm accepted';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      chain.deCompiledToken.decodedToken.jti,
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.clientTokenExpiresInSeconds,
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
  })
  // ----------------------------------------------------------
  // 5 POST /oauth/introspect - Mint expired access token (expires = -3600 sec)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '5 POST /oauth/introspect - Mint expired access token (expires = -3600 sec)';
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
  })

  // ----------------------------------------------------------
  // 6 POST /oauth/introspect - Mint access token with random JTI
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '6 POST /oauth/introspect - Mint access token with random JTI';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      // Generate random JTI using same method as server
      uuid.v4(),
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.clientTokenExpiresInSeconds,
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
  })

  // ----------------------------------------------------------
  // 7 POST /oauth/introspect - Concatenate a character at start of access token header
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '7 POST /oauth/introspect - Concatenate a character at start of access token header';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      chain.deCompiledToken.decodedToken.jti,
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.clientTokenExpiresInSeconds,
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
  })

  // ----------------------------------------------------------
  // 8 POST /oauth/introspect - Concatenate a character at start of access token payload
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '8 POST /oauth/introspect - Concatenate a character at start of access token payload';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      chain.deCompiledToken.decodedToken.jti,
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.clientTokenExpiresInSeconds,
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
  })

  // ----------------------------------------------------------
  // 99 POST /oauth/introspect - Done mutated tokens, confirm JTI still accepted
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '99 POST /oauth/introspect - Done mutated tokens, confirm JTI still accepted';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    const newToken = mintNewAccessToken(
      chain.deCompiledToken.decodedToken.jti,
      chain.deCompiledToken.decodedToken.sub,
      config.oauth2.clientTokenExpiresInSeconds,
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
  })

  //
  // Next section is optional expiration test using timer
  //
  // -----------------------------------------
  // 100 POST /oauth/token - Request a new access_token
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '100 POST /oauth/token - Request a new access_token';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    chain.requestAuthorization = 'basic';
    if (config.oauth2.clientTokenExpiresInSeconds === 10) {
      chain.requestBody = {
        grant_type: 'client_credentials',
        scope: 'api.read api.write'
      };
      return Promise.resolve(chain);
    } else {
      console.log('\nTo test token expiration, ' +
        'configure server: OAUTH2_CLIENT_TOKEN_EXPIRES_IN_SECONDS=10');
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
      console.log('\tExpect: response has access_token property');
      assert.ok(Object.hasOwn(chain.responseRawData, 'access_token'));
      //
      // Parse Data
      //
      chain.parsedAccessToken = chain.responseRawData.access_token;
      chain.deCompiledToken = deCompileAccessToken(chain.parsedAccessToken);
      //
      // Show Token
      //
      showJwtToken(chain);
      return Promise.resolve(chain);
    }
  })

  // --------------------------------
  // Wait for access token to expire
  // --------------------------------
  .then((chain) => sleep(
    chain,
    // Set timer 4 + 8 = 12 seconds, expire in 10 seconds
    4,
    'Delay before confirming token still works.'
  ))

  // ----------------------------------------------------------
  // 101 POST /oauth/introspect - Verify token accepted before time delay
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '101 POST /oauth/introspect - Verify token accepted before time delay';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    if (config.oauth2.clientTokenExpiresInSeconds === 10) {
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
  })
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
  // 102 POST /oauth/introspect - Expect access token expired after delay
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '102 POST /oauth/introspect - Expect access token expired after delay';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    if (config.oauth2.clientTokenExpiresInSeconds === 10) {
      chain.requestBody = {
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
      logRequest(chain, { ignoreErrorStatus: 401 });
      console.log('\tExpect: status === 401 (access token expired)');
      assert.strictEqual(chain.responseStatus, 401);
      showJwtMetaData(chain);
      return Promise.resolve(chain);
    }
  })

  // ----------------------------------------------------------
  // 103 POST /oauth/introspect - Mint new unexpired token with same JTI
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '103 POST /oauth/introspect - Mint new unexpired access_token with same JTI';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    if (config.oauth2.clientTokenExpiresInSeconds === 10) {
      //
      // build new access token
      //
      const newToken = mintNewAccessToken(
        // uuid.v4(),
        chain.deCompiledToken.decodedToken.jti,
        chain.deCompiledToken.decodedToken.sub,
        config.oauth2.clientTokenExpiresInSeconds,
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
    }
  })

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
