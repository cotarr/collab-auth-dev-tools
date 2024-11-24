// test-utils.js
//
// The file contains common toolbox functions used by test test modules.
// -----------------------------------------------------------
'use-strict';

/**
 * Log the fetch request from each test
 * @param {Object} chain - Chain object for pass data down a chain of promises
 * @param {Number} chain.responseStatus - HTTP response status code
 * @param {String} chain.requestMethod
 * @param {String} chain.requestFetchURL
 * @param {String} chain.responseErrorMessage - Contents (body) of error response from server
 * @param {Object} options - Optional log options
 * @param {Number|[Number]} options.ignoreErrorStatus - Do not log these error status codes
 */
exports.logRequest = (chain, options) => {
  if (options == null) options = {};
  let logURL = chain.requestFetchURL.split('?')[0];
  if ((Object.hasOwn(process.env, 'SHOWQUERY')) &&
    (parseInt(process.env.SHOWQUERY) === 1)) {
    logURL = chain.requestFetchURL;
  }
  console.log('\t' + chain.responseStatus + ' ' +
    chain.requestMethod + ' ' + logURL);
  let ignoreErrorStatusList = [];
  if (Object.hasOwn(options, 'ignoreErrorStatus')) {
    if (typeof options.ignoreErrorStatus === 'number') {
      ignoreErrorStatusList = [options.ignoreErrorStatus];
    }
    if (typeof options.ignoreErrorStatus === 'string') {
      ignoreErrorStatusList = [parseInt(options.ignoreErrorStatus)];
    }
    if (Array.isArray(options.ignoreErrorStatus)) {
      ignoreErrorStatusList = options.ignoreErrorStatus;
    }
  }
  if (chain.responseErrorMessage) {
    if (ignoreErrorStatusList.indexOf(chain.responseStatus) < 0) {
      console.log(chain.responseErrorMessage);
    }
  }
  let showChainFlag = false;
  if ((process.env.SHOWCHAIN != null) && (parseInt(process.env.SHOWCHAIN) === 2)) {
    showChainFlag = true;
  }
  if (showChainFlag) {
    console.log('-------------- DEBUG: chain object ----------------');
    console.log('chain', JSON.stringify(chain, null, 2));
    console.log('-------------- DEBUG: end chain -------------------');
  }
};

/**
 * For case of environment variable SHOWCHAIN === 1, log the chain object.
 * @param {Object} chain - Object used to pass data down the promise chain.
 */
exports.showChain = (chain) => {
  let showChainFlag = false;
  if ((process.env.SHOWCHAIN != null) && (parseInt(process.env.SHOWCHAIN) === 1)) {
    showChainFlag = true;
  }
  if (showChainFlag) {
    console.log('-------------- chain object ----------------');
    console.log('chain', JSON.stringify(chain, null, 2));
    console.log('---------------- end chain -----------------');
  }
  Promise.resolve(chain);
};

/**
 * Log hard errors, such as fetch network error.
 * @param {Error} err - Thrown error object.
 */
exports.showHardError = (err) => {
  // console.log(err);
  if ((err.message) &&
    (err.message.indexOf('Fetch error') >= 0) &&
    (err.message.indexOf('fetch failed') >= 0)) {
    console.log('Tests aborted due to hard network error.');
    console.log('The authorization server is not running or the URL is incorrect.');
    console.log(err.message || err.toString() || 'An unknown error occurred while running tests.');
  } else {
    console.log(err.message || err.toString() || 'An unknown error occurred while running tests.');
  }
  if ((Object.hasOwn(process.env, 'SHOWSTACK')) && (parseInt(process.env.SHOWSTACK) === 1)) {
    if (err.stack) console.log(err.stack);
  }
  process.exit(1);
};

/**
 * Log the contents of the access token.
 * @param {Object} chain - Chain object used to pass data down the chain of promises
 * @param {String} chain.responseRawData.access_token - OAuth 2 access token
 * @param {String} chain.responseRawData.refresh_token - OAuth 2 access token
 */
exports.showJwtToken = (chain) => {
  let tempDateObj = null;
  if ((process.env.SHOWTOKEN != null) && ((parseInt(process.env.SHOWTOKEN) & 1) === 1)) {
    if ((chain.responseRawData != null) &&
      (Object.hasOwn(chain.responseRawData, 'access_token')) &&
      (chain.responseRawData.access_token != null) &&
      (chain.responseRawData.access_token.length > 0)) {
      const decodedAccessToken = {
        preamble: JSON.parse(
          Buffer.from(chain.responseRawData.access_token.split('.')[0], 'base64').toString('utf-8')
        ),
        payload: JSON.parse(
          Buffer.from(chain.responseRawData.access_token.split('.')[1], 'base64').toString('utf-8')
        )
      };
      console.log('--------------- access_token ------------------');
      console.log(JSON.stringify(decodedAccessToken, null, 2));
      // Convert times to human readable
      console.log('\tHuman readable...');
      tempDateObj = new Date(decodedAccessToken.payload.iat * 1000);
      console.log('\tiat: ', tempDateObj.toISOString());
      tempDateObj = new Date(decodedAccessToken.payload.exp * 1000);
      console.log('\texp: ', tempDateObj.toISOString());
      //
      // see if there is a refresh token
      //
      if ((Object.hasOwn(chain.responseRawData, 'refresh_token')) &&
      (chain.responseRawData.refresh_token.length > 0)) {
        const decodedRefreshToken = {
          preamble: JSON.parse(
            Buffer.from(chain.responseRawData.refresh_token.split('.')[0], 'base64')
              .toString('utf-8')
          ),
          payload: JSON.parse(
            Buffer.from(chain.responseRawData.refresh_token.split('.')[1], 'base64')
              .toString('utf-8')
          )
        };
        console.log('--------------- refresh_token ------------------');
        console.log(JSON.stringify(decodedRefreshToken, null, 2));
        // Convert times to human readable
        console.log('\tHuman readable...');
        tempDateObj = new Date(decodedRefreshToken.payload.iat * 1000);
        console.log('\tiat: ', tempDateObj.toISOString());
        tempDateObj = new Date(decodedRefreshToken.payload.exp * 1000);
        console.log('\texp: ', tempDateObj.toISOString());
      }
      console.log('-----------------------------------------------');
    }
  }
}; // showJwtToken()

/**
 * Log the access token meta-data.
 * @param {Object} chain - Chain object used to pass data down the chain of promises
 * @param {Object} chain.responseRawData - HTTP response body
 */
exports.showJwtMetaData = (chain) => {
  let tempDateObj = null;
  if ((process.env.SHOWTOKEN != null) && ((parseInt(process.env.SHOWTOKEN) & 2) === 2)) {
    if ((chain.responseStatus === 200) && (chain.responseRawData != null)) {
      console.log('--------access_token meta data  --------------');
      console.log(JSON.stringify(chain.responseRawData, null, 2));
      // Convert times to human readable
      console.log('\tHuman readable...');
      tempDateObj = new Date(chain.responseRawData.iat * 1000);
      console.log('\tiat:       ', tempDateObj.toISOString());
      tempDateObj = new Date(chain.responseRawData.exp * 1000);
      console.log('\texp:       ', tempDateObj.toISOString());
      tempDateObj = new Date(chain.responseRawData.auth_time * 1000);
      console.log('\tauth_time: ', tempDateObj.toISOString());
      console.log('-----------------------------------------------');
    }
  }
};

/**
 * Notify user if virtual host mismatch is reject requests
 * @param {Number} chain.responseStatus - HTTP status code of previous fetch
 */
exports.check404PossibleVhostError = (chain) => {
  if (chain.responseStatus === 404) {
    console.log('\nWarning: First request of test returned 404 Not Found');
    console.log('The base URL used for test may be blocked due to virtual hosting vhost setting');
    console.log('Check setting for SITE_VHOST=\n');
    process.exit(1);
  }
};
