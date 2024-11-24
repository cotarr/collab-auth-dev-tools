// managed-fetch.js
//
// This module contains a function managedFetch() that is used
// to perform network requests. It requires the native node-fetch
// module in NodeJs, so Node V18 or greater is needed.
// The managedFetch function returns a promise.
// Shared test variables are passed into the manageFetch function
// through a chain object. The chain object is modified during
// evaluation of the network request results. The modified chain
// object is returned when the promise resolves.
//
// The following pseudo code explains the process
//
// ----------------------------------------------------------
// ...
//   .then((chain) => {
//     // Set various fetch related variables
//     chain.requestMethod = 'GET';
//     chain.requestFetchURL = '/some/route/
//
//     // Set any relevant testing variables
//     chain.someVariables = someValue;
//
//     // Resolved promise passes chain object to managedFetch function
//     return Promise.resolve(chain)
//
//   // (this module is called)
//   .then((chain) => managedFetch(chain))
//
//   .then((chain) => {
//     // Evaluate the results of the fetch operation
//     if (chain.someValue === 'expected result') {
//       doSomething()
//     }
//
//     // Continue to the next test
//     return Promise.resolve(chain)
//   })
// ...
// ----------------------------------------------------------
'use strict';

/**
 * Perform fetch request using native NodeJs fetch() API
 * @param {Object} chain - Chain object used to pass data from promise to promise
 * @param {String} chain.requestMethod - GET and POST supported
 * @param {String} chain.requestFetchURL - Full URI encoded URL
 * @param {String} chain.requestAcceptType - Header: Accept
 * @param {String} chain.requestAuthorization - Values: 'basic', 'cookie
 * @param {String} chain.requestBasicAuthCredentials - Base64 encoded
 * @param {String} chain.currentSessionCookie - Used for requestAuthorization: cookie
 * @param {String} chain.requestContentType - Header: Content-type
 * @param {String} chain.requestBody - Used for POST requests
 * @param {String} chain.forceOverrideContentType - Used to mis-match header verses content
 * @returns {Promise} resolves to chain object, or reject error
 * @returns {Number} chain.responseStatus
 * @returns {String} chain.responseStatusText
 * @returns {Object} chain.responseHeaders
 * @returns {String|Object} chain.responseRawData
 * @returns {String} chain.parsedContentType
 * @returns {String} chain.parsedLocationHeader
 * @returns {String} chain.parseSetCookieHeader
 * @returns {Number} chain.parseSetCookieHeaderExpires
 * @returns {String} chain.currentSessionCookie
 * @returns {Number} chain.currentSessionCookieExpires
 * @returns {String} chain.responseErrorMessage
*/
exports.managedFetch = (chain) => {
  if ((Object.hasOwn(chain, 'testDescription')) &&
    (chain.testDescription.length > 0)) {
    console.log('\nTest:', chain.testDescription);
  }
  if (chain.abortManagedFetch) {
    console.log('\t(Aborted due to test or server configuration)');
    delete chain.abortManagedFetch;
    return Promise.resolve(chain);
  } else {
    return new Promise((resolve, reject) => {
      // Initialize response variables
      chain.responseStatus = null;
      chain.responseStatusText = '';
      chain.responseHeaders = {};
      chain.responseRawData = null;
      chain.parsedContentType = null;
      chain.parsedLocationHeader = null;
      chain.parsedSetCookieHeader = null;
      chain.parseSetCookieHeaderExpires = null;
      chain.responseErrorMessage = null;

      const fetchController = new AbortController();

      const fetchURL = chain.requestFetchURL;

      const fetchOptions = {
        method: chain.requestMethod,
        redirect: 'manual',
        signal: fetchController.signal,
        headers: {
          Accept: '*/*'
        }
      };
      if (Object.hasOwn(chain, 'requestAcceptType')) {
        fetchOptions.headers.Accept = chain.requestAcceptType;
      }
      if (chain.requestAuthorization === 'basic') {
        fetchOptions.headers.Authorization = 'Basic ' + chain.requestBasicAuthCredentials;
      }
      if (chain.requestAuthorization === 'cookie') {
        if ((Object.hasOwn(chain, 'currentSessionCookie')) &&
          (chain.currentSessionCookie != null) &&
          (chain.currentSessionCookie.length > 0)) {
          fetchOptions.headers.cookie = chain.currentSessionCookie;
          if ((Object.hasOwn(process.env, 'SHOWCOOKIE') &&
            (parseInt(process.env.SHOWCOOKIE) === 1))) {
            console.log('---------- REQUEST Cookie Header ----------');
            console.log(chain.currentSessionCookie);
            console.log('-----------END Cookie Header --------------');
          }
        }
      }
      if (chain.requestMethod === 'POST') {
        if (chain.requestContentType === 'application/json') {
          fetchOptions.headers['Content-type'] = 'application/json';
          fetchOptions.body = JSON.stringify(chain.requestBody);
        } else if (chain.requestContentType === 'application/x-www-form-urlencoded') {
          fetchOptions.headers['Content-type'] = 'application/x-www-form-urlencoded';
          let body = '';
          const keys = Object.keys(chain.requestBody);
          if (keys.length > 0) {
            for (let i = 0; i < keys.length; i++) {
              if (i > 0) body += '&';
              body += encodeURIComponent(keys[i]) + '=';
              body += encodeURIComponent(chain.requestBody[keys[i]]);
            }
          }
          fetchOptions.body = body;
        } else if (chain.requestContentType === 'text/html') {
          fetchOptions.headers['Content-type'] = 'text/html';
          // Note: this is not encoded
          fetchOptions.body = chain.requestBody;
        } else {
          const error = new Error('Unsupported or missing Content-type in POST request');
          reject(error);
        }
      }
      //
      // Used for testing, after processing the request of one type,
      // change the request header before sending, to create a type mismatch.
      //
      if (chain.forceOverrideContentType) {
        fetchOptions.headers['Content-type'] = chain.forceOverrideContentType;
        delete chain.forceOverrideContentType;
      }

      // console.log('fetchOptions', JSON.stringify(fetchOptions, null, 2));

      const fetchTimerId = setTimeout(() => fetchController.abort(), 5000);

      fetch(fetchURL, fetchOptions)
        .then((response) => {
          // console.log('response', response);
          chain.responseStatus = response.status;
          chain.responseStatusText = response.statusText;
          chain.responseHeaders = {};
          let showHeadersFlag = false;
          if ((process.env.SHOWRES != null) && ((parseInt(process.env.SHOWRES) & 2) === 2)) {
            showHeadersFlag = true;
          }
          if (showHeadersFlag) {
            console.log('------------ RESPONSE HEADERS --------------');
          }
          const responseCookieArray = [];
          for (const header of response.headers) {
            chain.responseHeaders[header[0]] = header[1];
            if (header[0].toLowerCase() === 'content-type') {
              chain.parsedContentType = header[1].toLowerCase();
            }
            if (header[0].toLowerCase() === 'set-cookie') {
              responseCookieArray.push(header[1]);
            }
            if (header[0].toLowerCase() === 'location') {
              chain.parsedLocationHeader = header[1];
            }
            if (showHeadersFlag) {
              console.log('"' + header[0] + '": "' + header[1] + '"');
            }
          };
          if (showHeadersFlag) {
            console.log('-------------- END HEADERS -----------------');
          }
          // Assume only 1 cookie is returned from auth server
          if (responseCookieArray.length === 1) {
            // This variable will persist in future fetch calls
            chain.currentSessionCookie = responseCookieArray[0].split(';')[0];
            // This variable is set null before each fetch
            chain.parsedSetCookieHeader = responseCookieArray[0].split(';')[0];

            // parse cookie expiration time if present
            const cookieFields = responseCookieArray[0].split(';');
            cookieFields.forEach((field) => {
              if (field.toLowerCase().indexOf('expires=') >= 0) {
                const expDateObj = new Date(field.split('='[1]));
                chain.parseSetCookieHeaderExpires = Math.floor(expDateObj.getTime() / 1000);
                chain.currentSessionCookieExpires = Math.floor(expDateObj.getTime() / 1000);
                // console.log(chain.cookieExpires);
              }
            });
            if ((Object.hasOwn(process.env, 'SHOWCOOKIE') &&
            (parseInt(process.env.SHOWCOOKIE) === 1))) {
              console.log('------ RESPONSE Set-Cookie Header ---------');
              console.log(responseCookieArray[0]);
              console.log('--------- END Set-cookie Header------------');
            }
          } else if (responseCookieArray.length > 1) {
            throw new Error('Fatal test error: Response contained more than 1 set-cookie header');
          }

          if ((response.ok) || (response.status === 302)) {
            if ((chain.parsedContentType) &&
              (chain.parsedContentType.indexOf('application/json') >= 0)) {
              return response.json();
            } else if ((chain.parsedContentType) &&
              (chain.parsedContentType.indexOf('text/html') >= 0)) {
              return response.text();
            } else {
              return response.text();
            }
          } else {
            // Retrieve error message from remote web server and pass to error handler
            return response.text()
              .then((remoteErrorText) => {
                let showResponseError = false;
                if ((process.env.SHOWRES != null) && ((parseInt(process.env.SHOWRES) & 1) === 1)) {
                  showResponseError = true;
                }
                if (showResponseError) {
                  console.log('------------ RESPONSE ERROR TEXT --------------');
                  console.log(remoteErrorText);
                  console.log('--------------- END RESPONSE ------------------');
                }
                const err = new Error('HTTP status error');
                err.status = response.status;
                err.statusText = response.statusText;
                err.remoteErrorText = remoteErrorText;
                if (response.headers.get('WWW-Authenticate')) {
                  err.oauthHeaderText = response.headers.get('WWW-Authenticate');
                }
                throw err;
              });
          }
        })
        .then((data) => {
          let showRawResponse = false;
          if ((process.env.SHOWRES != null) && ((parseInt(process.env.SHOWRES) & 1) === 1)) {
            showRawResponse = true;
          }
          if (showRawResponse) {
            console.log('------------ RAW RESPONSE BODY --------------');
            if ((chain.parsedContentType) &&
              (chain.parsedContentType.toLowerCase().indexOf('application/json') >= 0)) {
              console.log(JSON.stringify(data, null, 2));
            } else {
              console.log(data);
            }
            console.log('--------------- END RESPONSE ----------------');
          }
          if (fetchTimerId) clearTimeout(fetchTimerId);
          chain.responseRawData = data;
          resolve(chain);
        })
        .catch((err) => {
          // console.log(err);
          if (fetchTimerId) clearTimeout(fetchTimerId);
          // Build generic error message to catch network errors
          let message = ('Fetch error, ' + fetchOptions.method + ' ' + fetchURL + ', ' +
            (err.message || err.toString() || 'Error'));
          if (err.status) {
            // Case of HTTP status error, build descriptive error message
            message = ('HTTP status error, ') + err.status.toString() + ' ' +
              err.statusText + ', ' + fetchOptions.method + ' ' + fetchURL;
          }
          if (err.remoteErrorText) {
            message += ', ' + err.remoteErrorText;
          }
          if (err.oauthHeaderText) {
            message += ', ' + err.oauthHeaderText;
          }
          const error = new Error(message);
          if ((err.status) && (err.status > 0)) {
            chain.responseErrorMessage = message;
            resolve(chain);
          } else {
            reject(error);
          }
        }); // catch
    }); // promise
  } // if fetch not aborted
}; // managedFetch()
