// display-config.js
//
// This file is intended to inclusion in the test running.
// It will print relevant configuration file contents related to the testing.
//
// -----------------------------------------------------------
'use strict';

const fs = require('node:fs');

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/display-config.js');
  process.exit(1);
}

const testEnv = require('./modules/import-config.js').testEnv;
const {
  config
  // clients
  // users
} = require('./modules/import-config.js');

console.log('\n--------------------');
console.log('Server configuration');
console.log('--------------------\n');

console.log('server.appVersion: ' + config.server.appVersion);
console.log('site.authUrl: ' + config.site.authURL);
console.log('session.rollingCookie: ' + config.session.rollingCookie);
console.log('session.ttl: ' + config.session.ttl + ' seconds');
console.log('session.enablePgSessionStore: ' + config.session.enablePgSessionStore);
console.log('database.enablePgUserDatabase: ' + config.database.enablePgUserDatabase);
console.log('database.disableWebAdminPanel: ' + config.database.disableWebAdminPanel);

console.log('\n--------------------');
console.log('Test Enviornment');
console.log('--------------------\n');

const filteredTestEnv = Object.assign({}, testEnv);
// Passwords and secrets removed from log.
delete filteredTestEnv.clientSecret;
delete filteredTestEnv.password;
delete filteredTestEnv.redirectTiming;
delete filteredTestEnv.loadTest;

console.log('testEnv ' + JSON.stringify(filteredTestEnv, null, 2));

console.log('---------------------');
console.log(' Display Config Done');
console.log('---------------------');
