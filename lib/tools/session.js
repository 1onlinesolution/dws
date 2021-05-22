// ========================================================================================
// From book: Secure Your Node.js Web Application, page 103
//
// Implementation of a two-tiered model.
//
// A two-tier system is a session with two states:
// one for a short period immediately after logging in
// and the other that keeps you signed in but with a lower access level.
//
// Users can access less-secure areas for a longer period of time,
// but when trying to access more privileged areas, the user must authenticate again.
// A new session is created with privileged access for a short period of time
// and then degrades a to low-level session again. GitHub uses this mode, for example.
//
// Extend the Session prototype with custom functions.
//
// We can now use these functions in our application.
// We can check if the session  is valid and allow privileged access
// if the session was validated recently by using:
// 'req.session.login()', 'req.session.isLoggedIn()', and 'req.session.isFresh()'.

// More on security issues:
// https://supertokens.io/blog/all-you-need-to-know-about-user-session-security

const session = require('express-session');

// Extend the Session prototype with some custom functions
// Add a login function
session.Session.prototype.login = function login(cb) {
  const req = this.req;
  this.regenerate(function(err) {
    if (err) {
      cb(err);
      return;
    }
    req.session._loggedInAt = Date.now();
    req.session._ip = req.ip;
    req.session._ua = req.headers['user-agent'];
    cb();
  });
};

// Add a function to check the logged in status of the user
session.Session.prototype.isLoggedIn = function isLoggedIn() {
  return !!this._loggedInAt;
};

session.Session.prototype.isGuest = function isGuest() {
  return !this._loggedInAt; // If this is not set then we are not logged in
};

// Add a function to check the freshness of the session
session.Session.prototype.isFresh = function isFresh() {

  // Return true if logged in less then 10 minutes ago
  return (this._loggedInAt && (Date.now() - this._loggedInAt) < (1000 * 60 * 10));

};

session.Session.prototype.saveAsync = function saveAsync() {

  return new Promise((resolve, reject) => {
    this.save((err) => {
      if (err) {
        // For any error detected
        reject(err);
      } else {
        // Success
        resolve();
      }
    });
  });

};

session.Session.prototype.reloadAsync = function reloadAsync() {

  return new Promise((resolve, reject) => {
    this.reload((err) => {
      if (err) {
        // For any error detected
        reject(err);
      } else {
        // Success
        resolve();
      }
    });
  });

};

module.exports = session;

// Example code:
// app.get('/login', function (req, res) {
//   req.session.login(function(err) {
//     res.send('ok - ' + req.session._loggedInAt);
//   });
// });
//
// app.get('/secure', function (req, res) {
//   if(!req.session.isLoggedIn()) { // Check if user is logged in
//     res.send(401);
//     return;
//   }
//   res.send('Access');
// });
//
// app.get('/secure/more', function (req, res) {
//   if(!req.session.isFresh()) { // Check if session is fresh
//     res.send(401);
//     return;
//   }
//   res.send('You are fresh');
// });
//
// app.get('/logout', function (req, res) {
//   req.session.destroy(); // Delete session
//   res.redirect('/');
// });
