const User = require('../models/documents/sso/user');

module.exports = (req, res, next) => {

  // middleware to pass extra data to all our pages
  if (req.csrfToken) {
    res.locals.csrfToken = req.csrfToken();
  }

  if (req.session) {
    req.session.isAdmin = User.isAdmin(req.session.user);
    res.locals.user = req.session.user;
    res.locals.isAdmin = req.session.isAdmin;
    if (req.session.user) {
      res.locals.fullName = `${req.session.user.firstName} ${req.session.user.lastName}`;
    }
  }

  res.locals.requestedUrl = req.url;

  if (req.flash) {
    res.locals.data = req.flash('data');
    res.locals.error = req.flash('error');
    res.locals.info = req.flash('info');
  }

  next();

};