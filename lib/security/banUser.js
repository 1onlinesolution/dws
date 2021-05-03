// ========================================================================================
// From book: Secure Your Node.js Web Application, page 93
//
// Insert delays in your login mechanism.
//
// You can ban the user for a while, such as fifteen minutes after five failed attempts,
// or make the user fill out a CAPTCHA challenge.
// Banning the user is a double-edged sword, because an attacker can maliciously block
// legitimate users by intentionally entering bad passwords, so use it carefully.
// The other approach is to create a universal delay for each failed login
// for a certain period of time. The legitimate user won’t feel the delay; the attacker will.
//
// Ban the user’s IP for a period of time if the user fails to log in a certain number of times

// NOTE: WIP

const maxFailedCount = 5;     // Max tries
const forgetFailedMins = 15;  // time the user will be blocked

class BanUser {
  constructor() {
    this.blockList = {};
  }

  // Check if ip is still allowed
  isAllowed(ip) {
    return !this.blockList[ip] || this.blockList[ip].count < maxFailedCount;
  }

  // Remove ip from blockList
  successfulAttempt(ip) {
    if(this.blockList[ip]) {
      if(this.blockList[ip].timeout) {
        clearTimeout(this.blockList[ip].timeout);
      }
      delete this.blockList[ip];
    }
  }

  // Increment blocklist counter
  failedAttempt(ip) {
    if(!this.blockList[ip]) {
      this.blockList[ip] = {
        count: 0
      };
    }
    this.blockList[ip].count++;
    if(this.blockList[ip].timeout) {
      clearTimeout(this.blockList[ip].timeout);
    }
    this.blockList[ip].timeout = setTimeout(function () {
      delete this.blockList[ip];
    }, forgetFailedMins * 60 * 1000);
  }
}

module.exports = BanUser;


// Example:
// const banUser = new BanUser();
// app.post('/login', function (req, res, next) {
//   if(!banUser.isAllowed(req.ip)) { // Check if user is blocked
//     req.session.error = 'You have been blocked for ' +
//       forgetFailedMins + ' minutes';
//     res.redirect('/');
//     return;
//   }
//   validateUser(req.body, function(err, valid) {
//     if(err) {
//       next(err);
//       return;
//     }
//     if(valid.success) { // Validation success. Create authorized session.
//       banUser.successfulAttempt(req.ip); // Clear from blocklist
//       req.session.login({userId: valid.userId}, function () {
//         res.redirect('/user/' + valid.userId);
//       });
//     } else {
//       banUser.failedAttempt(req.ip); // Register the failed attempt
//       req.session.error = valid.error;
//       res.redirect('/');
//     }
//   });
// });
