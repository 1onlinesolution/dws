const BaseValidator = require('./baseValidator');
const Validity = require('../../tools/validity');
const { check } = require('express-validator');

class EmailValidator extends BaseValidator {
  constructor({ fields = 'email', messageRequired = 'Email is required', messageInvalid = 'Not a valid email' } = {}) {
    super({ fields });

    this.messageRequired = messageRequired;
    this.messageInvalid = messageInvalid;
    return this;
  }

  validateEmail() {
    return check(this.fields)
      .not()
      .isEmpty()
      .withMessage(this.messageRequired)
      .trim()
      .escape()
      .isEmail()
      .normalizeEmail()
      .withMessage(this.messageInvalid);
  }

  validateEmailWithCustomRule({
    customAction = this.checkEmailRule,
  } = {}) {
    return check(this.fields)
      .not()
      .isEmpty()
      .withMessage(this.messageRequired)
      .trim()
      .escape()
      .normalizeEmail()
      .custom(customAction);
  }

  checkEmailRule(value) {
    return Validity.isValidEmail(value);
  }

}

module.exports = EmailValidator;

