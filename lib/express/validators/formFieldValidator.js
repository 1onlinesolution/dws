const Validity = require('../../tools/validity');
const Converter = require('../../tools/converter');
const { check, validationResult } = require('express-validator');

class FormFieldValidator {
  static validateFormInput(req) {
    return validationResult(req);
  };

  static formInputContainsErrors(req) {
    const errors = FormFieldValidator.validateFormInput(req);
    return errors.isEmpty();
  };

  static validateFormInputWithFlash(req, data = null) {
    const errors = FormFieldValidator.validateFormInput(req);
    if (!errors.isEmpty()) {
      // There are errors. Render form again with sanitized values/errors messages.
      // Error messages can be returned in an array using `errors.array()`.
      const errorsArray = errors.array();
      if (req.flash) {
        errorsArray.forEach((error) => {
          req.flash('error', error.msg);
        });

        if (data) req.flash('data', { data: data });
      }
    }

    return errors.isEmpty();
  };

  static validateEmail({
    fields = 'email',
    messageRequired = 'Email is required',
    messageInvalid = 'Not a valid email',
  }) {
    return check(fields)
      .not()
      .isEmpty()
      .withMessage(messageRequired)
      .trim()
      .escape()
      .isEmail()
      .normalizeEmail()
      .withMessage(messageInvalid);
  }

  static validateEmailWithCustomRule({
    fields = 'email',
    messageRequired = 'Email is required',
    messageInvalid = 'Not a valid email',
    customAction = (value) => {
      if (!Validity.isValidEmail(value)) {
        return Promise.reject(new Error(messageInvalid));
      }
      return true;
    },
  }) {
    return check(fields)
      .not()
      .isEmpty()
      .withMessage(messageRequired)
      .trim()
      .escape()
      .normalizeEmail()
      .custom(customAction);
  }

  static validateUserName({
    fields = 'userName',
    min = 6,
    messageRequired = 'User name is required',
    messageInvalid = `User name must be at least ${min} characters long`,
  }) {
    return check(fields)
      .not().isEmpty().trim().escape().withMessage(messageRequired)
      .isLength({ min: min }).withMessage(messageInvalid);
  }

  static validatePassword({
    fields = 'password',
    min = 8,
    messageRequired = 'Password is required',
    messageInvalid = `Password be at least ${min} characters long`,
  }) {
    return check(fields)
      .not().isEmpty().trim().escape().withMessage(messageRequired)
      .isLength({ min: min }).withMessage(messageInvalid);
  }

  static validateConfirmPassword({
    fields = 'passwordConfirm',
    min = 8,
    messageRequired = `Confirmation password is required and must be at least ${min} characters long`,
    messageInvalid = 'Passwords don\'t match',
    customAction = (value, { req }) => {
      if (value !== req.body.password) {
        return Promise.reject(new Error(messageInvalid));
      }

      return value;
    },
  }) {
    return check(fields)
      .not().isEmpty().trim().escape().withMessage(messageRequired)
      .isLength({ min: min }).withMessage(messageInvalid)
      .custom(customAction);
  }

  static validateToken({
    fields = 'token',
    min = 32,
    messageRequired = 'Token is required',
    messageInvalid = `Token be at least ${min} characters long`,
  }) {
    return check(fields)
      .not().isEmpty().trim().escape().withMessage(messageRequired)
      .isLength({ min: min }).withMessage(messageInvalid);
  }

  static validateRequiredField({
    fields = undefined,
    messageRequired = undefined,
  }) {
    return check(fields).not().isEmpty().trim().escape().withMessage(messageRequired);
  }

  static validateRequiredFieldWithCustomRule({
    fields = undefined,
    messageRequired = undefined,
    messageInvalid = undefined,
    customAction = undefined,
  }) {
    return check(fields).not().isEmpty().trim().escape().withMessage(messageRequired).custom(customAction);
  }

  static validateCheckBoxField({
    fields = undefined,
    valueExpected = undefined,
    throwIfNotExpected = true,
    errorMessage = undefined,
    customAction = (value, { req }) => {
      const isTrue = Converter.checkBoxToBoolean(value, valueExpected);
      if (!isTrue && throwIfNotExpected) {
        return Promise.reject(new Error(errorMessage));
      }
      return isTrue;
    },
  }) {
    return check(fields).custom(customAction);
  }

}


module.exports = FormFieldValidator;
