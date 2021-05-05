const { validationResult } = require('express-validator');

class BaseValidator {
  constructor({ fields = [] } = {}) {
    this.fields = fields;
    return this;
  }

  static validateFormInput(req) {
    return validationResult(req);
  };

  static formInputContainsErrors(req) {
    const errors = BaseValidator.validateFormInput(req);
    return errors.isEmpty();
  };

  static validateFormInputWithFlash(req, data = null) {
    const errors = BaseValidator.validateFormInput(req);
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
}

module.exports = BaseValidator;