const ProjectStatus = require('../projectStatus');
const { Validity, DateTimeUtils } = require('@1onlinesolution/dws-utils');

class CreateProjectParameters {
  constructor({ user_id,
    application,
    label,
    description = '',
    status = ProjectStatus.created,
    completionEstimate = 10,
    _id = null, // the ObjectID
    users = [],
    created_at = undefined,
    modified_at = undefined,
  } = {}) {

    this._id = _id;
    this.user_id = user_id;
    this.application = application;
    this.label = label;
    this.description = description;
    this.status = status;
    this.completionEstimate = completionEstimate;
    this.users = users;

    const nowUtc = DateTimeUtils.currentUtcDate();
    this.created_at = created_at || nowUtc;
    this.modified_at = modified_at || nowUtc;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  checkForError() {
    return CreateProjectParameters.checkForError(this);
  }

  static checkForError(createProjectParameters) {
    if (!createProjectParameters || !(createProjectParameters instanceof CreateProjectParameters)) {
      return new Error('invalid project details');
    }

    if (!Validity.isValidString(createProjectParameters.user_id)) return new Error('invalid user identifier');
    if (!Validity.isValidString(createProjectParameters.application)) return new Error('invalid application');
    if (!Validity.isValidString(createProjectParameters.label)) return new Error('invalid label');
    return null;
  }
}

module.exports = CreateProjectParameters;