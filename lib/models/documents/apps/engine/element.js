const Validity = require('../../../../tools/validity');

//
// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class Element {
  constructor({ elementGroup, label, description = '', nodes = [] } = {}) {
    // 1-based index of element group
    this.elementGroup = elementGroup;
    this.label = label;
    this.description = description || '';

    // Array of integers; the 1-based index of the node in the project's node collection
    this.nodes = nodes;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return Element.checkForError(this);
  }

  static checkForError(element) {
    if (!element || !(element instanceof Element)) return new Error('invalid element details');
    if (!Validity.isValidString(element.label)) return new Error('invalid element label');
    if (!Validity.isValidNumber(element.elementGroup)) return new Error('invalid element group');
    const error = Element.checkNodes(element.nodes);
    if (error) return error;
    return null;
  }

  static checkNodes(nodes) {
    const errMessage = 'invalid element nodes';
    if (!nodes) return new Error(errMessage);
    nodes.forEach((item) => {
      if (!item || !(item instanceof Array)) return new Error(errMessage);
      item.forEach((indexOfNode) => {
        if (!indexOfNode || !(indexOfNode instanceof Number)) return new Error(errMessage);
      });
    });
    return null;
  }
}

module.exports = Element;
