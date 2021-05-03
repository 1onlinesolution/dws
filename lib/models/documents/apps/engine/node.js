const Validity = require('../../../../tools/validity');

//
// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class Node {
  constructor({ x = 0.0, y = 0.0, z = 0.0 } = {}) {
    this.x = x;
    this.y = y;
    this.z = z;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return Node.checkForError(this);
  }

  static checkForError(node) {
    if (!node || !(node instanceof Node)) return new Error('invalid node');
    if (!Validity.isValidNumber(node.x) || !Validity.isValidNumber(node.y) || !Validity.isValidNumber(node.z))
      return new Error('invalid node coordinates');
    return null;
  }
}

module.exports = Node;
