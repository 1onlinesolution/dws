const Node = require('./engine/node');
const Element = require('./engine/element');
const ElementGroup = require('./engine/elementGroup');

//
// IMPORTANT!!!
//
// This is THE DOCUMENT that will be saved in MongoDB
//
class ProjectData {
  constructor({ elementGroups = [], elements = [], nodes = [] } = {}) {
    this.nodes = nodes;
    this.elementGroups = elementGroups;
    this.elements = elements;

    const error = this.checkForError();
    if (error) throw error;

    return this;
  }

  static get [Symbol.species]() {
    return this;
  }

  checkForError() {
    return ProjectData.checkForError(this);
  }

  static checkForError(projectData) {
    if (!projectData || !(projectData instanceof ProjectData)) return new Error('invalid project data');

    let error = checkElementGroups(projectData.elementGroups);
    if (!error) error = checkElements(projectData.elements);
    if (!error) error = checkNodes(projectData.nodes);
    return error;
  }

}

module.exports = ProjectData;

function checkElementGroups(elementGroups) {
  let errMessage = 'invalid project data element groups';
  if (!elementGroups) return new Error(errMessage);
  elementGroups.forEach((item) => {
    const error = ElementGroup.checkForError(item);
    if (error) return error;
  });
  return null;
}

function checkElements(elements) {
  let errMessage = 'invalid project data elements';
  if (!elements) return new Error(errMessage);
  elements.forEach((item) => {
    const error = Element.checkForError(item);
    if (error) return error;
  });
  return null;
}

function checkNodes(nodes) {
  let errMessage = 'invalid project data nodes';
  if (!nodes) return new Error(errMessage);
  nodes.forEach((item) => {
    const error = Node.checkForError(item);
    if (error) return error;
  });
  return null;
}