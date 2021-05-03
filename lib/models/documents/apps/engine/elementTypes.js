const ElementTypes = {
  undefined: 0,
  min: 1,
  generic: 1, // Generic element group.
  stiff: 2, // The group contains stiffness elements.
  truss: 3, // The group contains truss elements.
  beam: 4, // The group contains beam elements.
  torsion: 5, // The group contains two-dimensional elements for cross-sectional analysis.
  solid2d: 6, // The group contains two-dimensional solid elements.
  solid3d: 7, // The group contains three-dimensional solid elements.
  plate: 8, // The group contains plate elements.
  shell: 9, // The group contains shell elements.
  max: 9,
};

module.exports = ElementTypes;
