module.exports.register = function (handlebars) {
  handlebars.registerHelper('code', function(options) {

    const className = options.hash.lang || '';

    // Input html
    let input = options.fn(this);

    // Escape html to string
    input = handlebars.Utils.escapeExpression(input);

    // Break by lines
    let lines = input.split('\n');

    // Get number of tabs before first line
    const numTabs = getNumFrontTabs(lines[0]);

    // Remove tabs before 
    lines = lines.map(function(line) {
      return line.substring(numTabs);
    });

    // Rejoin the lines
    return '<pre><code class=\'' + className + '\'>' + lines.join('\n') + '</code></pre>';
  });
};


function getNumFrontTabs(line) {
  let count = 0;
  let index = 0;
  while (line.charAt(index++) === '\t') {
    count++;
  }
  return count;
}