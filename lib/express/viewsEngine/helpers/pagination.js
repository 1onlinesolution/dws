module.exports.register = function (handlebars) {
  handlebars.registerHelper('pagination', function (baseRoute, currentPage, pageCount, size, options) {
    let startPage, endPage, context;

    if (arguments.length === 4) {
      options = size;
      size = 5;
    }

    startPage = currentPage - Math.floor(size / 2);
    endPage = currentPage + Math.floor(size / 2);

    if (startPage <= 0) {
      endPage -= startPage - 1;
      startPage = 1;
    }

    if (endPage > pageCount) {
      endPage = pageCount;
      if (endPage - size + 1 > 0) {
        startPage = endPage - size + 1;
      } else {
        startPage = 1;
      }
    }

    context = {
      baseRoute: baseRoute,
      currentPage: currentPage,
      pageCount: pageCount,
      size: size,
      startFromFirstPage: false,
      pages: [],
      endAtLastPage: false,
    };
    if (startPage === 1) {
      context.startFromFirstPage = true;
    }
    for (let i = startPage; i <= endPage; i++) {
      context.pages.push({
        page: i,
        isCurrent: i === currentPage,
      });
    }
    if (endPage === pageCount) {
      context.endAtLastPage = true;
    }

    return options.fn(context);
  });
};
