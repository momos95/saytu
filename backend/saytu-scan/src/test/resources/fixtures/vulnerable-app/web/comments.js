// Deliberately vulnerable code used by SAYTU's scanner tests.
function showComment(el, comment) {
  el.innerHTML = comment;
}

module.exports = { showComment };
