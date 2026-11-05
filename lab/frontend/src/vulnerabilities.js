"use strict";

/**
 * CWE-79: intentionally unsafe educational DOM sink.
 * No DOM operations occur until explicitly called; never use in production.
 */
function vulnerable_inner_html(element, userInput) {
  element.innerHTML = userInput;
}

module.exports = { vulnerable_inner_html };
