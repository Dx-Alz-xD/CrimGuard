'use strict';

// A write that names an account by id can race that account being deleted. The foreign key
// refuses it, and there is nothing left to write to - not an error worth raising.
function ignoreDeletedAccount(write) {
  try {
    return write();
  } catch (err) {
    if (/FOREIGN KEY constraint failed/.test(err.message)) return undefined;
    throw err;
  }
}

module.exports = { ignoreDeletedAccount };
