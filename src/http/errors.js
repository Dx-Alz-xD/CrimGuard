'use strict';

// An error whose message is safe to show the person who made the request.
// Anything else that's thrown becomes a generic 500 and is only logged on the server.
class HttpError extends Error {
  constructor(status, message, { code, headers } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

module.exports = { HttpError };
