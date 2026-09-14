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

// The answer to a request whose session was just ended under it - a freeze, a tripped decoy. The
// page treats any 401 as "go and sign in", which is exactly what is wanted.
const sessionEnded = () => new HttpError(401, 'Your session has ended. Please sign in again.');

// A route that reads the CrimGuard risk database, on a server started without one.
const riskDatabaseMissing = () => new HttpError(503, 'The risk database is not connected.');

module.exports = { HttpError, sessionEnded, riskDatabaseMissing };
