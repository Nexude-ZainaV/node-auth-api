/** An error that carries the HTTP status the client should see. */
export class HttpError extends Error {
  /** @param {number} status @param {string} message @param {Record<string, string>} [details] */
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}
