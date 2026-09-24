export type ProblemDetails = {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  instance?: string;
  [extension: string]: unknown;
};

export class ApiError extends Error {
  readonly status: number;
  readonly problem: ProblemDetails;
  /** Seconds to wait before retrying, parsed from a 503's Retry-After header. */
  readonly retryAfter?: number;

  constructor(status: number, problem: ProblemDetails, retryAfter?: number) {
    super(problem.detail ?? problem.title ?? `Request failed with status ${status}.`);
    this.name = 'ApiError';
    this.status = status;
    this.problem = problem;
    this.retryAfter = retryAfter;
  }

  static from(status: number, body: unknown, retryAfter?: number): ApiError {
    if (body && typeof body === 'object') return new ApiError(status, body as ProblemDetails, retryAfter);
    return new ApiError(status, { title: typeof body === 'string' && body ? body : undefined, status }, retryAfter);
  }
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    return e.retryAfter !== undefined ? `${e.message} Retry in ${e.retryAfter}s.` : e.message;
  }
  if (e instanceof Error && e.message) return e.message;
  return 'Request failed. Check the server log for details.';
}
