// Matches a Blob from any realm. With msw 3 the real (undici) fetch runs, so
// response.blob() returns Node's Blob, not jsdom's global Blob, and
// expect.any(Blob) no longer matches. Both realms tag theirs "[object Blob]".
export const anyBlob = () => ({
  asymmetricMatch: (actual: unknown) => Object.prototype.toString.call(actual) === '[object Blob]',
  toString: () => 'AnyBlob',
  toAsymmetricMatcher: () => 'AnyBlob',
});
