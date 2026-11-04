/**
 * Whether a request URL targets our own API: same-origin relative URLs under the API base path.
 * Absolute URLs (other origins) never receive the access token.
 */
export function isApiCall(url: string, apiBase: string): boolean {
  if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('//') || url.startsWith('\\')) {
    return false;
  }
  const path = url.split(/[?#]/)[0];
  if (path.split('/').includes('..')) {
    return false;
  }
  return path === apiBase || path.startsWith(apiBase + '/');
}
