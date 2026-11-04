import { isApiCall } from './api-url';

describe('isApiCall', () => {
  it('accepts relative URLs under the API base', () => {
    expect(isApiCall('/api/v1/git-connections', '/api/v1')).toBeTrue();
    expect(isApiCall('/api/v1/git-connections?x=1', '/api/v1')).toBeTrue();
    expect(isApiCall('/api/v1', '/api/v1')).toBeTrue();
  });

  it('never sends the token elsewhere', () => {
    for (const url of ['https://evil.example/api/v1/x', '//evil.example/api/v1', '/api/v10/x', '/assets/config.json',
      'http://localhost/api/v1/x', '/api/v1/../../assets', '\\\\evil/api/v1']) {
      expect(isApiCall(url, '/api/v1')).toBeFalse();
    }
  });
});
