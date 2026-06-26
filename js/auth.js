// JWT utility — intentionally vulnerable (alg:none accepted)

function b64url_encode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64url_decode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

function createToken(user) {
  const header  = b64url_encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url_encode(JSON.stringify({
    id:       user.id,
    username: user.username,
    role:     user.role,
    hash:     user.hash,
    iat:      Math.floor(Date.now() / 1000)
  }));
  // weak static secret — signature is not actually verified server-side (no server)
  const sig = b64url_encode('divinehmac_' + user.id);
  return `${header}.${payload}.${sig}`;
}

function parseToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const header  = JSON.parse(b64url_decode(parts[0]));
    const payload = JSON.parse(b64url_decode(parts[1]));
    // VULNERABLE: accepts alg:none with empty signature
    if (header.alg === 'none' && parts[2] === '') {
      return payload;
    }
    // also accept HS256 tokens (legit login)
    if (header.alg === 'HS256') {
      return payload;
    }
    return null;
  } catch (e) {
    return null;
  }
}

function getToken() {
  return localStorage.getItem('divine_token');
}

function getUser() {
  const token = getToken();
  if (!token) return null;
  return parseToken(token);
}

function requireAuth(redirectTo = '/') {
  const user = getUser();
  if (!user) { window.location.href = redirectTo; return null; }
  return user;
}

function requireAdmin(redirectTo = '/') {
  const user = requireAuth(redirectTo);
  if (!user) return null;
  if (user.role !== 'admin') { window.location.href = redirectTo; return null; }
  return user;
}

function logout() {
  localStorage.removeItem('divine_token');
  window.location.href = '/';
}
