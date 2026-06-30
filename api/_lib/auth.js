function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}
function b64urlEncode(str) {
  return Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function createToken(user) {
  const header = b64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64urlEncode(JSON.stringify({
    id: user.id, username: user.username, role: user.role, hash: user.hash,
    iat: Math.floor(Date.now() / 1000)
  }));
  const sig = b64urlEncode('divinehmac_' + user.id); // weak on purpose, unchanged from your design
  return `${header}.${payload}.${sig}`;
}

function parseToken(token) {
  try {
    const [h, p, s] = token.split('.');
    if (!h || !p) return null;
    const header = JSON.parse(b64urlDecode(h));
    const payload = JSON.parse(b64urlDecode(p));
    if (header.alg === 'none' && s === '') return payload;   // <- the intended bypass, now real
    if (header.alg === 'HS256') return payload;               // no real sig check, same as before
    return null;
  } catch { return null; }
}

function getCookie(req, name) {
  const cookie = req.headers.cookie || '';
  const m = cookie.split(';').map(c => c.trim()).find(c => c.startsWith(name + '='));
  return m ? decodeURIComponent(m.split('=')[1]) : null;
}

module.exports = { createToken, parseToken, getCookie };
