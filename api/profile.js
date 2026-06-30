const { parseToken, getCookie } = require('./_lib/auth');
const USERS = require('./_lib/users.json');

module.exports = (req, res) => {
  const token = getCookie(req, 'divine_token');
  const user = token && parseToken(token);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });

  const target = USERS[req.query.hash];
  if (!target) return res.status(404).json({ error: 'Not found' });

  // No ownership check here on purpose — this IS the IDOR your design wants.
  return res.status(200).json({ username: target.username, role: target.role, hash: target.hash });
};
