const { parseToken, getCookie } = require('./_lib/auth');

module.exports = (req, res) => {
  const token = getCookie(req, 'divine_token');
  const user = token && parseToken(token);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  return res.status(200).json({ username: user.username, role: user.role, hash: user.hash });
};
