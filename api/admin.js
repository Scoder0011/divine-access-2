const { parseToken, getCookie } = require('./_lib/auth');

module.exports = (req, res) => {
  const token = getCookie(req, 'divine_token');
  const user = token && parseToken(token);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  if (user.role !== 'admin') return res.status(403).json({ denied: true });

  return res.status(200).json({ vaultPath: '/sys/core/admin/x7k2/secret/realm/vault' });
};
