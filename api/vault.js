const { parseToken, getCookie } = require('./_lib/auth');

module.exports = (req, res) => {
  const token = getCookie(req, 'divine_token');
  const user = token && parseToken(token);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  return res.status(200).json({ flag: process.env.FLAG });
};
