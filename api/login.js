const { createToken } = require('./_lib/auth');
const USERS = require('./_lib/users.json');

module.exports = (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const match = Object.values(USERS).find(
    u => u.username === username.toLowerCase().trim() && u.password === password.trim()
  );
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = createToken(match);
  // HttpOnly intentionally OFF — the challenge wants the player able to read/edit this
  // cookie in DevTools to forge the alg:none token. That's the puzzle.
  res.setHeader('Set-Cookie', `divine_token=${token}; Path=/; SameSite=Lax`);
  return res.status(200).json({ success: true });
};
