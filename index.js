const express   = require('express');
const path      = require('path');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { Pool }  = require('pg');

const app        = express();
const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_en_prod';

// ── Base de données PostgreSQL ──────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id               SERIAL PRIMARY KEY,
      username         TEXT UNIQUE NOT NULL,
      password         TEXT NOT NULL,
      ecoledirecte_id  TEXT UNIQUE NOT NULL,
      created_at       TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  console.log('Base de données prête.');
}
initDB().catch(err => {
  console.error('Erreur connexion DB :', err.message);
  process.exit(1);
});

// ── Middlewares ─────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Routes API ──────────────────────────────────────────────────────────────

app.get('/api/check-username/:username', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id FROM users WHERE username = $1',
    [req.params.username]
  );
  res.json({ available: rows.length === 0 });
});

app.post('/api/register', async (req, res) => {
  const { username, password, edLogin, edPassword } = req.body;

  if (!username || username.trim().length < 3)
    return res.status(400).json({ error: 'Le pseudo doit faire au moins 3 caractères.' });

  if (!/^[a-zA-Z0-9_.\-]+$/.test(username))
    return res.status(400).json({ error: 'Le pseudo ne peut contenir que des lettres, chiffres, _ . -' });

  if (!password || password.length < 5)
    return res.status(400).json({ error: 'Le mot de passe doit faire au moins 5 caractères.' });

  const { rows: existing } = await pool.query(
    'SELECT id FROM users WHERE username = $1',
    [username.trim()]
  );
  if (existing.length > 0)
    return res.status(400).json({ error: 'Ce pseudo est déjà pris.' });

  try {
    const body = new URLSearchParams();
    body.append('data', JSON.stringify({
      identifiant: edLogin,
      motdepasse: edPassword,
      isRelogin: false,
      uuid: '',
    }));

    // log temporaire pour vérifier l'identifiant reçu
    console.log('Tentative EcoleDirecte pour :', edLogin);

    const edResponse = await fetch('https://api.ecoledirecte.com/v3/login.awp?v=4', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'ecoledirecte/4 CFNetwork/1492.0.1 Darwin/23.3.0',
        'X-Token': '',
      },
      body: body.toString(),
    });

    const edData = await edResponse.json();
    console.log('Réponse EcoleDirecte :', JSON.stringify(edData, null, 2));

    if (edData.code !== 200)
      return res.status(401).json({ error: 'Identifiants EcoleDirecte incorrects.' });

    const account = edData.data?.accounts?.[0];
    const edId    = String(account?.id);

    if (!edId || edId === 'undefined')
      return res.status(401).json({ error: "Impossible de récupérer l'ID EcoleDirecte." });

    const { rows: existingEd } = await pool.query(
      'SELECT id FROM users WHERE ecoledirecte_id = $1',
      [edId]
    );
    if (existingEd.length > 0)
      return res.status(400).json({ error: 'Ce compte EcoleDirecte est déjà associé à un compte.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password, ecoledirecte_id) VALUES ($1, $2, $3)',
      [username.trim(), hashedPassword, edId]
    );

    const token = jwt.sign({ username: username.trim() }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, username: username.trim() });

  } catch (err) {
    console.error('Erreur EcoleDirecte :', err);
    res.status(500).json({ error: 'Erreur lors de la vérification EcoleDirecte. Réessaie.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const { rows } = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [username?.trim()]
  );
  const user = rows[0];

  if (!user)
    return res.status(401).json({ error: 'Pseudo ou mot de passe incorrect.' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid)
    return res.status(401).json({ error: 'Pseudo ou mot de passe incorrect.' });

  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, username: user.username });
});

app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));