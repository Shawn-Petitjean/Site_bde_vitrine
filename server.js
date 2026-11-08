import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5001;
const publicAppUrl = (process.env.PUBLIC_APP_URL || `http://localhost:${PORT}`).trim().replace(/\/+$/, '');

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ----------------------------------------------------
// JSON DATA STORE (Events & BDE Crew)
// ----------------------------------------------------
const DATA_FILE = path.join(__dirname, 'data', 'store.json');
const CLICK_LOG_FILE = path.join(__dirname, 'data', 'event_clicks.log');
const IDEAS_LOG_FILE = path.join(__dirname, 'data', 'ideas.log');

function readStore() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    return {
      events: Array.isArray(parsed.events) ? parsed.events : [],
      crew: Array.isArray(parsed.crew) ? parsed.crew : [],
      eventLogs: Array.isArray(parsed.eventLogs) ? parsed.eventLogs : [],
      ideas: Array.isArray(parsed.ideas) ? parsed.ideas : [],
    };
  } catch (err) {
    console.error('Failed to read store.json:', err.message);
    return { events: [], crew: [], eventLogs: [], ideas: [] };
  }
}

function writeStore(store) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(store, null, 2), 'utf-8');
}

function appendClickLogFile(entry) {
  try {
    fs.mkdirSync(path.dirname(CLICK_LOG_FILE), { recursive: true });
    const line = `[${entry.clickedAt}] login=${entry.login} (${entry.displayName}) -> event="${entry.eventTitle}" (${entry.eventId})\n`;
    fs.appendFileSync(CLICK_LOG_FILE, line, 'utf-8');
  } catch (err) {
    console.error('Failed to write event_clicks.log:', err.message);
  }
}

function appendIdeaLogFile(idea) {
  try {
    fs.mkdirSync(path.dirname(IDEAS_LOG_FILE), { recursive: true });
    const line = `[${idea.createdAt}] login=${idea.authorLogin} (${idea.authorName}) [${idea.category}] "${idea.title}" — ${idea.description}\n`;
    fs.appendFileSync(IDEAS_LOG_FILE, line, 'utf-8');
  } catch (err) {
    console.error('Failed to write ideas.log:', err.message);
  }
}

// ----------------------------------------------------
// BDE ADMIN CHECK (Env ADMIN_LOGINS + BDE Crew logins)
// ----------------------------------------------------
function getEnvAdminLogins() {
  return (process.env.ADMIN_LOGINS || '')
    .split(',')
    .map(l => l.trim().toLowerCase())
    .filter(Boolean);
}

function isBdeAdminLogin(login) {
  if (!login) return false;
  const normalized = login.trim().toLowerCase();
  if (getEnvAdminLogins().includes(normalized)) {
    return true;
  }
  const store = readStore();
  return store.crew.some(member => (member.login || '').trim().toLowerCase() === normalized);
}

// ----------------------------------------------------
// SESSIONS & OAUTH STATE
// ----------------------------------------------------
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const sessions = new Map(); // token -> { user, expiresAt }

function createSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, { user, expiresAt: Date.now() + SESSION_TTL_MS });
  return token;
}

function getUserFromReq(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!token) return null;
  const entry = sessions.get(token);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  entry.expiresAt = Date.now() + SESSION_TTL_MS;
  // Re-evaluate isAdmin dynamically against current BDE Crew + ADMIN_LOGINS
  const isAdmin = isBdeAdminLogin(entry.user.login);
  return { ...entry.user, isAdmin };
}

function requireAuth(req, res, next) {
  const user = getUserFromReq(req);
  if (!user) return res.status(401).json({ error: 'Non authentifié' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getUserFromReq(req);
  if (!user) return res.status(401).json({ error: 'Non authentifié' });
  if (!user.isAdmin) {
    return res.status(403).json({ error: 'Accès refusé : votre login 42 ne fait pas partie du BDE.' });
  }
  req.user = user;
  next();
}

const oauthStates = new Map();
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

function issueOauthState() {
  const state = crypto.randomBytes(16).toString('base64url');
  oauthStates.set(state, Date.now() + OAUTH_STATE_TTL_MS);
  return state;
}

function consumeOauthState(state) {
  const exp = oauthStates.get(state);
  if (!exp) return false;
  oauthStates.delete(state);
  return exp >= Date.now();
}

function getPublicAppUrl() {
  const port = process.env.PORT || PORT;
  return (process.env.PUBLIC_APP_URL || `http://localhost:${port}`).trim().replace(/\/+$/, '');
}

function getRedirectUri() {
  if (process.env.INTRA42_REDIRECT_URI && process.env.INTRA42_REDIRECT_URI.trim()) {
    return process.env.INTRA42_REDIRECT_URI.trim();
  }
  return `${getPublicAppUrl()}/api/auth/42/callback`;
}

// ----------------------------------------------------
// 42 OAUTH2 ROUTES
// ----------------------------------------------------
app.get('/api/auth/42/url', (req, res) => {
  dotenv.config({ override: true });
  const clientId = (process.env.INTRA42_CLIENT_ID || '').trim();
  if (!clientId) {
    return res.status(503).json({ error: 'INTRA42_CLIENT_ID manquant dans .env' });
  }
  const state = issueOauthState();
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: getRedirectUri(),
    response_type: 'code',
    scope: 'public',
    state,
  });
  res.json({ url: `https://api.intra.42.fr/oauth/authorize?${params.toString()}` });
});

app.get('/api/auth/42/callback', async (req, res) => {
  dotenv.config({ override: true });
  const { code, state } = req.query;
  try {
    if (!consumeOauthState(state)) {
      return res.redirect(`${publicAppUrl}/?auth_error=${encodeURIComponent('Session OAuth expirée ou invalide. Réessayez.')}`);
    }
    if (!code) {
      return res.redirect(`${publicAppUrl}/?auth_error=${encodeURIComponent('Code OAuth 42 manquant.')}`);
    }

    const clientId = (process.env.INTRA42_CLIENT_ID || '').trim();
    const clientSecret = (process.env.INTRA42_CLIENT_SECRET || '').trim();
    const redirectUri = getRedirectUri();

    if (!clientId || !clientSecret) {
      throw new Error('Identifiants INTRA42_CLIENT_ID / INTRA42_CLIENT_SECRET manquants dans .env');
    }

    // 1. Exchange authorization code for access token
    const tokenRes = await fetch('https://api.intra.42.fr/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        client_secret: clientSecret,
        code: String(code),
        redirect_uri: redirectUri,
      }),
    });

    if (!tokenRes.ok) {
      const errText = await tokenRes.text();
      if (tokenRes.status === 401 && errText.includes('invalid_client')) {
        throw new Error(
          'Secret 42 expiré ou invalide (invalid_client). Mettez à jour INTRA42_CLIENT_SECRET dans le fichier .env depuis https://profile.intra.42.fr/oauth/applications'
        );
      }
      throw new Error(`Échec de l'échange du token 42 (${tokenRes.status}): ${errText}`);
    }

    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    // 2. Fetch user profile from 42 Intra API
    const meRes = await fetch('https://api.intra.42.fr/v2/me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!meRes.ok) {
      throw new Error(`Impossible de récupérer le profil 42 (${meRes.status})`);
    }

    const intraUser = await meRes.json();
    const login = (intraUser.login || '').toLowerCase();

    const user = {
      id: intraUser.id,
      login: intraUser.login,
      displayName: intraUser.usual_full_name || intraUser.displayname || intraUser.login,
      email: intraUser.email,
      avatarUrl: intraUser.image?.link || intraUser.image?.versions?.medium || '',
      campus: intraUser.campus?.[0]?.name || '42 Perpignan',
      isAdmin: isBdeAdminLogin(login),
    };

    const sessionToken = createSession(user);
    res.redirect(`${publicAppUrl}/?token=${encodeURIComponent(sessionToken)}`);
  } catch (err) {
    console.error('42 OAuth Callback Error:', err.message);
    res.redirect(`${publicAppUrl}/?auth_error=${encodeURIComponent(err.message)}`);
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

// ----------------------------------------------------
// PUBLIC DATA ENDPOINT
// ----------------------------------------------------
app.get('/api/data', (req, res) => {
  const store = readStore();
  res.json(store);
});

// ----------------------------------------------------
// ADMIN CRUD: EVENTS
// ----------------------------------------------------
app.post('/api/events', requireAdmin, (req, res) => {
  const {
    day,
    month,
    category = 'tech',
    badge1 = 'TECH / DEV',
    badge2 = '',
    title,
    description,
    location = 'Campus 42',
    time = '20:00',
    price = 'Gratuit',
    slots = 'Illimité',
    ctaText = 'RÉSERVER MA PLACE →',
    theme = 'yellow',
  } = req.body || {};

  if (!title || !day || !month) {
    return res.status(400).json({ error: 'Titre, jour et mois sont requis.' });
  }

  const store = readStore();
  const newEvent = {
    id: `evt-${Date.now()}`,
    day: String(day).trim(),
    month: String(month).trim().toUpperCase(),
    category: ['tech', 'party', 'gaming'].includes(category) ? category : 'tech',
    badge1: String(badge1 || '').trim().toUpperCase(),
    badge2: String(badge2 || '').trim().toUpperCase(),
    title: String(title).trim(),
    description: String(description || '').trim(),
    location: String(location || '').trim(),
    time: String(time || '').trim(),
    price: String(price || '').trim(),
    slots: String(slots || '').trim(),
    ctaText: String(ctaText || 'RÉSERVER MA PLACE →').trim(),
    theme: ['yellow', 'cream', 'purple', 'red', 'black'].includes(theme) ? theme : 'yellow',
  };

  store.events.push(newEvent);
  writeStore(store);
  res.status(201).json({ event: newEvent, events: store.events });
});

app.put('/api/events/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const store = readStore();
  const idx = store.events.findIndex(e => e.id === id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Événement introuvable.' });
  }

  const current = store.events[idx];
  const body = req.body || {};
  const updated = {
    ...current,
    day: body.day !== undefined ? String(body.day).trim() : current.day,
    month: body.month !== undefined ? String(body.month).trim().toUpperCase() : current.month,
    category: ['tech', 'party', 'gaming'].includes(body.category) ? body.category : current.category,
    badge1: body.badge1 !== undefined ? String(body.badge1).trim().toUpperCase() : current.badge1,
    badge2: body.badge2 !== undefined ? String(body.badge2).trim().toUpperCase() : current.badge2,
    title: body.title !== undefined ? String(body.title).trim() : current.title,
    description: body.description !== undefined ? String(body.description).trim() : current.description,
    location: body.location !== undefined ? String(body.location).trim() : current.location,
    time: body.time !== undefined ? String(body.time).trim() : current.time,
    price: body.price !== undefined ? String(body.price).trim() : current.price,
    slots: body.slots !== undefined ? String(body.slots).trim() : current.slots,
    ctaText: body.ctaText !== undefined ? String(body.ctaText).trim() : current.ctaText,
    theme: ['yellow', 'cream', 'purple', 'red', 'black'].includes(body.theme) ? body.theme : current.theme,
  };

  store.events[idx] = updated;
  writeStore(store);
  res.json({ event: updated, events: store.events });
});

app.delete('/api/events/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const store = readStore();
  const nextEvents = store.events.filter(e => e.id !== id);
  if (nextEvents.length === store.events.length) {
    return res.status(404).json({ error: 'Événement introuvable.' });
  }
  store.events = nextEvents;
  writeStore(store);
  res.json({ events: store.events });
});

// ----------------------------------------------------
// EVENT BUTTON CLICK LOGGING & REGISTRATIONS (42 Auth Required)
// ----------------------------------------------------
app.post('/api/events/:id/click', requireAuth, (req, res) => {
  const { id } = req.params;
  const user = req.user;
  const store = readStore();
  const evt = store.events.find(e => e.id === id);

  if (!evt) {
    return res.status(404).json({ error: 'Événement introuvable.' });
  }

  if (!Array.isArray(evt.registrations)) {
    evt.registrations = [];
  }

  const login = user.login;
  const alreadyRegistered = evt.registrations.some(
    r => (r.login || '').toLowerCase() === login.toLowerCase()
  );
  if (alreadyRegistered) {
    return res.status(409).json({ error: 'Vous êtes déjà inscrit à cet événement.' });
  }

  const clickedAt = new Date().toISOString();
  const displayName = user.displayName || user.login;
  const avatarUrl = user.avatarUrl || '';

  const logEntry = {
    id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    eventId: evt.id,
    eventTitle: evt.title,
    login,
    displayName,
    avatarUrl,
    clickedAt,
  };

  store.eventLogs.unshift(logEntry);
  evt.registrations.push({
    login,
    displayName,
    avatarUrl,
    clickedAt,
  });

  writeStore(store);
  appendClickLogFile(logEntry);

  res.status(201).json({
    logEntry,
    event: evt,
    events: store.events,
    eventLogs: store.eventLogs,
  });
});

app.get('/api/events/logs', requireAdmin, (req, res) => {
  const store = readStore();
  res.json({ eventLogs: store.eventLogs });
});

app.delete('/api/events/:id/registrations/:login', requireAdmin, (req, res) => {
  const { id, login } = req.params;
  const targetLogin = (login || '').trim().toLowerCase();
  const store = readStore();
  const evt = store.events.find(e => e.id === id);

  if (!evt) {
    return res.status(404).json({ error: 'Événement introuvable.' });
  }

  if (Array.isArray(evt.registrations)) {
    evt.registrations = evt.registrations.filter(
      r => (r.login || '').toLowerCase() !== targetLogin
    );
  }

  store.eventLogs = store.eventLogs.filter(
    l => !(l.eventId === id && (l.login || '').toLowerCase() === targetLogin)
  );

  writeStore(store);
  res.json({
    event: evt,
    events: store.events,
    eventLogs: store.eventLogs,
  });
});

// ----------------------------------------------------
// ADMIN CRUD: BDE CREW MEMBERS
// ----------------------------------------------------
app.post('/api/crew', requireAdmin, (req, res) => {
  const {
    login = '',
    name,
    role = 'MEMBRE BDE // LVL.80',
    quote = '',
    stack = '',
    avatarUrl = '',
    avatarType = 'bot',
    theme = 'purple',
  } = req.body || {};

  if (!name || !role) {
    return res.status(400).json({ error: 'Nom et rôle sont requis.' });
  }

  const store = readStore();
  const newMember = {
    id: `crew-${Date.now()}`,
    login: String(login || '').trim().toLowerCase(),
    name: String(name).trim(),
    role: String(role).trim().toUpperCase(),
    quote: String(quote || '').trim(),
    stack: String(stack || '').trim(),
    avatarUrl: String(avatarUrl || '').trim(),
    avatarType: ['bot', 'vault', 'dj', 'hex'].includes(avatarType) ? avatarType : 'bot',
    theme: ['purple', 'red', 'yellow', 'black'].includes(theme) ? theme : 'purple',
  };

  store.crew.push(newMember);
  writeStore(store);
  res.status(201).json({ member: newMember, crew: store.crew });
});

app.put('/api/crew/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const store = readStore();
  const idx = store.crew.findIndex(m => m.id === id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Membre introuvable.' });
  }

  const current = store.crew[idx];
  const body = req.body || {};
  const updated = {
    ...current,
    login: body.login !== undefined ? String(body.login).trim().toLowerCase() : current.login,
    name: body.name !== undefined ? String(body.name).trim() : current.name,
    role: body.role !== undefined ? String(body.role).trim().toUpperCase() : current.role,
    quote: body.quote !== undefined ? String(body.quote).trim() : current.quote,
    stack: body.stack !== undefined ? String(body.stack).trim() : current.stack,
    avatarUrl: body.avatarUrl !== undefined ? String(body.avatarUrl).trim() : current.avatarUrl,
    avatarType: ['bot', 'vault', 'dj', 'hex'].includes(body.avatarType) ? body.avatarType : current.avatarType,
    theme: ['purple', 'red', 'yellow', 'black'].includes(body.theme) ? body.theme : current.theme,
  };

  store.crew[idx] = updated;
  writeStore(store);
  res.json({ member: updated, crew: store.crew });
});

app.delete('/api/crew/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const store = readStore();
  const nextCrew = store.crew.filter(m => m.id !== id);
  if (nextCrew.length === store.crew.length) {
    return res.status(404).json({ error: 'Membre introuvable.' });
  }
  store.crew = nextCrew;
  writeStore(store);
  res.json({ crew: store.crew });
});

// ----------------------------------------------------
// BOÎTE À IDÉES & PULL REQUESTS ÉTUDIANTES
// ----------------------------------------------------
app.post('/api/ideas', requireAuth, (req, res) => {
  const { title, category = 'CAMPUS', description } = req.body || {};
  if (!title || !description) {
    return res.status(400).json({ error: 'Le titre et la description sont requis.' });
  }

  const user = req.user;
  const store = readStore();
  const themes = ['cream', 'red', 'black'];
  const nextTheme = themes[store.ideas.length % themes.length];

  const newIdea = {
    id: `idea-${Date.now()}`,
    title: String(title).trim(),
    category: String(category || 'CAMPUS').trim().toUpperCase(),
    description: String(description).trim(),
    votes: 1,
    voters: [user.login.toLowerCase()],
    authorLogin: user.login,
    authorName: user.displayName || user.login,
    createdAt: new Date().toISOString(),
    theme: nextTheme,
  };

  store.ideas.unshift(newIdea);
  writeStore(store);
  appendIdeaLogFile(newIdea);

  res.status(201).json({ idea: newIdea, ideas: store.ideas });
});

app.post('/api/ideas/:id/vote', requireAuth, (req, res) => {
  const { id } = req.params;
  const login = (req.user.login || '').toLowerCase();
  const store = readStore();
  const idea = store.ideas.find(i => i.id === id);

  if (!idea) {
    return res.status(404).json({ error: 'Idée introuvable.' });
  }

  if (!Array.isArray(idea.voters)) {
    idea.voters = [];
  }

  if (idea.voters.includes(login)) {
    return res.status(409).json({ error: 'Vous avez déjà voté pour cette proposition.' });
  }

  idea.voters.push(login);
  idea.votes = (Number(idea.votes) || 0) + 1;
  store.ideas.sort((a, b) => (b.votes || 0) - (a.votes || 0));

  writeStore(store);
  res.json({ idea, ideas: store.ideas });
});

app.delete('/api/ideas/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const store = readStore();
  const nextIdeas = store.ideas.filter(i => i.id !== id);
  if (nextIdeas.length === store.ideas.length) {
    return res.status(404).json({ error: 'Idée introuvable.' });
  }
  store.ideas = nextIdeas;
  writeStore(store);
  res.json({ ideas: store.ideas });
});

// ----------------------------------------------------
// STATIC FILES & FRONTEND ENTRY
// ----------------------------------------------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'maquette_bde.html'));
});

app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`🚀 BDE ROOT_OVERFLOW Server running at ${publicAppUrl}`);
  console.log(`🔑 42 OAuth Redirect URI: ${getRedirectUri()}`);
});
