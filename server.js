require('dotenv').config();
const express   = require('express');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const {
  S3Client,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  GetObjectCommand,
  ListObjectsV2Command,
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const crypto = require('crypto');
const path   = require('path');

const app = express();
const cspDefaults = helmet.contentSecurityPolicy.getDefaultDirectives();
delete cspDefaults['upgrade-insecure-requests'];

const s3Host = `https://${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com`;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...cspDefaults,
      'script-src':      ["'self'", "'unsafe-inline'"],
      'script-src-attr': ["'unsafe-inline'"],
      'img-src':         ["'self'", 'data:', 'https://dstec.com.br'],
      'connect-src':     ["'self'", s3Host],
    },
  },
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Aguarde 15 minutos.' },
});

const s3 = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
  requestChecksumRequired: false,
});

// SDK 3.600+: remove CRC32 headers injected during build phase so they don't
// end up signed into presigned URLs (browsers can't send the matching header).
s3.middlewareStack.add(
  (next) => async (args) => {
    delete args.request.headers['x-amz-checksum-crc32'];
    delete args.request.headers['x-amz-checksum-crc64nvme'];
    delete args.request.headers['x-amz-sdk-checksum-algorithm'];
    delete args.request.headers['x-amz-checksum-mode'];
    return next(args);
  },
  { step: 'build', name: 'stripChecksumForPresign', priority: 'low' }
);

const BUCKET         = process.env.S3_BUCKET;
const PREFIX         = process.env.S3_PREFIX || 'uploads/';
const PASSWORD       = process.env.UPLOAD_PASSWORD;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const PORT           = process.env.PORT || 3000;
const SESSION_TTL    = 24 * 60 * 60 * 1000;

// sessions: token → { expiry, name }
const sessions      = new Map();
const adminSessions = new Map();

// upload tracking
const uploadStore   = new Map();  // uploadId → info (active)
const recentUploads = [];         // completed / aborted (max 200)
const sseClients    = new Set();  // admin SSE responses

// hourly cleanup
setInterval(() => {
  const now = Date.now();
  for (const [t, s] of sessions)      if (now > s.expiry) sessions.delete(t);
  for (const [t, e] of adminSessions) if (now > e)        adminSessions.delete(t);
  // stale uploads (no activity for 4h)
  const stale = now - 4 * 60 * 60 * 1000;
  for (const [id, info] of uploadStore) {
    if ((info.lastActivity || info.startedAt) < stale) {
      info.status      = 'aborted';
      info.error       = 'Timeout – upload abandonado';
      info.completedAt = now;
      uploadStore.delete(id);
      pushRecent(info);
      broadcast('upload_aborted', info);
    }
  }
}, 60 * 60 * 1000);

// ── Helpers ───────────────────────────────────────────────────────────────────

function safeCompare(a, b) {
  const sa = String(a);
  const sb = String(b);
  if (sa.length !== sb.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sa), Buffer.from(sb));
}

function pushRecent(info) {
  recentUploads.push(info);
  if (recentUploads.length > 200) recentUploads.shift();
}

function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(msg); } catch (_) { sseClients.delete(res); }
  }
}

// ── Collaborator Auth ─────────────────────────────────────────────────────────

app.post('/auth', authLimiter, (req, res) => {
  if (!PASSWORD) return res.status(500).json({ error: 'UPLOAD_PASSWORD não configurado' });
  const { password, name } = req.body;
  if (!password || !safeCompare(password, PASSWORD))
    return res.status(401).json({ error: 'Senha incorreta' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    expiry: Date.now() + SESSION_TTL,
    name: (name || 'Colaborador').trim().slice(0, 60),
  });
  res.json({ token });
});

app.post('/auth/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  const sess  = token && sessions.get(token);
  if (!sess || Date.now() > sess.expiry) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Sessão inválida ou expirada' });
  }
  req.session = sess;
  req.token   = token;
  next();
}

// ── Admin Auth ────────────────────────────────────────────────────────────────

app.post('/admin/auth', authLimiter, (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(500).json({ error: 'ADMIN_PASSWORD não configurado' });
  const { password } = req.body;
  if (!password || !safeCompare(password, ADMIN_PASSWORD))
    return res.status(401).json({ error: 'Senha incorreta' });
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, Date.now() + SESSION_TTL);
  res.json({ token });
});

app.post('/admin/logout', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token) adminSessions.delete(token);
  res.json({ ok: true });
});

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!token || !adminSessions.has(token) || Date.now() > adminSessions.get(token)) {
    adminSessions.delete(token);
    return res.status(401).json({ error: 'Sessão admin inválida ou expirada' });
  }
  next();
}

function requireAnyAuth(req, res, next) {
  const authToken  = req.headers['x-auth-token'];
  const adminToken = req.headers['x-admin-token'];
  if (authToken) {
    const sess = sessions.get(authToken);
    if (sess && Date.now() <= sess.expiry) { req.session = sess; return next(); }
  }
  if (adminToken && adminSessions.has(adminToken) && Date.now() <= adminSessions.get(adminToken)) {
    return next();
  }
  return res.status(401).json({ error: 'Sessão inválida ou expirada' });
}

// ── Admin Routes ──────────────────────────────────────────────────────────────

app.get('/admin/s3/browse', requireAdmin, async (_req, res) => {
  try {
    const result = await s3.send(new ListObjectsV2Command({
      Bucket: BUCKET,
      Prefix: PREFIX,
    }));
    const files = (result.Contents || []).map(o => ({
      key:          o.Key,
      fileName:     path.basename(o.Key).replace(/^\d+-/, ''),
      size:         o.Size,
      lastModified: o.LastModified,
    }));
    res.json({ files, prefix: PREFIX });
  } catch (err) {
    console.error('[s3/browse]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/uploads', requireAdmin, (_req, res) => {
  res.json({
    active: [...uploadStore.values()],
    recent: recentUploads.slice(-100),
  });
});

// SSE stream – token via query param (browsers don't support custom headers on EventSource)
app.get('/admin/stream', requireAdmin, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const all = [...uploadStore.values(), ...recentUploads.slice(-100)];
  res.write(`event: init\ndata: ${JSON.stringify(all)}\n\n`);

  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

// ── Download (presigned GET URL) ──────────────────────────────────────────────

app.get('/upload/download', requireAnyAuth, async (req, res) => {
  const { key } = req.query;
  if (!key) return res.status(400).json({ error: 'key obrigatório' });
  if (!key.startsWith(PREFIX)) return res.status(403).json({ error: 'Acesso negado' });
  try {
    const cmd = new GetObjectCommand({ Bucket: BUCKET, Key: key });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 3600 });
    res.json({ url });
  } catch (err) {
    console.error('[download]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Upload Progress (client reports bytes to server) ──────────────────────────

app.post('/upload/progress', requireAuth, (req, res) => {
  const { uploadId, bytesUploaded } = req.body;
  const info = uploadId && uploadStore.get(uploadId);
  if (info && typeof bytesUploaded === 'number' && bytesUploaded >= 0 && bytesUploaded <= info.fileSize) {
    info.bytesUploaded = bytesUploaded;
    info.lastActivity  = Date.now();
    broadcast('progress', { uploadId, bytesUploaded });
  }
  res.json({ ok: true });
});

// ── Multipart Upload ──────────────────────────────────────────────────────────

app.post('/upload/initiate', requireAuth, async (req, res) => {
  const { filename, contentType, fileSize } = req.body;
  if (!filename) return res.status(400).json({ error: 'filename obrigatório' });

  const sanitized = path.basename(filename).replace(/[^a-zA-Z0-9._\-() ]/g, '_');
  const key = `${PREFIX}${Date.now()}-${sanitized}`;

  try {
    const result = await s3.send(new CreateMultipartUploadCommand({
      Bucket: BUCKET,
      Key: key,
      ContentType: contentType || 'application/octet-stream',
    }));

    const info = {
      uploadId:      result.UploadId,
      key,
      fileName:      sanitized,
      fileSize:      fileSize || 0,
      contentType:   contentType || 'application/octet-stream',
      userName:      req.session.name,
      status:        'uploading',
      bytesUploaded: 0,
      startedAt:     Date.now(),
      lastActivity:  Date.now(),
      completedAt:   null,
      error:         null,
    };
    uploadStore.set(result.UploadId, info);
    broadcast('upload_started', info);

    res.json({ uploadId: result.UploadId, key });
  } catch (err) {
    console.error('[initiate]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/upload/presign', requireAuth, async (req, res) => {
  const { key, uploadId, partNumber } = req.body;
  if (!key || !uploadId || !partNumber)
    return res.status(400).json({ error: 'key, uploadId e partNumber obrigatórios' });
  const partNum = Number(partNumber);
  if (!Number.isInteger(partNum) || partNum < 1 || partNum > 10000)
    return res.status(400).json({ error: 'partNumber inválido (1–10000)' });
  if (!uploadStore.has(uploadId))
    return res.status(404).json({ error: 'Upload não encontrado' });
  try {
    const cmd = new UploadPartCommand({
      Bucket: BUCKET, Key: key, UploadId: uploadId, PartNumber: partNum,
    });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 3600 });
    res.json({ url });
  } catch (err) {
    console.error('[presign]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/upload/complete', requireAuth, async (req, res) => {
  const { key, uploadId, parts } = req.body;
  if (!key || !uploadId || !Array.isArray(parts))
    return res.status(400).json({ error: 'key, uploadId e parts obrigatórios' });
  try {
    await s3.send(new CompleteMultipartUploadCommand({
      Bucket: BUCKET, Key: key, UploadId: uploadId,
      MultipartUpload: { Parts: parts.map(p => ({ PartNumber: p.PartNumber, ETag: p.ETag })) },
    }));

    const info = uploadStore.get(uploadId);
    if (info) {
      info.status        = 'completed';
      info.bytesUploaded = info.fileSize;
      info.completedAt   = Date.now();
      uploadStore.delete(uploadId);
      pushRecent(info);
      broadcast('upload_completed', info);
    }

    console.log(`[complete] ${key}`);
    res.json({ ok: true, key });
  } catch (err) {
    console.error('[complete]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/upload/abort', requireAuth, async (req, res) => {
  const { key, uploadId } = req.body;
  if (!key || !uploadId) return res.status(400).json({ error: 'key e uploadId obrigatórios' });
  try {
    await s3.send(new AbortMultipartUploadCommand({ Bucket: BUCKET, Key: key, UploadId: uploadId }));

    const info = uploadStore.get(uploadId);
    if (info) {
      info.status      = 'aborted';
      info.error       = 'Cancelado pelo usuário';
      info.completedAt = Date.now();
      uploadStore.delete(uploadId);
      pushRecent(info);
      broadcast('upload_aborted', info);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('[abort]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`S3 Upload Panel rodando em http://localhost:${PORT}`);
  if (!BUCKET)         console.warn('AVISO: S3_BUCKET não configurado!');
  if (!PASSWORD)       console.warn('AVISO: UPLOAD_PASSWORD não configurado!');
  if (!ADMIN_PASSWORD) console.warn('AVISO: ADMIN_PASSWORD não configurado!');
});
