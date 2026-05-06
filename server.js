require('dotenv').config();
const express = require('express');
const {
  S3Client,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const s3 = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
  requestChecksumRequired: false, // evita CRC32 nas URLs presignadas de multipart
});

const BUCKET   = process.env.S3_BUCKET;
const PREFIX   = process.env.S3_PREFIX || 'uploads/';
const PASSWORD = process.env.UPLOAD_PASSWORD;
const PORT     = process.env.PORT || 3000;
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24h

// token → expiry
const sessions = new Map();

// Limpa sessões expiradas a cada hora
setInterval(() => {
  const now = Date.now();
  for (const [token, expiry] of sessions) {
    if (now > expiry) sessions.delete(token);
  }
}, 60 * 60 * 1000);

// ── Auth ─────────────────────────────────────────────────────────────────────

app.post('/auth', (req, res) => {
  if (!PASSWORD) return res.status(500).json({ error: 'UPLOAD_PASSWORD não configurado no servidor' });
  const { password } = req.body;
  if (!password || password !== PASSWORD) {
    return res.status(401).json({ error: 'Senha incorreta' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL);
  res.json({ token });
});

app.post('/auth/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions.has(token) || Date.now() > sessions.get(token)) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Sessão inválida ou expirada' });
  }
  next();
}

// ── Multipart Upload ──────────────────────────────────────────────────────────

// 1. Inicia o upload e retorna uploadId + key
app.post('/upload/initiate', requireAuth, async (req, res) => {
  const { filename, contentType } = req.body;
  if (!filename) return res.status(400).json({ error: 'filename obrigatório' });

  // Sanitiza o nome do arquivo para uso seguro como S3 key
  const sanitized = path.basename(filename).replace(/[^a-zA-Z0-9._\-() ]/g, '_');
  const key = `${PREFIX}${Date.now()}-${sanitized}`;

  try {
    const result = await s3.send(new CreateMultipartUploadCommand({
      Bucket: BUCKET,
      Key: key,
      ContentType: contentType || 'application/octet-stream',
    }));
    res.json({ uploadId: result.UploadId, key });
  } catch (err) {
    console.error('[initiate]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 2. Gera URL assinada para upload de uma parte diretamente no S3
app.post('/upload/presign', requireAuth, async (req, res) => {
  const { key, uploadId, partNumber } = req.body;
  if (!key || !uploadId || !partNumber) {
    return res.status(400).json({ error: 'key, uploadId e partNumber obrigatórios' });
  }

  try {
    const cmd = new UploadPartCommand({
      Bucket: BUCKET,
      Key: key,
      UploadId: uploadId,
      PartNumber: Number(partNumber),
    });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 3600 });
    res.json({ url });
  } catch (err) {
    console.error('[presign]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 3. Finaliza o upload com a lista de partes e ETags
app.post('/upload/complete', requireAuth, async (req, res) => {
  const { key, uploadId, parts } = req.body;
  if (!key || !uploadId || !Array.isArray(parts)) {
    return res.status(400).json({ error: 'key, uploadId e parts obrigatórios' });
  }

  try {
    await s3.send(new CompleteMultipartUploadCommand({
      Bucket: BUCKET,
      Key: key,
      UploadId: uploadId,
      MultipartUpload: {
        Parts: parts.map(p => ({ PartNumber: p.PartNumber, ETag: p.ETag })),
      },
    }));
    console.log(`[complete] ${key}`);
    res.json({ ok: true, key });
  } catch (err) {
    console.error('[complete]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 4. Cancela o upload (libera as partes no S3)
app.post('/upload/abort', requireAuth, async (req, res) => {
  const { key, uploadId } = req.body;
  if (!key || !uploadId) return res.status(400).json({ error: 'key e uploadId obrigatórios' });

  try {
    await s3.send(new AbortMultipartUploadCommand({
      Bucket: BUCKET,
      Key: key,
      UploadId: uploadId,
    }));
    res.json({ ok: true });
  } catch (err) {
    console.error('[abort]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`S3 Upload Panel rodando em http://localhost:${PORT}`);
  if (!BUCKET)   console.warn('AVISO: S3_BUCKET não configurado!');
  if (!PASSWORD) console.warn('AVISO: UPLOAD_PASSWORD não configurado!');
});
