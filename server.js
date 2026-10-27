import "dotenv/config";
import express from "express";
import multer from "multer";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { v2 as cloudinary } from "cloudinary";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT       = process.env.PORT || 3000;
const MAX_MB     = Number(process.env.MAX_UPLOAD_MB || 3);

const BOOT_USER  = process.env.ADMIN_USER || "owner";
const BOOT_PASS  = process.env.ADMIN_PASS || "";

if(!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET){
  console.error("Cloudinary env vars missing. Need CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET.");
  process.exit(1);
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const DATA_DIR       = path.join(__dirname, "data");
const PHOTOS_FILE    = path.join(DATA_DIR, "photos.json");
const AUTH_FILE      = path.join(DATA_DIR, "auth.json");
const CLOUD_AUTH_ID  = "herbal-haven/_auth/credentials";
fs.mkdirSync(DATA_DIR, { recursive: true });
if(!fs.existsSync(PHOTOS_FILE)) fs.writeFileSync(PHOTOS_FILE, "{}");

const app = express();
app.use(express.json({ limit: "32kb" }));

/* ============ AUTH STORAGE ============ */
/*
  auth.json format:
    { "username": "owner", "salt": "<hex>", "hash": "<hex>", "updatedAt": "..." }
  Passwords are hashed with scrypt + a per-account random salt.
*/

function hashPassword(password, saltHex){
  const salt = Buffer.from(saltHex, "hex");
  return crypto.scryptSync(password, salt, 64).toString("hex");
}
function makeAuthRecord(username, password){
  const saltHex = crypto.randomBytes(16).toString("hex");
  return {
    username,
    salt: saltHex,
    hash: hashPassword(password, saltHex),
    updatedAt: new Date().toISOString()
  };
}
function readAuth(){
  try { return JSON.parse(fs.readFileSync(AUTH_FILE, "utf8")); }
  catch { return null; }
}
function writeAuth(record){
  fs.writeFileSync(AUTH_FILE, JSON.stringify(record, null, 2));
}
function safeEqual(a, b){
  const ab = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}
function verifyCredentials(username, password){
  const rec = readAuth();
  if(!rec || !rec.salt || !rec.hash) return false;
  if(!safeEqual(username, rec.username)) return false;
  const candidate = hashPassword(password, rec.salt);
  return safeEqual(candidate, rec.hash);
}

async function pushAuthToCloudinary(record){
  try {
    const body = Buffer.from(JSON.stringify(record), "utf8");
    await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { resource_type: "raw", folder: "herbal-haven/_auth", public_id: "credentials", overwrite: true },
        (err, result) => (err ? reject(err) : resolve(result))
      );
      stream.end(body);
    });
    console.log("Backed up auth.json to Cloudinary");
  } catch(e){
    console.warn("Could not back up auth.json to Cloudinary:", e.message);
  }
}

async function pullAuthFromCloudinary(){
  try {
    const res = await cloudinary.api.resource(CLOUD_AUTH_ID, { resource_type: "raw" });
    const response = await fetch(res.secure_url);
    if(!response.ok) return null;
    const record = await response.json();
    if(record && record.username && record.salt && record.hash) return record;
  } catch(e){
    /* no backup yet — that's normal on first boot */
  }
  return null;
}

async function bootstrapAuth(){
  // If AUTH_FILE exists and is valid, keep it.
  const existing = readAuth();
  if(existing && existing.username && existing.salt && existing.hash){
    console.log("auth.json found on disk");
    return;
  }
  // If Cloudinary has a backup, restore it.
  const remote = await pullAuthFromCloudinary();
  if(remote){
    writeAuth(remote);
    console.log("Restored auth.json from Cloudinary");
    return;
  }
  // Otherwise seed from env vars (first-ever boot).
  if(!BOOT_PASS || BOOT_PASS.length < 8){
    console.error("First boot: set ADMIN_PASS (min 8 chars) as env var so an initial account can be created.");
    process.exit(1);
  }
  const rec = makeAuthRecord(BOOT_USER, BOOT_PASS);
  writeAuth(rec);
  await pushAuthToCloudinary(rec);
  console.log(`Created initial credentials for user "${BOOT_USER}". Change them from /admin settings.`);
}

/* ============ BASIC AUTH MIDDLEWARE ============ */
function basicAuth(req, res, next){
  // Never let the browser silently reuse a cached credential.
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.set("Pragma", "no-cache");

  const header = req.headers.authorization || "";
  if(header.startsWith("Basic ")){
    const decoded = Buffer.from(header.slice(6), "base64").toString();
    const idx = decoded.indexOf(":");
    if(idx > 0){
      const user = decoded.slice(0, idx);
      const pass = decoded.slice(idx + 1);
      if(verifyCredentials(user, pass)) return next();
    }
  }
  res.set("WWW-Authenticate", 'Basic realm="Herbal Haven Admin", charset="UTF-8"');
  return res.status(401).send("Authentication required");
}

/* ============ STATIC ROUTES ============ */
app.use("/admin", basicAuth, express.static(path.join(__dirname, "admin"), {
  etag: false,
  lastModified: false,
  setHeaders: (res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  }
}));
app.use(express.static(__dirname, { index: "index.html" }));

/* ============ PHOTOS ============ */
function readPhotos(){
  try { return JSON.parse(fs.readFileSync(PHOTOS_FILE, "utf8")); }
  catch { return {}; }
}
function writePhotos(map){
  fs.writeFileSync(PHOTOS_FILE, JSON.stringify(map, null, 2));
}

app.get("/api/photos", (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.json(readPhotos());
});

const ALLOWED = new Set(["image/jpeg","image/png","image/webp","image/gif","image/avif"]);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_MB * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if(!ALLOWED.has(file.mimetype)) return cb(new Error("Unsupported image type"));
    cb(null, true);
  }
});

app.post("/api/upload/:id", basicAuth, (req, res) => {
  const id = Number(req.params.id);
  if(!Number.isInteger(id) || id < 1 || id > 9999){
    return res.status(400).json({ error: "Invalid product id" });
  }

  upload.single("photo")(req, res, async (err) => {
    if(err){
      const msg = err.code === "LIMIT_FILE_SIZE"
        ? `Image larger than ${MAX_MB} MB`
        : err.message || "Upload failed";
      return res.status(400).json({ error: msg });
    }
    if(!req.file) return res.status(400).json({ error: "No file received" });

    try {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          {
            folder: "herbal-haven",
            public_id: `product-${id}`,
            overwrite: true,
            invalidate: true,
            resource_type: "image"
          },
          (error, result) => (error ? reject(error) : resolve(result))
        );
        stream.end(req.file.buffer);
      });

      const photos = readPhotos();
      photos[id] = result.secure_url;
      writePhotos(photos);
      res.json({ id, url: result.secure_url });
    } catch(e){
      res.status(502).json({ error: e.message || "Cloudinary upload failed" });
    }
  });
});

app.delete("/api/upload/:id", basicAuth, async (req, res) => {
  const id = Number(req.params.id);
  const photos = readPhotos();
  if(!photos[id]) return res.status(404).json({ error: "No photo for that product" });

  try {
    await cloudinary.uploader.destroy(`herbal-haven/product-${id}`);
  } catch(e){ /* ignore */ }

  delete photos[id];
  writePhotos(photos);
  res.json({ id, removed: true });
});

/* ============ CHANGE CREDENTIALS ============ */
app.post("/api/credentials", basicAuth, async (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body || {};
  const rec = readAuth();
  if(!rec) return res.status(500).json({ error: "No credentials stored" });

  // current password of the *current* user must match
  const currentUser = (req.headers.authorization || "").startsWith("Basic ")
    ? Buffer.from(req.headers.authorization.slice(6), "base64").toString().split(":")[0]
    : "";
  if(!verifyCredentials(currentUser, currentPassword || "")){
    return res.status(403).json({ error: "Current password is incorrect" });
  }

  const nextUser = String(newUsername || "").trim();
  if(nextUser.length < 3 || nextUser.length > 32){
    return res.status(400).json({ error: "Username must be 3–32 characters" });
  }
  if(!/^[A-Za-z0-9._-]+$/.test(nextUser)){
    return res.status(400).json({ error: "Username may only contain letters, digits, dot, underscore, hyphen" });
  }
  if(String(newPassword || "").length < 8){
    return res.status(400).json({ error: "New password must be at least 8 characters" });
  }

  const updated = makeAuthRecord(nextUser, newPassword);
  writeAuth(updated);
  await pushAuthToCloudinary(updated);
  res.json({ ok: true, username: updated.username });
});

/* ============ REBUILD PHOTOS FROM CLOUDINARY ============ */
async function rebuildPhotosFromCloudinary(){
  try {
    const result = await cloudinary.api.resources({
      type: "upload",
      prefix: "herbal-haven/product-",
      max_results: 500
    });
    const photos = {};
    for(const r of result.resources){
      const m = r.public_id.match(/product-(\d+)$/);
      if(m) photos[Number(m[1])] = r.secure_url;
    }
    writePhotos(photos);
    console.log(`Rebuilt photos.json from Cloudinary: ${Object.keys(photos).length} entries`);
  } catch(e){
    console.warn("Could not rebuild photos.json from Cloudinary:", e.message);
  }
}

/* ============ SPA FALLBACK + BOOT ============ */
app.get("*", (req, res) => {
  if(req.path.startsWith("/api/")) return res.status(404).json({ error: "Not found" });
  res.sendFile(path.join(__dirname, "index.html"));
});

await bootstrapAuth();
await rebuildPhotosFromCloudinary();

app.listen(PORT, () => {
  console.log(`Herbal Haven running on http://localhost:${PORT}`);
  console.log(`Storefront: /     Admin: /admin`);
  console.log(`Photos go to Cloudinary cloud: ${process.env.CLOUDINARY_CLOUD_NAME}`);
});
