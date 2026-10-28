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
  console.error("Cloudinary env vars missing.");
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
const PRICES_FILE    = path.join(DATA_DIR, "prices.json");
const PRODUCTS_FILE  = path.join(DATA_DIR, "custom_products.json");
const CLOUD_AUTH_ID  = "herbal-haven/_auth/credentials";
const CLOUD_PRICES_ID = "herbal-haven/_auth/prices";
const CLOUD_PROD_ID  = "herbal-haven/_auth/custom_products";

fs.mkdirSync(DATA_DIR, { recursive: true });
if(!fs.existsSync(PHOTOS_FILE)) fs.writeFileSync(PHOTOS_FILE, "{}");
if(!fs.existsSync(PRICES_FILE)) fs.writeFileSync(PRICES_FILE, "{}");
if(!fs.existsSync(PRODUCTS_FILE)) fs.writeFileSync(PRODUCTS_FILE, "[]");

const app = express();
app.use(express.json({ limit: "32kb" }));

/* ============ AUTH STORAGE ============ */
function hashPassword(password, saltHex){
  const salt = Buffer.from(saltHex, "hex");
  return crypto.scryptSync(password, salt, 64).toString("hex");
}
function makeAuthRecord(username, password){
  const saltHex = crypto.randomBytes(16).toString("hex");
  return { username, salt: saltHex, hash: hashPassword(password, saltHex), updatedAt: new Date().toISOString() };
}
function readAuth(){
  try { return JSON.parse(fs.readFileSync(AUTH_FILE, "utf8")); } catch { return null; }
}
function writeAuth(record){ fs.writeFileSync(AUTH_FILE, JSON.stringify(record, null, 2)); }
function safeEqual(a, b){
  const ab = Buffer.from(String(a || "")); const bb = Buffer.from(String(b || ""));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}
function verifyCredentials(username, password){
  const rec = readAuth();
  if(!rec || !rec.salt || !rec.hash) return false;
  if(!safeEqual(username, rec.username)) return false;
  return safeEqual(hashPassword(password, rec.salt), rec.hash);
}

async function pushToCloudinary(json, publicId){
  try {
    const body = Buffer.from(JSON.stringify(json), "utf8");
    await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { resource_type: "raw", folder: "herbal-haven/_auth", public_id: publicId, overwrite: true },
        (err, result) => (err ? reject(err) : resolve(result))
      );
      stream.end(body);
    });
  } catch(e){ console.warn("Cloudinary backup failed:", e.message); }
}

async function pullFromCloudinary(cloudId){
  try {
    const res = await cloudinary.api.resource(cloudId, { resource_type: "raw" });
    const response = await fetch(res.secure_url);
    if(!response.ok) return null;
    return await response.json();
  } catch(e){ return null; }
}

async function bootstrapAuth(){
  const existing = readAuth();
  if(existing && existing.username && existing.salt && existing.hash) return;
  const remote = await pullFromCloudinary(CLOUD_AUTH_ID);
  if(remote && remote.username){
    writeAuth(remote); return;
  }
  if(!BOOT_PASS){ console.error("First boot: set ADMIN_PASS env var."); process.exit(1); }
  const rec = makeAuthRecord(BOOT_USER, BOOT_PASS);
  writeAuth(rec); await pushToCloudinary(rec, "credentials");
}

/* ============ BASIC AUTH ============ */
function basicAuth(req, res, next){
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.set("Pragma", "no-cache");
  const header = req.headers.authorization || "";
  if(header.startsWith("Basic ")){
    const decoded = Buffer.from(header.slice(6), "base64").toString();
    const idx = decoded.indexOf(":");
    if(idx > 0){
      const user = decoded.slice(0, idx); const pass = decoded.slice(idx + 1);
      if(verifyCredentials(user, pass)) return next();
    }
  }
  res.set("WWW-Authenticate", 'Basic realm="Betti Naturals Admin", charset="UTF-8"');
  return res.status(401).send("Authentication required");
}

app.use("/admin", basicAuth, express.static(path.join(__dirname, "admin"), {
  etag: false, lastModified: false,
  setHeaders: (res) => res.set("Cache-Control", "no-store, no-cache, must-revalidate, private")
}));
app.use(express.static(__dirname, { index: "index.html" }));

/* ============ DATA HELPERS ============ */
function readJSON(file, fallback){
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; }
}
function writeJSON(file, data){ fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

/* ============ API ROUTES ============ */
app.get("/api/photos", (_req, res) => { res.set("Cache-Control", "no-store"); res.json(readJSON(PHOTOS_FILE, {})); });
app.get("/api/prices", (_req, res) => { res.set("Cache-Control", "no-store"); res.json(readJSON(PRICES_FILE, {})); });
app.get("/api/products", (_req, res) => { res.set("Cache-Control", "no-store"); res.json(readJSON(PRODUCTS_FILE, [])); });

app.post("/api/prices", basicAuth, async (req, res) => {
  const updates = req.body;
  if(!updates || typeof updates !== "object") return res.status(400).json({ error: "Invalid data" });
  const prices = readJSON(PRICES_FILE, {});
  for(const [id, price] of Object.entries(updates)){
    const num = Number(price);
    if(!Number.isNaN(num) && num > 0) prices[id] = num;
  }
  writeJSON(PRICES_FILE, prices);
  await pushToCloudinary(prices, "prices");
  res.json({ ok: true });
});

app.post("/api/products", basicAuth, async (req, res) => {
  const { name, cat, size, price, desc } = req.body;
  if(!name || !price) return res.status(400).json({ error: "Name and price required" });
  
  const products = readJSON(PRODUCTS_FILE, []);
  // Generate a new ID based on timestamp to avoid clashes
  const newId = Date.now();
  const newProduct = { id: newId, name, cat: cat || "powders", size: size || "", price: Number(price), desc, icon: "leaf" };
  
  products.push(newProduct);
  writeJSON(PRODUCTS_FILE, products);
  await pushToCloudinary(products, "custom_products");
  res.json({ ok: true, product: newProduct });
});

const ALLOWED = new Set(["image/jpeg","image/png","image/webp","image/gif","image/avif"]);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_MB * 1024 * 1024 }, fileFilter: (_req, file, cb) => { if(!ALLOWED.has(file.mimetype)) return cb(new Error("Unsupported image")); cb(null, true); } });

app.post("/api/upload/:id", basicAuth, (req, res) => {
  const id = Number(req.params.id);
  upload.single("photo")(req, res, async (err) => {
    if(err) return res.status(400).json({ error: err.message });
    if(!req.file) return res.status(400).json({ error: "No file" });
    try {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: "herbal-haven", public_id: `product-${id}`, overwrite: true, invalidate: true },
          (error, result) => (error ? reject(error) : resolve(result))
        );
        stream.end(req.file.buffer);
      });
      const photos = readJSON(PHOTOS_FILE, {});
      photos[id] = result.secure_url;
      writeJSON(PHOTOS_FILE, photos);
      res.json({ id, url: result.secure_url });
    } catch(e){ res.status(502).json({ error: e.message }); }
  });
});

app.delete("/api/upload/:id", basicAuth, async (req, res) => {
  const id = Number(req.params.id);
  const photos = readJSON(PHOTOS_FILE, {});
  if(!photos[id]) return res.status(404).json({ error: "Not found" });
  try { await cloudinary.uploader.destroy(`herbal-haven/product-${id}`); } catch(e){}
  delete photos[id]; writeJSON(PHOTOS_FILE, photos);
  res.json({ id, removed: true });
});

app.post("/api/credentials", basicAuth, async (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body || {};
  const currentUser = Buffer.from(req.headers.authorization.slice(6), "base64").toString().split(":")[0];
  if(!verifyCredentials(currentUser, currentPassword || "")) return res.status(403).json({ error: "Current password incorrect" });
  if(newUsername.length < 3 || newPassword.length < 4) return res.status(400).json({ error: "Username min 3, pass min 4" });
  const updated = makeAuthRecord(newUsername, newPassword);
  writeAuth(updated); await pushToCloudinary(updated, "credentials");
  res.json({ ok: true, username: updated.username });
});

/* ============ REBUILD ON BOOT ============ */
async function rebuildFromCloudinary(){
  try {
    const photoRes = await cloudinary.api.resources({ type: "upload", prefix: "herbal-haven/product-", max_results: 500 });
    const photos = {};
    for(const r of photoRes.resources){
      const m = r.public_id.match(/product-(\d+)$/);
      if(m) photos[Number(m[1])] = r.secure_url;
    }
    writeJSON(PHOTOS_FILE, photos);
  } catch(e){}

  const prices = await pullFromCloudinary(CLOUD_PRICES_ID);
  if(prices) writeJSON(PRICES_FILE, prices);

  const products = await pullFromCloudinary(CLOUD_PROD_ID);
  if(products) writeJSON(PRODUCTS_FILE, products);
}

app.get("*", (req, res) => {
  if(req.path.startsWith("/api/")) return res.status(404).json({ error: "Not found" });
  res.sendFile(path.join(__dirname, "index.html"));
});

await bootstrapAuth();
await rebuildFromCloudinary();

app.listen(PORT, () => {
  console.log(`Betti Naturals running on port ${PORT}`);
});
