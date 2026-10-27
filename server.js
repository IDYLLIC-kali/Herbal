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
const ADMIN_USER = process.env.ADMIN_USER || "owner";
const ADMIN_PASS = process.env.ADMIN_PASS || "";
const MAX_MB     = Number(process.env.MAX_UPLOAD_MB || 3);

if(!ADMIN_PASS){
  console.error("ADMIN_PASS env var is required. Refusing to start.");
  process.exit(1);
}

if(!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET){
  console.error("Cloudinary env vars missing. Need CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET.");
  process.exit(1);
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

/* photos.json is just a small cache of Cloudinary URLs. On Render it's
   ephemeral, but Cloudinary holds the images permanently. */
const DATA_DIR    = path.join(__dirname, "data");
const PHOTOS_FILE = path.join(DATA_DIR, "photos.json");
fs.mkdirSync(DATA_DIR, { recursive: true });
if(!fs.existsSync(PHOTOS_FILE)) fs.writeFileSync(PHOTOS_FILE, "{}");

const app = express();

function safeEqual(a, b){
  const ab = Buffer.from(a || "");
  const bb = Buffer.from(b || "");
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}
function basicAuth(req, res, next){
  const header = req.headers.authorization || "";
  if(header.startsWith("Basic ")){
    const [user, pass] = Buffer.from(header.slice(6), "base64").toString().split(":");
    if(safeEqual(user, ADMIN_USER) && safeEqual(pass, ADMIN_PASS)) return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Herbal Haven Admin"');
  return res.status(401).send("Authentication required");
}

app.use("/admin", basicAuth, express.static(path.join(__dirname, "admin")));
app.use(express.static(__dirname, { index: "index.html" }));

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
  } catch(e){ /* ignore destroy errors */ }

  delete photos[id];
  writePhotos(photos);
  res.json({ id, removed: true });
});

app.get("*", (req, res) => {
  if(req.path.startsWith("/api/")) return res.status(404).json({ error: "Not found" });
  res.sendFile(path.join(__dirname, "index.html"));
});
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
await rebuildPhotosFromCloudinary();

app.listen(PORT, () => {
  console.log(`Herbal Haven running on http://localhost:${PORT}`);
  console.log(`Storefront: /     Admin: /admin (user: ${ADMIN_USER})`);
  console.log(`Photos go to Cloudinary cloud: ${process.env.CLOUDINARY_CLOUD_NAME}`);
});
