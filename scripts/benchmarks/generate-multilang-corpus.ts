/**
 * Deterministic multilanguage security benchmark corpus generator.
 * Inspired by CWE / OWASP patterns and OpenSSF CVE Benchmark idioms — original minimal snippets only.
 *
 * Usage:
 *   npx tsx scripts/benchmarks/generate-multilang-corpus.ts
 *   CASES_PER_LANG=150 npx tsx scripts/benchmarks/generate-multilang-corpus.ts
 */

import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");

export type HarnessCategory =
  | "injection"
  | "authz"
  | "secrets"
  | "crypto"
  | "config"
  | "dependency"
  | "other";

export type Language = "c" | "cpp" | "rust" | "python" | "javascript" | "typescript";

export type BenchmarkCase = {
  id: string;
  language: Language;
  category: string;
  cwe?: string;
  file_path: string;
  diff: string;
  expected: Array<{ category: HarnessCategory }>;
  negative: boolean;
};

const LANGS: Language[] = ["c", "cpp", "rust", "python", "javascript", "typescript"];

const NAMES = [
  "user",
  "account",
  "session",
  "payload",
  "request",
  "resource",
  "target",
  "input",
  "token",
  "record",
  "client",
  "order",
  "profile",
  "config",
  "buffer",
  "path",
  "query",
  "host",
  "url",
  "data",
];

function pick<T>(seed: number, arr: T[]): T {
  return arr[seed % arr.length]!;
}

function slug(s: string): string {
  return s.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase();
}

export type TemplateCtx = { seed: number; lang: Language; variant: number; name: string };

export type CaseTemplate = {
  category: string;
  cwe?: string;
  harness: HarnessCategory;
  ext: string;
  dir: string;
  positive: (ctx: TemplateCtx) => { diff: string; fn: string };
  negative: (ctx: TemplateCtx) => { diff: string; fn: string };
};

function ctx(seed: number, lang: Language, variant: number): TemplateCtx {
  return { seed, lang, variant, name: pick(seed + variant, NAMES) };
}

function makeId(lang: Language, category: string, variant: number, negative: boolean): string {
  const prefix = negative ? "safe" : "vuln";
  return `${lang}-${slug(category)}-${prefix}-${String(variant).padStart(3, "0")}`;
}

export function buildCase(
  lang: Language,
  tpl: CaseTemplate,
  variant: number,
  negative: boolean
): BenchmarkCase {
  const c = ctx(variant * 17 + tpl.category.length, lang, variant);
  const body = negative ? tpl.negative(c) : tpl.positive(c);
  return {
    id: makeId(lang, tpl.category, variant, negative),
    language: lang,
    category: tpl.category,
    cwe: tpl.cwe,
    file_path: `${tpl.dir}/${body.fn}.${tpl.ext}`,
    diff: body.diff,
    expected: negative ? [] : [{ category: tpl.harness }],
    negative,
  };
}

// --- C templates ---
const C_TEMPLATES: CaseTemplate[] = [
  {
    category: "buffer-overflow",
    cwe: "CWE-787",
    harness: "injection",
    ext: "c",
    dir: "src/net",
    positive: ({ name }) => ({
      fn: `copy_${name}`,
      diff: `@@ -18,8 +18,7 @@ int copy_${name}(const char *in, char *out, size_t out_len) {
   if (!in || !out) return -1;
-  strncpy(out, in, out_len - 1);
-  out[out_len - 1] = '\\0';
+  strcpy(out, in);
   return 0;
 }`,
    }),
    negative: ({ name }) => ({
      fn: `copy_${name}`,
      diff: `@@ -18,8 +18,8 @@ int copy_${name}(const char *in, char *out, size_t out_len) {
   if (!in || !out) return -1;
-  strncpy(out, in, out_len - 1);
-  out[out_len - 1] = '\\0';
+  size_t n = strnlen(in, out_len - 1);
+  memcpy(out, in, n);
+  out[n] = '\\0';
   return 0;
 }`,
    }),
  },
  {
    category: "format-string",
    cwe: "CWE-134",
    harness: "injection",
    ext: "c",
    dir: "src/log",
    positive: ({ name }) => ({
      fn: `log_${name}`,
      diff: `@@ -9,7 +9,7 @@ void log_${name}(const char *fmt, ...) {
   va_list ap;
   va_start(ap, fmt);
-  vfprintf(stderr, fmt, ap);
+  fprintf(stderr, fmt, ap);
   va_end(ap);
 }`,
    }),
    negative: ({ name }) => ({
      fn: `log_${name}`,
      diff: `@@ -9,7 +9,7 @@ void log_${name}(const char *fmt, ...) {
   va_list ap;
   va_start(ap, fmt);
-  vfprintf(stderr, fmt, ap);
+  vfprintf(stderr, "%s", fmt);
   va_end(ap);
 }`,
    }),
  },
  {
    category: "integer-overflow",
    cwe: "CWE-190",
    harness: "injection",
    ext: "c",
    dir: "src/alloc",
    positive: ({ name }) => ({
      fn: `alloc_${name}`,
      diff: `@@ -12,8 +12,7 @@ void *alloc_${name}(size_t count, size_t size) {
-  if (count > 0 && size > SIZE_MAX / count) return NULL;
-  return malloc(count * size);
+  return malloc(count * size);
 }`,
    }),
    negative: ({ name }) => ({
      fn: `alloc_${name}`,
      diff: `@@ -12,8 +12,9 @@ void *alloc_${name}(size_t count, size_t size) {
-  if (count > 0 && size > SIZE_MAX / count) return NULL;
-  return malloc(count * size);
+  if (count == 0 || size == 0) return NULL;
+  if (count > SIZE_MAX / size) return NULL;
+  return calloc(count, size);
 }`,
    }),
  },
  {
    category: "null-deref",
    cwe: "CWE-476",
    harness: "other",
    ext: "c",
    dir: "src/auth",
    positive: ({ name }) => ({
      fn: `check_${name}`,
      diff: `@@ -21,7 +21,6 @@ int check_${name}(struct session *s) {
-  if (!s || !s->user) return -1;
   return strcmp(s->user->role, "admin") == 0;
 }`,
    }),
    negative: ({ name }) => ({
      fn: `check_${name}`,
      diff: `@@ -21,7 +21,8 @@ int check_${name}(struct session *s) {
-  if (!s || !s->user) return -1;
+  if (!s || !s->user || !s->user->role) return -1;
   return strcmp(s->user->role, "admin") == 0;
 }`,
    }),
  },
  {
    category: "command-injection",
    cwe: "CWE-78",
    harness: "injection",
    ext: "c",
    dir: "src/tools",
    positive: ({ name }) => ({
      fn: `run_${name}`,
      diff: `@@ -14,7 +14,7 @@ int run_${name}(const char *filename) {
   char cmd[512];
-  snprintf(cmd, sizeof(cmd), "convert %s out.png", filename);
+  sprintf(cmd, "convert %s out.png", filename);
   return system(cmd);
 }`,
    }),
    negative: ({ name }) => ({
      fn: `run_${name}`,
      diff: `@@ -14,7 +14,9 @@ int run_${name}(const char *filename) {
   char cmd[512];
-  snprintf(cmd, sizeof(cmd), "convert %s out.png", filename);
+  const char *args[] = { "convert", filename, "out.png", NULL };
+  return execv("/usr/bin/convert", (char *const *)args);
 }`,
    }),
  },
  {
    category: "path-traversal",
    cwe: "CWE-22",
    harness: "injection",
    ext: "c",
    dir: "src/fs",
    positive: ({ name }) => ({
      fn: `open_${name}`,
      diff: `@@ -30,7 +30,7 @@ FILE *open_${name}(const char *name) {
   char path[256];
-  snprintf(path, sizeof(path), "/data/%s", basename(name));
+  snprintf(path, sizeof(path), "/data/%s", name);
   return fopen(path, "rb");
 }`,
    }),
    negative: ({ name }) => ({
      fn: `open_${name}`,
      diff: `@@ -30,7 +30,9 @@ FILE *open_${name}(const char *name) {
   char path[256];
-  snprintf(path, sizeof(path), "/data/%s", basename(name));
+  const char *base = basename(name);
+  if (strstr(base, "..") != NULL) return NULL;
+  snprintf(path, sizeof(path), "/data/%s", base);
   return fopen(path, "rb");
 }`,
    }),
  },
  {
    category: "hardcoded-secrets",
    cwe: "CWE-798",
    harness: "secrets",
    ext: "c",
    dir: "src/config",
    positive: ({ name }) => ({
      fn: `load_${name}`,
      diff: `@@ -4,6 +4,7 @@ struct config load_${name}(void) {
   struct config c = {0};
+  strcpy(c.api_key, "sk_live_REPLACE_ME_IN_DIFF_7f3a");
   c.port = 8080;
   return c;
 }`,
    }),
    negative: ({ name }) => ({
      fn: `load_${name}`,
      diff: `@@ -4,6 +4,7 @@ struct config load_${name}(void) {
   struct config c = {0};
+  const char *key = getenv("API_KEY");
+  if (key) strncpy(c.api_key, key, sizeof(c.api_key) - 1);
   c.port = 8080;
   return c;
 }`,
    }),
  },
  {
    category: "use-after-free",
    cwe: "CWE-416",
    harness: "injection",
    ext: "c",
    dir: "src/cache",
    positive: ({ name }) => ({
      fn: `cache_${name}`,
      diff: `@@ -44,9 +44,8 @@ const char *cache_${name}(struct entry *e) {
   free(e->payload);
-  e->payload = strdup("ok");
-  return e->payload;
+  return e->payload;
 }`,
    }),
    negative: ({ name }) => ({
      fn: `cache_${name}`,
      diff: `@@ -44,9 +44,9 @@ const char *cache_${name}(struct entry *e) {
   free(e->payload);
-  e->payload = strdup("ok");
-  return e->payload;
+  e->payload = strdup("ok");
+  if (!e->payload) return NULL;
+  return e->payload;
 }`,
    }),
  },
];

// --- C++ templates (extends C patterns) ---
const CPP_TEMPLATES: CaseTemplate[] = [
  {
    category: "buffer-overflow",
    cwe: "CWE-787",
    harness: "injection",
    ext: "cpp",
    dir: "src/parser",
    positive: ({ name }) => ({
      fn: `parse_${name}`,
      diff: `@@ -22,7 +22,7 @@ void parse_${name}(std::span<char> out, const char *in) {
-  std::strncpy(out.data(), in, out.size() - 1);
-  out[out.size() - 1] = '\\0';
+  std::strcpy(out.data(), in);
 }`,
    }),
    negative: ({ name }) => ({
      fn: `parse_${name}`,
      diff: `@@ -22,7 +22,7 @@ void parse_${name}(std::span<char> out, const char *in) {
-  std::strncpy(out.data(), in, out.size() - 1);
-  out[out.size() - 1] = '\\0';
+  std::string safe(in);
+  safe.copy(out.data(), out.size() - 1);
 }`,
    }),
  },
  {
    category: "iterator-invalidation",
    cwe: "CWE-416",
    harness: "injection",
    ext: "cpp",
    dir: "src/store",
    positive: ({ name }) => ({
      fn: `erase_${name}`,
      diff: `@@ -31,8 +31,7 @@ void erase_${name}(std::vector<Item> &items, size_t idx) {
   auto it = items.begin() + idx;
   items.erase(it);
-  process(*it);
+  process(items[idx]);
 }`,
    }),
    negative: ({ name }) => ({
      fn: `erase_${name}`,
      diff: `@@ -31,8 +31,8 @@ void erase_${name}(std::vector<Item> &items, size_t idx) {
   auto it = items.begin() + idx;
+  Item copy = *it;
   items.erase(it);
-  process(*it);
+  process(copy);
 }`,
    }),
  },
  {
    category: "double-free",
    cwe: "CWE-415",
    harness: "injection",
    ext: "cpp",
    dir: "src/legacy",
    positive: ({ name }) => ({
      fn: `release_${name}`,
      diff: `@@ -15,8 +15,8 @@ void release_${name}(Buffer *b) {
   delete b;
+  delete b;
 }`,
    }),
    negative: ({ name }) => ({
      fn: `release_${name}`,
      diff: `@@ -15,8 +15,9 @@ void release_${name}(Buffer *b) {
-  delete b;
+  delete b;
+  b = nullptr;
 }`,
    }),
  },
  {
    category: "format-string",
    cwe: "CWE-134",
    harness: "injection",
    ext: "cpp",
    dir: "src/log",
    positive: ({ name }) => ({
      fn: `audit_${name}`,
      diff: `@@ -11,7 +11,7 @@ void audit_${name}(const std::string &msg) {
-  std::fprintf(stderr, "%s", msg.c_str());
+  std::printf(msg.c_str());
 }`,
    }),
    negative: ({ name }) => ({
      fn: `audit_${name}`,
      diff: `@@ -11,7 +11,7 @@ void audit_${name}(const std::string &msg) {
-  std::fprintf(stderr, "%s", msg.c_str());
+  std::fprintf(stderr, "%s", msg.c_str());
 }`,
    }),
  },
  {
    category: "integer-overflow",
    cwe: "CWE-190",
    harness: "injection",
    ext: "cpp",
    dir: "src/alloc",
    positive: ({ name }) => ({
      fn: `reserve_${name}`,
      diff: `@@ -8,7 +8,6 @@ std::vector<uint8_t> reserve_${name}(size_t n, size_t sz) {
-  if (n > 0 && sz > std::vector<uint8_t>::max_size() / n)
-    throw std::length_error("overflow");
   return std::vector<uint8_t>(n * sz);
 }`,
    }),
    negative: ({ name }) => ({
      fn: `reserve_${name}`,
      diff: `@@ -8,7 +8,8 @@ std::vector<uint8_t> reserve_${name}(size_t n, size_t sz) {
-  if (n > 0 && sz > std::vector<uint8_t>::max_size() / n)
-    throw std::length_error("overflow");
+  if (n == 0 || sz == 0) return {};
+  if (n > std::vector<uint8_t>::max_size() / sz) throw std::length_error("overflow");
   return std::vector<uint8_t>(n * sz);
 }`,
    }),
  },
  {
    category: "command-injection",
    cwe: "CWE-78",
    harness: "injection",
    ext: "cpp",
    dir: "src/shell",
    positive: ({ name }) => ({
      fn: `compress_${name}`,
      diff: `@@ -19,7 +19,7 @@ int compress_${name}(const std::string &file) {
-  return std::system(("gzip " + shell_escape(file)).c_str());
+  return std::system(("gzip " + file).c_str());
 }`,
    }),
    negative: ({ name }) => ({
      fn: `compress_${name}`,
      diff: `@@ -19,7 +19,8 @@ int compress_${name}(const std::string &file) {
-  return std::system(("gzip " + shell_escape(file)).c_str());
+  std::vector<std::string> args{"gzip", file};
+  return run_exec("/bin/gzip", args);
 }`,
    }),
  },
  {
    category: "path-traversal",
    cwe: "CWE-22",
    harness: "injection",
    ext: "cpp",
    dir: "src/files",
    positive: ({ name }) => ({
      fn: `read_${name}`,
      diff: `@@ -26,7 +26,7 @@ std::string read_${name}(const std::string &userPath) {
-  auto safe = fs::path("/vault").append(fs::path(userPath).filename());
+  auto safe = fs::path("/vault") / userPath;
   return read_all(safe);
 }`,
    }),
    negative: ({ name }) => ({
      fn: `read_${name}`,
      diff: `@@ -26,7 +26,9 @@ std::string read_${name}(const std::string &userPath) {
-  auto safe = fs::path("/vault").append(fs::path(userPath).filename());
+  auto base = fs::path(userPath).filename();
+  if (base.string().find("..") != std::string::npos) throw std::runtime_error("bad path");
+  auto safe = fs::path("/vault") / base;
   return read_all(safe);
 }`,
    }),
  },
  {
    category: "missing-authz",
    cwe: "CWE-862",
    harness: "authz",
    ext: "cpp",
    dir: "src/api",
    positive: ({ name }) => ({
      fn: `delete_${name}`,
      diff: `@@ -40,6 +40,9 @@ void delete_${name}(HttpRequest &req) {
+void delete_${name}_handler(HttpRequest &req) {
+  db.remove(req.param("id"));
+  req.send(200, "{}");
+}
 void delete_${name}(HttpRequest &req) {`,
    }),
    negative: ({ name }) => ({
      fn: `delete_${name}`,
      diff: `@@ -40,6 +40,9 @@ void delete_${name}(HttpRequest &req) {
+void delete_${name}_handler(HttpRequest &req) {
+  if (!req.user().is_admin()) return req.send(403, "{}");
+  db.remove(req.param("id"));
+  req.send(200, "{}");
+}
 void delete_${name}(HttpRequest &req) {`,
    }),
  },
];

// --- Rust ---
const RUST_TEMPLATES: CaseTemplate[] = [
  {
    category: "unsafe-misuse",
    cwe: "CWE-787",
    harness: "injection",
    ext: "rs",
    dir: "src/net",
    positive: ({ name }) => ({
      fn: `copy_${name}`,
      diff: `@@ -18,8 +18,7 @@ pub fn copy_${name}(src: &[u8], dst: &mut [u8]) {
     unsafe {
-        let n = src.len().min(dst.len());
-        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n);
+        std::ptr::copy(src.as_ptr(), dst.as_mut_ptr(), src.len());
     }
 }`,
    }),
    negative: ({ name }) => ({
      fn: `copy_${name}`,
      diff: `@@ -18,8 +18,7 @@ pub fn copy_${name}(src: &[u8], dst: &mut [u8]) {
     unsafe {
-        let n = src.len().min(dst.len());
-        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n);
+        let n = src.len().min(dst.len());
+        dst[..n].copy_from_slice(&src[..n]);
     }
 }`,
    }),
  },
  {
    category: "unwrap-panic",
    cwe: "CWE-754",
    harness: "other",
    ext: "rs",
    dir: "src/auth",
    positive: ({ name }) => ({
      fn: `verify_${name}`,
      diff: `@@ -12,7 +12,7 @@ pub fn verify_${name}(token: Option<&str>) -> bool {
-    let t = token?;
+    let t = token.unwrap();
     validate_hmac(t)
 }`,
    }),
    negative: ({ name }) => ({
      fn: `verify_${name}`,
      diff: `@@ -12,7 +12,7 @@ pub fn verify_${name}(token: Option<&str>) -> bool {
-    let t = token?;
+    let Some(t) = token else { return false };
     validate_hmac(t)
 }`,
    }),
  },
  {
    category: "command-injection",
    cwe: "CWE-78",
    harness: "injection",
    ext: "rs",
    dir: "src/tools",
    positive: ({ name }) => ({
      fn: `render_${name}`,
      diff: `@@ -9,7 +9,7 @@ pub fn render_${name}(path: &str) -> std::io::Result<()> {
-    Command::new("convert").arg(path).arg("out.png").status()?;
+    Command::new("sh").arg("-c").arg(format!("convert {} out.png", path)).status()?;
     Ok(())
 }`,
    }),
    negative: ({ name }) => ({
      fn: `render_${name}`,
      diff: `@@ -9,7 +9,8 @@ pub fn render_${name}(path: &str) -> std::io::Result<()> {
-    Command::new("convert").arg(path).arg("out.png").status()?;
+    let mut cmd = Command::new("convert");
+    cmd.arg(path).arg("out.png").status()?;
     Ok(())
 }`,
    }),
  },
  {
    category: "sql-injection",
    cwe: "CWE-89",
    harness: "injection",
    ext: "rs",
    dir: "src/db",
    positive: ({ name }) => ({
      fn: `find_${name}`,
      diff: `@@ -21,7 +21,7 @@ pub async fn find_${name}(pool: &PgPool, id: &str) -> Result<User> {
-    sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
+    sqlx::query_as!(User, &format!("SELECT * FROM users WHERE id = '{}'", id))
         .fetch_one(pool)
         .await
 }`,
    }),
    negative: ({ name }) => ({
      fn: `find_${name}`,
      diff: `@@ -21,7 +21,7 @@ pub async fn find_${name}(pool: &PgPool, id: &str) -> Result<User> {
-    sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
+    sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
         .fetch_one(pool)
         .await
 }`,
    }),
  },
  {
    category: "path-traversal",
    cwe: "CWE-22",
    harness: "injection",
    ext: "rs",
    dir: "src/fs",
    positive: ({ name }) => ({
      fn: `load_${name}`,
      diff: `@@ -14,7 +14,7 @@ pub fn load_${name}(name: &str) -> std::io::Result<Vec<u8>> {
-    let path = Path::new("/data").join(Path::new(name).file_name().unwrap());
+    let path = Path::new("/data").join(name);
     std::fs::read(path)
 }`,
    }),
    negative: ({ name }) => ({
      fn: `load_${name}`,
      diff: `@@ -14,7 +14,9 @@ pub fn load_${name}(name: &str) -> std::io::Result<Vec<u8>> {
-    let path = Path::new("/data").join(Path::new(name).file_name().unwrap());
+    let base = Path::new(name).file_name().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad"))?;
+    if name.contains("..") { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "traversal")); }
+    let path = Path::new("/data").join(base);
     std::fs::read(path)
 }`,
    }),
  },
  {
    category: "hardcoded-secrets",
    cwe: "CWE-798",
    harness: "secrets",
    ext: "rs",
    dir: "src/config",
    positive: ({ name }) => ({
      fn: `jwt_${name}`,
      diff: `@@ -3,7 +3,7 @@ use once_cell::sync::Lazy;
 
-static JWT_SECRET: Lazy<String> = Lazy::new(|| std::env::var("JWT_SECRET").expect("JWT_SECRET"));
+static JWT_SECRET: Lazy<String> = Lazy::new(|| "hardcoded-jwt-secret-do-not-ship".into());
 
 pub fn sign_${name}(claims: Claims) -> String {`,
    }),
    negative: ({ name }) => ({
      fn: `jwt_${name}`,
      diff: `@@ -3,7 +3,7 @@ use once_cell::sync::Lazy;
 
-static JWT_SECRET: Lazy<String> = Lazy::new(|| std::env::var("JWT_SECRET").expect("JWT_SECRET"));
+static JWT_SECRET: Lazy<String> = Lazy::new(|| std::env::var("JWT_SECRET").expect("JWT_SECRET"));
 
 pub fn sign_${name}(claims: Claims) -> String {`,
    }),
  },
  {
    category: "ssrf",
    cwe: "CWE-918",
    harness: "injection",
    ext: "rs",
    dir: "src/preview",
    positive: ({ name }) => ({
      fn: `preview_${name}`,
      diff: `@@ -27,7 +27,7 @@ pub async fn preview_${name}(url: &str) -> Result<String> {
-    if !is_allowed_host(url) { bail!("blocked"); }
+    let body = reqwest::get(url).await?.text().await?;
     Ok(body)
 }`,
    }),
    negative: ({ name }) => ({
      fn: `preview_${name}`,
      diff: `@@ -27,7 +27,8 @@ pub async fn preview_${name}(url: &str) -> Result<String> {
-    if !is_allowed_host(url) { bail!("blocked"); }
+    if !is_allowed_host(url) { bail!("blocked"); }
+    let body = reqwest::get(url).await?.text().await?;
     Ok(body)
 }`,
    }),
  },
  {
    category: "integer-overflow-unsafe",
    cwe: "CWE-190",
    harness: "injection",
    ext: "rs",
    dir: "src/binary",
    positive: ({ name }) => ({
      fn: `read_${name}`,
      diff: `@@ -33,8 +33,7 @@ pub fn read_${name}(data: &[u8]) -> usize {
     let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
-    let cap = data.len().saturating_sub(4);
-    len.min(cap)
+    len
 }`,
    }),
    negative: ({ name }) => ({
      fn: `read_${name}`,
      diff: `@@ -33,8 +33,9 @@ pub fn read_${name}(data: &[u8]) -> usize {
     let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
-    let cap = data.len().saturating_sub(4);
-    len.min(cap)
+    let cap = data.len().saturating_sub(4);
+    if len > cap { return cap; }
+    len
 }`,
    }),
  },
];

// --- Python ---
const PYTHON_TEMPLATES: CaseTemplate[] = [
  {
    category: "sql-injection",
    cwe: "CWE-89",
    harness: "injection",
    ext: "py",
    dir: "app/db",
    positive: ({ name }) => ({
      fn: `get_${name}`,
      diff: `@@ -14,7 +14,7 @@ def get_${name}(conn, user_id: str):
     cur = conn.cursor()
-    cur.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
+    cur.execute(f"SELECT * FROM accounts WHERE id = '{user_id}'")
     return cur.fetchone()
 `,
    }),
    negative: ({ name }) => ({
      fn: `get_${name}`,
      diff: `@@ -14,7 +14,7 @@ def get_${name}(conn, user_id: str):
     cur = conn.cursor()
-    cur.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
+    cur.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
     return cur.fetchone()
 `,
    }),
  },
  {
    category: "command-injection",
    cwe: "CWE-78",
    harness: "injection",
    ext: "py",
    dir: "app/tools",
    positive: ({ name }) => ({
      fn: `ping_${name}`,
      diff: `@@ -8,7 +8,7 @@ def ping_${name}(host: str) -> str:
-    return subprocess.check_output(["ping", "-c", "1", host], text=True)
+    return subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
 `,
    }),
    negative: ({ name }) => ({
      fn: `ping_${name}`,
      diff: `@@ -8,7 +8,7 @@ def ping_${name}(host: str) -> str:
-    return subprocess.check_output(["ping", "-c", "1", host], text=True)
+    return subprocess.check_output(["ping", "-c", "1", host], text=True)
 `,
    }),
  },
  {
    category: "pickle-deserialization",
    cwe: "CWE-502",
    harness: "injection",
    ext: "py",
    dir: "app/cache",
    positive: ({ name }) => ({
      fn: `load_${name}`,
      diff: `@@ -11,7 +11,7 @@ def load_${name}(blob: bytes):
-    return json.loads(blob)
+    return pickle.loads(blob)
 `,
    }),
    negative: ({ name }) => ({
      fn: `load_${name}`,
      diff: `@@ -11,7 +11,7 @@ def load_${name}(blob: bytes):
-    return json.loads(blob)
+    return json.loads(blob)
 `,
    }),
  },
  {
    category: "ssrf",
    cwe: "CWE-918",
    harness: "injection",
    ext: "py",
    dir: "app/preview",
    positive: ({ name }) => ({
      fn: `fetch_${name}`,
      diff: `@@ -19,7 +19,6 @@ def fetch_${name}(url: str) -> str:
-    if not is_allowed(url):
-        raise ValueError("blocked")
+    return requests.get(url, timeout=5).text
 `,
    }),
    negative: ({ name }) => ({
      fn: `fetch_${name}`,
      diff: `@@ -19,7 +19,8 @@ def fetch_${name}(url: str) -> str:
-    if not is_allowed(url):
-        raise ValueError("blocked")
+    if not is_allowed(url):
+        raise ValueError("blocked")
+    return requests.get(url, timeout=5).text
 `,
    }),
  },
  {
    category: "path-traversal",
    cwe: "CWE-22",
    harness: "injection",
    ext: "py",
    dir: "app/files",
    positive: ({ name }) => ({
      fn: `open_${name}`,
      diff: `@@ -23,7 +23,7 @@ def open_${name}(name: str) -> bytes:
-    safe = os.path.join("/data", os.path.basename(name))
+    safe = os.path.join("/data", name)
     return open(safe, "rb").read()
 `,
    }),
    negative: ({ name }) => ({
      fn: `open_${name}`,
      diff: `@@ -23,7 +23,9 @@ def open_${name}(name: str) -> bytes:
-    safe = os.path.join("/data", os.path.basename(name))
+    base = os.path.basename(name)
+    if ".." in name:
+        raise ValueError("traversal")
+    safe = os.path.join("/data", base)
     return open(safe, "rb").read()
 `,
    }),
  },
  {
    category: "hardcoded-secrets",
    cwe: "CWE-798",
    harness: "secrets",
    ext: "py",
    dir: "app/config",
    positive: ({ name }) => ({
      fn: `settings_${name}`,
      diff: `@@ -4,6 +4,7 @@ class Settings:
     debug: bool = False
+    stripe_key: str = "sk_live_HARDCODED_IN_DIFF_ABC123"
 
     @classmethod`,
    }),
    negative: ({ name }) => ({
      fn: `settings_${name}`,
      diff: `@@ -4,6 +4,7 @@ class Settings:
     debug: bool = False
+    stripe_key: str = os.environ["STRIPE_KEY"]
 
     @classmethod`,
    }),
  },
  {
    category: "ssti",
    cwe: "CWE-94",
    harness: "injection",
    ext: "py",
    dir: "app/views",
    positive: ({ name }) => ({
      fn: `render_${name}`,
      diff: `@@ -30,7 +30,7 @@ def render_${name}(template_str: str, ctx: dict) -> str:
-    return Template(template_str).render(**ctx)
+    return Template(template_str).render(**ctx, **request.args)
 `,
    }),
    negative: ({ name }) => ({
      fn: `render_${name}`,
      diff: `@@ -30,7 +30,8 @@ def render_${name}(template_str: str, ctx: dict) -> str:
-    return Template(template_str).render(**ctx)
+    env = SandboxedEnvironment()
+    return env.from_string(template_str).render(**ctx)
 `,
    }),
  },
  {
    category: "yaml-unsafe-load",
    cwe: "CWE-502",
    harness: "injection",
    ext: "py",
    dir: "app/import",
    positive: ({ name }) => ({
      fn: `parse_${name}`,
      diff: `@@ -6,7 +6,7 @@ def parse_${name}(raw: str) -> dict:
-    return yaml.safe_load(raw)
+    return yaml.load(raw, Loader=yaml.Loader)
 `,
    }),
    negative: ({ name }) => ({
      fn: `parse_${name}`,
      diff: `@@ -6,7 +6,7 @@ def parse_${name}(raw: str) -> dict:
-    return yaml.safe_load(raw)
+    return yaml.safe_load(raw)
 `,
    }),
  },
];

// --- JavaScript ---
const JS_TEMPLATES: CaseTemplate[] = [
  {
    category: "xss",
    cwe: "CWE-79",
    harness: "injection",
    ext: "js",
    dir: "src/ui",
    positive: ({ name }) => ({
      fn: `show_${name}`,
      diff: `@@ -18,7 +18,7 @@ export function show_${name}(el, value) {
-  el.textContent = value;
+  el.innerHTML = value;
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `show_${name}`,
      diff: `@@ -18,7 +18,7 @@ export function show_${name}(el, value) {
-  el.textContent = value;
+  el.textContent = escapeHtml(value);
 }
 `,
    }),
  },
  {
    category: "prototype-pollution",
    cwe: "CWE-1321",
    harness: "injection",
    ext: "js",
    dir: "src/merge",
    positive: ({ name }) => ({
      fn: `merge_${name}`,
      diff: `@@ -9,7 +9,7 @@ export function merge_${name}(target, source) {
   for (const key of Object.keys(source)) {
-    if (key === '__proto__') continue;
+    target[key] = source[key];
   }
   return target;
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `merge_${name}`,
      diff: `@@ -9,7 +9,8 @@ export function merge_${name}(target, source) {
   for (const key of Object.keys(source)) {
-    if (key === '__proto__') continue;
+    if (key === '__proto__' || key === 'constructor') continue;
+    target[key] = source[key];
   }
   return target;
 }
 `,
    }),
  },
  {
    category: "nosql-injection",
    cwe: "CWE-943",
    harness: "injection",
    ext: "js",
    dir: "src/db",
    positive: ({ name }) => ({
      fn: `find_${name}`,
      diff: `@@ -22,7 +22,7 @@ export async function find_${name}(db, username) {
-  return db.collection('users').findOne({ username });
+  return db.collection('users').findOne(JSON.parse(username));
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `find_${name}`,
      diff: `@@ -22,7 +22,8 @@ export async function find_${name}(db, username) {
-  return db.collection('users').findOne({ username });
+  if (typeof username !== 'string') throw new TypeError('username must be string');
+  return db.collection('users').findOne({ username });
 }
 `,
    }),
  },
  {
    category: "ssrf",
    cwe: "CWE-918",
    harness: "injection",
    ext: "js",
    dir: "src/preview",
    positive: ({ name }) => ({
      fn: `preview_${name}`,
      diff: `@@ -11,7 +11,6 @@ export async function preview_${name}(url) {
-  if (!isAllowedHost(url)) throw new Error('blocked');
   const res = await fetch(url);
   return res.text();
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `preview_${name}`,
      diff: `@@ -11,7 +11,8 @@ export async function preview_${name}(url) {
-  if (!isAllowedHost(url)) throw new Error('blocked');
+  if (!isAllowedHost(url)) throw new Error('blocked');
+  const res = await fetch(url);
   return res.text();
 }
 `,
    }),
  },
  {
    category: "eval-injection",
    cwe: "CWE-95",
    harness: "injection",
    ext: "js",
    dir: "src/rules",
    positive: ({ name }) => ({
      fn: `apply_${name}`,
      diff: `@@ -15,7 +15,7 @@ export function apply_${name}(expr, ctx) {
-  return safeEval(expr, ctx);
+  return eval(expr);
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `apply_${name}`,
      diff: `@@ -15,7 +15,7 @@ export function apply_${name}(expr, ctx) {
-  return safeEval(expr, ctx);
+  return safeEval(expr, ctx);
 }
 `,
    }),
  },
  {
    category: "jwt-misuse",
    cwe: "CWE-347",
    harness: "authz",
    ext: "js",
    dir: "src/auth",
    positive: ({ name }) => ({
      fn: `verify_${name}`,
      diff: `@@ -28,7 +28,7 @@ export function verify_${name}(token) {
-  return jwt.verify(token, SECRET, { algorithms: ['HS256'] });
+  return jwt.decode(token);
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `verify_${name}`,
      diff: `@@ -28,7 +28,7 @@ export function verify_${name}(token) {
-  return jwt.verify(token, SECRET, { algorithms: ['HS256'] });
+  return jwt.verify(token, SECRET, { algorithms: ['HS256'] });
 }
 `,
    }),
  },
  {
    category: "command-injection",
    cwe: "CWE-78",
    harness: "injection",
    ext: "js",
    dir: "src/tools",
    positive: ({ name }) => ({
      fn: `convert_${name}`,
      diff: `@@ -9,7 +9,7 @@ export function convert_${name}(file) {
-  execFile('convert', [file, 'out.png']);
+  exec(\`convert \${file} out.png\`);
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `convert_${name}`,
      diff: `@@ -9,7 +9,7 @@ export function convert_${name}(file) {
-  execFile('convert', [file, 'out.png']);
+  execFile('convert', [file, 'out.png']);
 }
 `,
    }),
  },
  {
    category: "idor",
    cwe: "CWE-639",
    harness: "authz",
    ext: "js",
    dir: "src/api",
    positive: ({ name }) => ({
      fn: `get_${name}`,
      diff: `@@ -33,7 +33,7 @@ router.get('/${name}/:id', async (req, res) => {
-  const row = await db.getForUser(req.params.id, req.user.id);
+  const row = await db.get(req.params.id);
   res.json(row);
 });
 `,
    }),
    negative: ({ name }) => ({
      fn: `get_${name}`,
      diff: `@@ -33,7 +33,7 @@ router.get('/${name}/:id', async (req, res) => {
-  const row = await db.getForUser(req.params.id, req.user.id);
+  const row = await db.getForUser(req.params.id, req.user.id);
   res.json(row);
 });
 `,
    }),
  },
];

// --- TypeScript (distinct from JS where possible) ---
const TS_TEMPLATES: CaseTemplate[] = [
  {
    category: "xss",
    cwe: "CWE-79",
    harness: "injection",
    ext: "ts",
    dir: "src/components",
    positive: ({ name }) => ({
      fn: `Bio_${name}`,
      diff: `@@ -12,7 +12,7 @@ export function Bio_${name}({ html }: { html: string }) {
-  return <p>{html}</p>;
+  return <div dangerouslySetInnerHTML={{ __html: html }} />;
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `Bio_${name}`,
      diff: `@@ -12,7 +12,7 @@ export function Bio_${name}({ html }: { html: string }) {
-  return <p>{html}</p>;
+  return <p>{sanitizeHtml(html)}</p>;
 }
 `,
    }),
  },
  {
    category: "prototype-pollution",
    cwe: "CWE-1321",
    harness: "injection",
    ext: "ts",
    dir: "src/utils",
    positive: ({ name }) => ({
      fn: `deepMerge_${name}`,
      diff: `@@ -7,7 +7,7 @@ export function deepMerge_${name}<T extends object>(target: T, patch: Record<string, unknown>): T {
   for (const [k, v] of Object.entries(patch)) {
-    if (k in target) (target as any)[k] = v;
+    (target as any)[k] = v;
   }
   return target;
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `deepMerge_${name}`,
      diff: `@@ -7,7 +7,8 @@ export function deepMerge_${name}<T extends object>(target: T, patch: Record<string, unknown>): T {
   for (const [k, v] of Object.entries(patch)) {
-    if (k in target) (target as any)[k] = v;
+    if (k === '__proto__' || k === 'constructor') continue;
+    if (k in target) (target as any)[k] = v;
   }
   return target;
 }
 `,
    }),
  },
  {
    category: "sql-injection",
    cwe: "CWE-89",
    harness: "injection",
    ext: "ts",
    dir: "src/db",
    positive: ({ name }) => ({
      fn: `find_${name}`,
      diff: `@@ -16,7 +16,7 @@ export async function find_${name}(name: string) {
-  return db.query<User>('SELECT * FROM users WHERE name = $1', [name]);
+  return db.query<User>(\`SELECT * FROM users WHERE name = '\${name}'\`);
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `find_${name}`,
      diff: `@@ -16,7 +16,7 @@ export async function find_${name}(name: string) {
-  return db.query<User>('SELECT * FROM users WHERE name = $1', [name]);
+  return db.query<User>('SELECT * FROM users WHERE name = $1', [name]);
 }
 `,
    }),
  },
  {
    category: "ssrf",
    cwe: "CWE-918",
    harness: "injection",
    ext: "ts",
    dir: "src/preview",
    positive: ({ name }) => ({
      fn: `proxy_${name}`,
      diff: `@@ -20,7 +20,6 @@ export async function proxy_${name}(target: string): Promise<string> {
-  assertAllowedUrl(target);
   const res = await fetch(target);
   return res.text();
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `proxy_${name}`,
      diff: `@@ -20,7 +20,8 @@ export async function proxy_${name}(target: string): Promise<string> {
-  assertAllowedUrl(target);
+  assertAllowedUrl(target);
+  const res = await fetch(target);
   return res.text();
 }
 `,
    }),
  },
  {
    category: "type-assertion-bypass",
    cwe: "CWE-20",
    harness: "authz",
    ext: "ts",
    dir: "src/middleware",
    positive: ({ name }) => ({
      fn: `admin_${name}`,
      diff: `@@ -14,7 +14,7 @@ export function admin_${name}(req: Request, _res: Response, next: NextFunction) {
-  if (req.user?.role !== 'admin') return next(new ForbiddenError());
+  const u = req.user as AdminUser;
+  if (u.isAdmin) return next();
   return next(new ForbiddenError());
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `admin_${name}`,
      diff: `@@ -14,7 +14,7 @@ export function admin_${name}(req: Request, _res: Response, next: NextFunction) {
-  if (req.user?.role !== 'admin') return next(new ForbiddenError());
+  if (req.user?.role !== 'admin') return next(new ForbiddenError());
   return next();
 }
 `,
    }),
  },
  {
    category: "jwt-misuse",
    cwe: "CWE-347",
    harness: "authz",
    ext: "ts",
    dir: "src/auth",
    positive: ({ name }) => ({
      fn: `parse_${name}`,
      diff: `@@ -31,7 +31,7 @@ export function parse_${name}(token: string): JwtPayload {
-  return jwt.verify(token, secret, { algorithms: ['HS256'] }) as JwtPayload;
+  return jwt.decode(token) as JwtPayload;
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `parse_${name}`,
      diff: `@@ -31,7 +31,7 @@ export function parse_${name}(token: string): JwtPayload {
-  return jwt.verify(token, secret, { algorithms: ['HS256'] }) as JwtPayload;
+  return jwt.verify(token, secret, { algorithms: ['HS256'] }) as JwtPayload;
 }
 `,
    }),
  },
  {
    category: "path-traversal",
    cwe: "CWE-22",
    harness: "injection",
    ext: "ts",
    dir: "src/files",
    positive: ({ name }) => ({
      fn: `read_${name}`,
      diff: `@@ -25,7 +25,7 @@ export async function read_${name}(file: string): Promise<Buffer> {
-  const safe = path.join('/data', path.basename(file));
+  const safe = path.join('/data', file);
   return fs.readFile(safe);
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `read_${name}`,
      diff: `@@ -25,7 +25,8 @@ export async function read_${name}(file: string): Promise<Buffer> {
-  const safe = path.join('/data', path.basename(file));
+  const base = path.basename(file);
+  if (file.includes('..')) throw new Error('traversal');
+  const safe = path.join('/data', base);
   return fs.readFile(safe);
 }
 `,
    }),
  },
  {
    category: "hardcoded-secrets",
    cwe: "CWE-798",
    harness: "secrets",
    ext: "ts",
    dir: "src/config",
    positive: ({ name }) => ({
      fn: `config_${name}`,
      diff: `@@ -3,7 +3,7 @@ export const config = {
   port: 3000,
-  apiKey: process.env.API_KEY ?? '',
+  apiKey: 'sk_test_HARDCODED_KEY_IN_PR_DIFF_9e2f',
 } as const;
 `,
    }),
    negative: ({ name }) => ({
      fn: `config_${name}`,
      diff: `@@ -3,7 +3,7 @@ export const config = {
   port: 3000,
-  apiKey: process.env.API_KEY ?? '',
+  apiKey: process.env.API_KEY ?? '',
 } as const;
 `,
    }),
  },
];

export const TEMPLATE_BY_LANG: Record<Language, CaseTemplate[]> = {
  c: C_TEMPLATES,
  cpp: CPP_TEMPLATES,
  rust: RUST_TEMPLATES,
  python: PYTHON_TEMPLATES,
  javascript: JS_TEMPLATES,
  typescript: TS_TEMPLATES,
};

function generateForLanguage(lang: Language, casesPerLang: number): BenchmarkCase[] {
  const templates = TEMPLATE_BY_LANG[lang];
  const negativeTarget = Math.round(casesPerLang * 0.3);
  const positiveTarget = casesPerLang - negativeTarget;
  const posPerCat = Math.floor(positiveTarget / templates.length);
  const negPerCat = Math.floor(negativeTarget / templates.length);
  const cases: BenchmarkCase[] = [];
  let variant = 0;

  for (const tpl of templates) {
    for (let i = 0; i < posPerCat; i++) {
      cases.push(buildCase(lang, tpl, variant++, false));
    }
    for (let i = 0; i < negPerCat; i++) {
      cases.push(buildCase(lang, tpl, variant++, true));
    }
  }

  let idx = 0;
  while (cases.filter((c) => !c.negative).length < positiveTarget) {
    const tpl = templates[idx % templates.length]!;
    cases.push(buildCase(lang, tpl, variant++, false));
    idx++;
  }
  while (cases.filter((c) => c.negative).length < negativeTarget) {
    const tpl = templates[idx % templates.length]!;
    cases.push(buildCase(lang, tpl, variant++, true));
    idx++;
  }

  return cases.slice(0, casesPerLang);
}

export function generateCorpus(casesPerLang = 140): BenchmarkCase[] {
  const all: BenchmarkCase[] = [];
  for (const lang of LANGS) {
    all.push(...generateForLanguage(lang, casesPerLang));
  }
  const seen = new Set<string>();
  for (const c of all) {
    if (seen.has(c.id)) throw new Error(`duplicate id: ${c.id}`);
    seen.add(c.id);
  }
  return all;
}

export type TaxonomyRow = {
  language: Language;
  category: string;
  cwe?: string;
  positive: number;
  negative: number;
  total: number;
};

export function buildTaxonomy(cases: BenchmarkCase[]): TaxonomyRow[] {
  const map = new Map<string, TaxonomyRow>();
  for (const c of cases) {
    const key = `${c.language}:${c.category}`;
    const row =
      map.get(key) ??
      ({
        language: c.language,
        category: c.category,
        cwe: c.cwe,
        positive: 0,
        negative: 0,
        total: 0,
      } satisfies TaxonomyRow);
    if (c.negative) row.negative++;
    else row.positive++;
    row.total++;
    map.set(key, row);
  }
  return [...map.values()].sort(
    (a, b) => a.language.localeCompare(b.language) || a.category.localeCompare(b.category)
  );
}

function renderMarkdownDoc(cases: BenchmarkCase[], casesPerLang: number): string {
  const taxonomy = buildTaxonomy(cases);
  const byLang = Object.fromEntries(LANGS.map((l) => [l, 0])) as Record<Language, number>;
  for (const c of cases) byLang[c.language]++;

  const pos = cases.filter((c) => !c.negative).length;
  const neg = cases.filter((c) => c.negative).length;

  const tableRows = taxonomy
    .map(
      (r) =>
        `| ${r.language} | ${r.category} | ${r.cwe ?? "—"} | ${r.positive} | ${r.negative} | ${r.total} |`
    )
    .join("\n");

  return `# Multilanguage security benchmark corpus

Original minimal PR-style unified diffs for **li-sec-agent** model evaluation. Patterns are inspired by CWE Top 25 (2024), OWASP categories, OpenSSF CVE Benchmark (JS/TS commit-diff style), and CWE-Bench-Java *families* — **not** copied from GPL OWASP Benchmark Java sources.

## Scale

| Metric | Value |
|--------|------:|
| Total cases | ${cases.length} |
| Positive (vuln in diff) | ${pos} (${((pos / cases.length) * 100).toFixed(1)}%) |
| Negative (safe / false-positive probes) | ${neg} (${((neg / cases.length) * 100).toFixed(1)}%) |
| Languages | ${LANGS.join(", ")} |
| Target per language | ${casesPerLang} |

### Per-language counts

| Language | Cases |
|----------|------:|
${LANGS.map((l) => `| ${l} | ${byLang[l]} |`).join("\n")}

## Taxonomy (language × category)

| Language | Category | CWE | Positive | Negative | Total |
|----------|----------|-----|----------|----------|------:|
${tableRows}

## Harness fields

Each case in \`eval/benchmark-multilang.json\`:

- \`id\` — deterministic (\`{lang}-{category}-vuln|safe-{variant}\`)
- \`language\`, \`category\`, \`cwe\` — metadata for analysis
- \`file_path\`, \`diff\` — unified diff hunks (10–80 lines typical)
- \`expected\` — harness categories: \`injection\`, \`authz\`, \`secrets\`, \`crypto\`, \`config\`, \`dependency\`, \`other\`
- \`negative\` — \`true\` when the diff is safe (no finding expected)

## Regenerate

\`\`\`bash
npx tsx scripts/benchmarks/generate-multilang-corpus.ts
CASES_PER_LANG=167 npx tsx scripts/benchmarks/generate-multilang-corpus.ts  # ~1002 total
\`\`\`

## Run evaluation

\`\`\`bash
# Full multilang corpus (default path via env)
BENCHMARK_PATH=eval/benchmark-multilang.json npx tsx scripts/eval-models.ts

# Smoke (10 cases)
CASE_LIMIT=10 BENCHMARK_PATH=eval/benchmark-multilang.json npx tsx scripts/eval-models.ts

# Combined with legacy 18-case set
BENCHMARK_MODE=combined npx tsx scripts/eval-models.ts
\`\`\`

See also \`docs/OFFICIAL_EVAL_BENCHMARKS.md\` and \`docs/MODEL_EVAL.md\`.
`;
}

function main(): void {
  const casesPerLang = Number(process.env.CASES_PER_LANG ?? "140");
  const cases = generateCorpus(casesPerLang);
  const outPath = join(REPO_ROOT, "eval", "benchmark-multilang.json");
  const samplePath = join(REPO_ROOT, "eval", "benchmark-multilang.sample.json");
  const manifestPath = join(REPO_ROOT, "eval", "benchmark-multilang.manifest.json");
  const docPath = join(REPO_ROOT, "docs", "MULTILANG_BENCHMARK.md");

  const json = JSON.stringify(cases, null, 2);
  writeFileSync(outPath, json + "\n", "utf8");
  writeFileSync(samplePath, JSON.stringify(cases.slice(0, 100), null, 2) + "\n", "utf8");
  writeFileSync(docPath, renderMarkdownDoc(cases, casesPerLang) + "\n", "utf8");

  const taxonomy = buildTaxonomy(cases);
  const manifest = {
    version: 1,
    generatedAt: new Date().toISOString(),
    casesPerLang,
    totalCases: cases.length,
    positiveCases: cases.filter((c) => !c.negative).length,
    negativeCases: cases.filter((c) => c.negative).length,
    languages: LANGS,
    outputFile: "eval/benchmark-multilang.json",
    sampleFile: "eval/benchmark-multilang.sample.json",
    taxonomy,
  };
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");

  const sizeMb = Buffer.byteLength(json, "utf8") / (1024 * 1024);
  console.log(`Wrote ${cases.length} cases -> ${outPath} (${sizeMb.toFixed(2)} MB)`);
  console.log(`Wrote 100-case sample -> ${samplePath}`);
  console.log(`Wrote taxonomy doc -> ${docPath}`);

  const byLang = buildTaxonomy(cases).reduce(
    (acc, r) => {
      acc[r.language] = (acc[r.language] ?? 0) + r.total;
      return acc;
    },
    {} as Record<string, number>
  );
  console.log("Per language:", byLang);
}

if (process.argv[1]?.includes("generate-multilang-corpus")) {
  main();
}
