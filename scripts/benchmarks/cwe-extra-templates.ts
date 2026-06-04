/**
 * Supplemental safe synthetic templates for backlog CWEs not in the main corpus.
 */

import type { CaseTemplate } from "./generate-multilang-corpus.js";

export const EXTRA_TEMPLATES: CaseTemplate[] = [
  {
    category: "oob-read",
    cwe: "CWE-125",
    harness: "injection",
    ext: "c",
    dir: "src/parse",
    positive: ({ name }) => ({
      fn: `read_${name}`,
      diff: `@@ -14,8 +14,7 @@ int read_${name}(const uint8_t *buf, size_t len, size_t idx) {
-  if (idx >= len) return -1;
-  return buf[idx];
+  return buf[idx];
 }`,
    }),
    negative: ({ name }) => ({
      fn: `read_${name}`,
      diff: `@@ -14,8 +14,9 @@ int read_${name}(const uint8_t *buf, size_t len, size_t idx) {
-  if (idx >= len) return -1;
-  return buf[idx];
+  if (idx >= len) return -1;
+  return (int)buf[idx];
 }`,
    }),
  },
  {
    category: "csrf",
    cwe: "CWE-352",
    harness: "authz",
    ext: "ts",
    dir: "src/api",
    positive: ({ name }) => ({
      fn: `transfer_${name}`,
      diff: `@@ -41,6 +41,7 @@ export async function transfer_${name}(req: Request) {
+export async function postTransfer_${name}(req: Request) {
+  await ledger.move(req.body);
+  return Response.json({ ok: true });
+}
 export async function transfer_${name}(req: Request) {`,
    }),
    negative: ({ name }) => ({
      fn: `transfer_${name}`,
      diff: `@@ -41,6 +41,8 @@ export async function transfer_${name}(req: Request) {
+export async function postTransfer_${name}(req: Request) {
+  assertSameOrigin(req);
+  await ledger.move(req.body);
+  return Response.json({ ok: true });
+}
 export async function transfer_${name}(req: Request) {`,
    }),
  },
  {
    category: "weak-crypto",
    cwe: "CWE-326",
    harness: "crypto",
    ext: "py",
    dir: "src/crypto",
    positive: ({ name }) => ({
      fn: `seal_${name}`,
      diff: `@@ -8,7 +8,7 @@ def seal_${name}(data: bytes) -> bytes:
-    return Fernet(key).encrypt(data)
+    return DES.new(key[:8], DES.MODE_ECB).encrypt(data)
 `,
    }),
    negative: ({ name }) => ({
      fn: `seal_${name}`,
      diff: `@@ -8,7 +8,7 @@ def seal_${name}(data: bytes) -> bytes:
-    return Fernet(key).encrypt(data)
+    return Fernet(key).encrypt(data)
 `,
    }),
  },
  {
    category: "broken-crypto",
    cwe: "CWE-327",
    harness: "crypto",
    ext: "ts",
    dir: "src/crypto",
    positive: ({ name }) => ({
      fn: `hash_${name}`,
      diff: `@@ -12,7 +12,7 @@ export function hash_${name}(input: string): string {
-  return createHash('sha256').update(input).digest('hex');
+  return createHash('md5').update(input).digest('hex');
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `hash_${name}`,
      diff: `@@ -12,7 +12,7 @@ export function hash_${name}(input: string): string {
-  return createHash('sha256').update(input).digest('hex');
+  return createHash('sha256').update(input).digest('hex');
 }
 `,
    }),
  },
  {
    category: "hardcoded-password",
    cwe: "CWE-259",
    harness: "secrets",
    ext: "py",
    dir: "src/auth",
    positive: ({ name }) => ({
      fn: `connect_${name}`,
      diff: `@@ -5,7 +5,7 @@ def connect_${name}():
-    password = os.environ.get("DB_PASSWORD")
+    password = "admin123_change_in_pr"
     return psycopg.connect(password=password)
 `,
    }),
    negative: ({ name }) => ({
      fn: `connect_${name}`,
      diff: `@@ -5,7 +5,7 @@ def connect_${name}():
-    password = os.environ.get("DB_PASSWORD")
+    password = os.environ.get("DB_PASSWORD")
     return psycopg.connect(password=password)
 `,
    }),
  },
  {
    category: "incorrect-authz",
    cwe: "CWE-863",
    harness: "authz",
    ext: "ts",
    dir: "src/routes",
    positive: ({ name }) => ({
      fn: `admin_${name}`,
      diff: `@@ -19,7 +19,7 @@ export function admin_${name}(req: Request) {
-  if (req.user.role !== 'admin') return deny();
+  if (req.user) return allow();
   return allow();
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `admin_${name}`,
      diff: `@@ -19,7 +19,7 @@ export function admin_${name}(req: Request) {
-  if (req.user.role !== 'admin') return deny();
+  if (req.user?.role !== 'admin') return deny();
   return allow();
 }
 `,
    }),
  },
  {
    category: "xxe",
    cwe: "CWE-611",
    harness: "injection",
    ext: "py",
    dir: "src/xml",
    positive: ({ name }) => ({
      fn: `parse_${name}`,
      diff: `@@ -6,7 +6,7 @@ def parse_${name}(raw: str):
-    return ET.fromstring(raw)
+    return ET.fromstring(raw, parser=ET.XMLParser(resolve_entities=True))
 `,
    }),
    negative: ({ name }) => ({
      fn: `parse_${name}`,
      diff: `@@ -6,7 +6,8 @@ def parse_${name}(raw: str):
-    return ET.fromstring(raw)
+    parser = ET.XMLParser(resolve_entities=False)
+    return ET.fromstring(raw, parser=parser)
 `,
    }),
  },
  {
    category: "open-redirect",
    cwe: "CWE-601",
    harness: "injection",
    ext: "js",
    dir: "src/auth",
    positive: ({ name }) => ({
      fn: `login_${name}`,
      diff: `@@ -22,7 +22,7 @@ export function login_${name}(req, res) {
-  const next = req.query.next || '/home';
+  const next = req.query.next;
   res.redirect(next);
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `login_${name}`,
      diff: `@@ -22,7 +22,8 @@ export function login_${name}(req, res) {
-  const next = req.query.next || '/home';
+  const next = safeRedirect(req.query.next);
+  if (!next) return res.status(400).end();
   res.redirect(next);
 }
 `,
    }),
  },
  {
    category: "redos",
    cwe: "CWE-1333",
    harness: "injection",
    ext: "js",
    dir: "src/validate",
    positive: ({ name }) => ({
      fn: `match_${name}`,
      diff: `@@ -11,7 +11,7 @@ export function match_${name}(input) {
-  return /^[a-z]+$/i.test(input);
+  return new RegExp('^(a+)+$').test(input);
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `match_${name}`,
      diff: `@@ -11,7 +11,7 @@ export function match_${name}(input) {
-  return /^[a-z]+$/i.test(input);
+  return /^[a-z]{1,64}$/i.test(input);
 }
 `,
    }),
  },
  {
    category: "improper-auth",
    cwe: "CWE-287",
    harness: "authz",
    ext: "ts",
    dir: "src/auth",
    positive: ({ name }) => ({
      fn: `session_${name}`,
      diff: `@@ -14,7 +14,6 @@ export function session_${name}(req: Request) {
-  if (!req.headers.get('authorization')) return unauthorized();
   return { userId: req.headers.get('x-user-id') };
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `session_${name}`,
      diff: `@@ -14,7 +14,8 @@ export function session_${name}(req: Request) {
-  if (!req.headers.get('authorization')) return unauthorized();
+  const token = req.headers.get('authorization');
+  if (!token || !verifyBearer(token)) return unauthorized();
   return { userId: req.headers.get('x-user-id') };
 }
 `,
    }),
  },
  {
    category: "missing-auth",
    cwe: "CWE-306",
    harness: "authz",
    ext: "py",
    dir: "src/api",
    positive: ({ name }) => ({
      fn: `reset_${name}`,
      diff: `@@ -21,6 +21,7 @@ def reset_${name}(user_id: str) -> None:
+@app.post("/admin/reset")
+def reset_${name}_handler(user_id: str) -> None:
+    store.wipe(user_id)
 `,
    }),
    negative: ({ name }) => ({
      fn: `reset_${name}`,
      diff: `@@ -21,6 +21,8 @@ def reset_${name}(user_id: str) -> None:
+@app.post("/admin/reset")
+def reset_${name}_handler(user_id: str, principal: Principal) -> None:
+    require_admin(principal)
+    store.wipe(user_id)
 `,
    }),
  },
  {
    category: "default-permissions",
    cwe: "CWE-276",
    harness: "config",
    ext: "py",
    dir: "src/fs",
    positive: ({ name }) => ({
      fn: `write_${name}`,
      diff: `@@ -7,7 +7,7 @@ def write_${name}(path: str, data: bytes) -> None:
-    os.chmod(path, 0o600)
+    os.chmod(path, 0o777)
     with open(path, "wb") as f:
         f.write(data)
 `,
    }),
    negative: ({ name }) => ({
      fn: `write_${name}`,
      diff: `@@ -7,7 +7,7 @@ def write_${name}(path: str, data: bytes) -> None:
-    os.chmod(path, 0o600)
+    os.chmod(path, 0o600)
     with open(path, "wb") as f:
         f.write(data)
 `,
    }),
  },
  {
    category: "resource-exhaustion",
    cwe: "CWE-770",
    harness: "config",
    ext: "ts",
    dir: "src/jobs",
    positive: ({ name }) => ({
      fn: `queue_${name}`,
      diff: `@@ -18,7 +18,6 @@ export function queue_${name}(items: unknown[]) {
-  const MAX = 10_000;
-  if (items.length > MAX) throw new Error('too many');
   for (const item of items) workers.push(item);
 }
 `,
    }),
    negative: ({ name }) => ({
      fn: `queue_${name}`,
      diff: `@@ -18,7 +18,8 @@ export function queue_${name}(items: unknown[]) {
-  const MAX = 10_000;
-  if (items.length > MAX) throw new Error('too many');
+  const MAX = 10_000;
+  if (items.length > MAX) throw new Error('too many');
   for (const item of items) workers.push(item);
 }
 `,
    }),
  },
  {
    category: "log-injection",
    cwe: "CWE-117",
    harness: "injection",
    ext: "py",
    dir: "src/log",
    positive: ({ name }) => ({
      fn: `audit_${name}`,
      diff: `@@ -9,7 +9,7 @@ def audit_${name}(user: str, action: str) -> None:
-    logger.info("user=%s action=%s", user, action)
+    logger.info(f"user={user} action={action}")
 `,
    }),
    negative: ({ name }) => ({
      fn: `audit_${name}`,
      diff: `@@ -9,7 +9,7 @@ def audit_${name}(user: str, action: str) -> None:
-    logger.info("user=%s action=%s", user, action)
+    logger.info("user=%s action=%s", user.replace("\\n", ""), action)
 `,
    }),
  },
];

/** When no direct template exists, borrow patterns from a related CWE. */
export const CWE_TEMPLATE_ALIAS: Record<string, string> = {
  "CWE-119": "CWE-787",
  "CWE-120": "CWE-787",
  "CWE-121": "CWE-787",
  "CWE-122": "CWE-787",
  "CWE-276": "CWE-862",
  "CWE-287": "CWE-639",
  "CWE-306": "CWE-862",
  "CWE-276": "CWE-22",
  "CWE-776": "CWE-611",
  "CWE-829": "CWE-95",
  "CWE-1336": "CWE-94",
  "CWE-209": "CWE-20",
  "CWE-532": "CWE-798",
  "CWE-770": "CWE-400",
  "CWE-400": "CWE-918",
  "CWE-732": "CWE-22",
  "CWE-693": "CWE-347",
  "CWE-704": "CWE-20",
  "CWE-434": "CWE-22",
};
