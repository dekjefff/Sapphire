# รายงานการดำเนินงาน Milestones 1–3

## การเรียกชื่อ

รายงานนี้ใช้ชื่อสามช่วงการส่งมอบตามที่ขอให้ตรวจทาน เอกสารแผนใน repository เริ่มนับจากศูนย์ จึงเรียกชื่อแตกต่างกันหนึ่งลำดับ:

| ช่วงสำหรับการตรวจทาน | งานส่งมอบบน GitHub | ชื่อในแผนของ repository | ผลลัพธ์ |
| --- | --- | --- | --- |
| 1. Foundation | PR #1 | Milestone 0 | โค้ดพื้นฐานและ Compose stack อยู่บน base branch แล้ว |
| 2. Source intake | Issue #2 | Milestone 1 | ดำเนินการใน worktree ปัจจุบันแล้ว |
| 3. Static tool pipeline | Issue #3 | Milestone 2 | ดำเนินการและตรวจ runtime ผ่าน test-only fixture แล้ว; ยังไม่ได้ประเมิน repository ของผู้ใช้หรือระบบ production |

## ช่วงที่ 1: Foundation / PR #1

Foundation ประกอบด้วย dashboard ที่ทำงานในเครื่อง, Fastify API, Postgres/Flyway schema, Redis-backed work queue, worker, audit events, สถานะการยกเลิก และขอบเขตเครือข่ายของ Compose การดำเนินงานนี้ต่อยอดจาก foundation ดังกล่าว พอร์ตของ web dashboard บนเครื่องยังคงเป็น `8080` (`127.0.0.1:8080:8080`)

## ช่วงที่ 2: Source intake / Issue #2

API รับ source path ภายใน workspace และ ZIP upload ที่มีขอบเขตจำกัด ระบบลบไฟล์ ZIP ที่ staging ไว้เมื่อเกิดข้อผิดพลาด ตรวจสอบ path และชนิดไฟล์ใน archive ก่อนแตกไฟล์ แปลง local path ให้อยู่ในรูป canonical ภายใต้ workspace root ที่กำหนด และ mount source แบบ read-only การ intake ใช้ Git commit identity หากหาได้ หรือคำนวณ content identity แบบ deterministic การดึง route ทำด้วย TypeScript AST แบบมีขอบเขต รองรับ route ของ Next.js และ route ของ Express/Fastify ที่เป็น literal โดยระบุหลักฐาน file/line ได้ ตัวแปร Router ของ Express เชื่อมโยงได้จาก import/export แบบ named/default, aliases, relative re-exports และสายการ mount ด้วย `app.use()` ที่ระบุ prefix เป็น literal รวมถึงชื่อตัวแปรใดก็ได้ ส่วน mount ที่เป็น dynamic หรือเชื่อมโยงไม่ได้จะแสดงเป็น warning และไม่เดา path ระบบข้าม generated/dependency directories ที่ระบุไว้อย่างชัดเจน และรายงานจำนวนที่ข้ามเพื่อให้ dashboard แสดง inventory ที่ไม่ครบถ้วน หากยกเลิกหลังการตรวจสอบ ระบบจะทิ้งผลตรวจสอบภายใน transaction ส่วน audit event สำหรับคำขอที่ถูกปฏิเสธจะบันทึก reason code ที่ sanitize แล้ว โดยไม่บันทึก path หรือ source content

## ช่วงที่ 3: Static pipeline / Issue #3

worker เรียก child tool run สองรายการที่ระบุและตรวจสอบย้อนหลังได้ โดยใช้ intake snapshot แบบ read-only เดียวกัน:

- Semgrep `1.185.0` ใช้ local rules ที่ดูแลใน repository และสร้างผลลัพธ์ JSON กับ SARIF
- Trivy `0.76.2` ใช้ filesystem vulnerability และ secret scanners แบบ offline (`vuln,secret`) พร้อม database cache ที่ provision ไว้ในเครื่อง

container `scanner-runner` แยกต่างหากไม่มี network interface รับ source และ Trivy cache ที่ mount แบบ read-only เรียกใช้ binary และ argument arrays ที่กำหนดตายตัวโดยไม่ใช้ shell จำกัดเวลา tool run ไว้ที่ 10 นาที จำกัด raw output ไว้ที่ 100 MiB และเขียน artifacts ลง task volume ที่แยกไว้ worker ตรวจสอบขนาดและ SHA-256 ของ artifact ก่อนจัดเก็บ raw JSON/SARIF และ metadata sidecar Trivy ต้องใช้ `db/metadata.json`; runner อ่านไฟล์โดยไม่ตาม symlink จำกัดขนาดไว้ที่ 16 KiB คำนวณ hash ของไฟล์ที่ใช้จริง และบันทึกเฉพาะ hash, schema version และ timestamp ที่ sanitize แล้วใน tool-run provenance PostgreSQL เก็บ tool/config/DB provenance, artifact references, normalized findings, duplicate groups และ audit events ผลของ Semgrep และ Trivy จะเก็บ source location เมื่อ tool รายงานมา และเชื่อมโยงกับ raw artifact pointer การ group ยังคงให้ตรวจดูข้อมูลต้นฉบับได้ หากไม่มีหรือ metadata ของ database ไม่ถูกต้อง, scanner ล้มเหลว, report ผิดรูปแบบหรือไม่สมบูรณ์, หมดเวลา, ถูกยกเลิก หรือเกิน output limit ระบบจะระบุ coverage ว่าไม่ครบ และจะไม่ตั้งสถานะ assessment เป็น `completed` ส่วน dashboard ยังตรวจสอบ run ได้แม้ scanner ไม่พบ finding หรือหยุดก่อนสร้าง artifact

scanner image ใช้ official images สำหรับ amd64 ที่ pin ไว้: Semgrep `1.185.0` (`sha256:67518c174185a2043fdbed16c70631b79209499b3671178e7194379b48295a0d`), Node `22.14.0` (`sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944`) และ Trivy `0.76.2` (`sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb`) ขั้นตอน build ของ image ตรวจสอบ runtime version ทั้งสามรายการ การ refresh database เป็นคำสั่งสำหรับ operator ที่เรียกผ่าน Compose profile `tool-db-maintenance`; ระหว่าง assessment จะไม่มีการดาวน์โหลด database หรือ rules ผ่าน network

การตรวจ runtime ใช้ test-only fixture ใน `samples/security-scan-fixture/` ผ่าน ZIP intake (5 files, 1,668 bytes) โดยไม่ execute fixture, install dependency หรือส่ง request ไปยัง target ผล assessment `5e1c2d4d-41c0-44a4-9ca9-616402818deb` เป็น `completed` และ coverage `complete` มี normalized finding 2 กลุ่ม: Semgrep rule `sapphire.javascript.eval` ที่ `unsafe-demo.js:3:10` (high) และ Trivy `CVE-2021-44906` สำหรับ `minimist@1.2.5` (critical) ทั้งสองกลุ่มเชื่อมกับ original finding, raw pointer และ artifact reference โดยแต่ละกลุ่มมี `duplicate_count=1`; การตรวจนี้จึงยังไม่ได้จำลองการรวม finding ซ้ำข้าม tool

Trivy รายงาน vulnerability finding จาก local database ที่ provision แล้ว (`db/metadata.json` SHA-256 `7e178eb413e43e9945772771877f2f5cd23626414198ed4665ab40c05e964478`, schema version `2`). Fixture มี public AWS example access key ID เท่านั้น ซึ่ง Trivy ไม่ได้รายงานเป็น secret; ไม่ได้ใช้ credential จริง

การลอง scan fixture เดียวกันผ่าน local path บน Windows/OneDrive ทำให้ Semgrep ค้างในสถานะ `running` นานประมาณ 4 นาที 35 วินาทีโดยไม่มี artifact แล้วถูกยกเลิก การส่งเนื้อหาเดียวกันผ่าน ZIP ทำงานสำเร็จใน Docker-managed intake volume พฤติกรรมของ local bind mount บน environment นี้ยังไม่ทราบสาเหตุแน่ชัด จึงเป็นข้อจำกัด runtime ที่ควรตรวจต่อ

### ตารางเทียบเกณฑ์การยอมรับของ Issue #3

| เกณฑ์การยอมรับ | การดำเนินการ |
| --- | --- |
| เรียก Semgrep และ Trivy ผ่าน runner ที่ควบคุมได้ | ใช้ `apps/api/src/scanner-runner.ts`, `apps/api/Dockerfile.scanner` และ Compose service `scanner-runner` ที่แยกเครือข่าย |
| เก็บ version, config hash และ raw artifact reference | ใช้ provenance columns ใน `tool_runs` และ `scan_artifacts` ใน migration V5; worker จัดเก็บ JSON/SARIF ที่ตรวจสอบแล้ว, Trivy DB metadata provenance ที่มีขอบเขต และ sidecar metadata |
| แปลงผลจากทั้งสอง tool เป็นรูปแบบกลางพร้อม source provenance | ใช้ `apps/api/src/normalize.ts`; normalized record เก็บ tool run, artifact ID, raw pointer, rule/CVE, source path/line, severity, confidence และ evidence |
| จัดกลุ่มรายการซ้ำโดยยังตรวจดูรายการต้นฉบับได้ | ใช้ `finding_groups` และ `normalized_findings`; assessment detail แสดงกลุ่มพร้อม original finding records |
| เมื่อเกิดข้อผิดพลาดต้องแสดง coverage ไม่ครบ ห้ามรายงานว่าสะอาด | worker กำหนด tool/assessment coverage เป็น `incomplete` และ assessment เป็น `failed` หาก scan หรือ parsing ล้มเหลว หรือไม่มี output ที่จำเป็น |
| Dashboard แสดง severity/confidence/location/rule/CVE/tool/version/evidence | Assessment detail API และ finding cards แสดง grouped records, original findings, provenance, evidence และ raw artifact links |
| Source เป็น read-only; ควบคุม commands และ network | ใช้ read-only source mounts, fixed command arrays, runner เฉพาะที่กำหนด `network_mode: none`, ขีดจำกัด resource/timeout/output และไม่เรียก target scripts, package installs, builds, tests หรือ requests |
| บันทึก audit เมื่อ tool run เริ่ม เสร็จ ล้มเหลว หรือถูกยกเลิก | worker เพิ่ม events `tool.started`, `tool.completed`, `tool.failed` และ `tool.cancelled` พร้อม metadata ที่ sanitize แล้ว |

## การตรวจสอบและข้อจำกัด

คำสั่งตรวจสอบที่ดำเนินการแล้ว:

- `npm run build` ใน `apps/api` — ผ่าน
- `npm run build` ใน `apps/web` — ผ่าน
- `docker compose config --quiet` — ผ่าน
- `docker compose build worker scanner-runner` — ผ่าน; image build ตรวจสอบ version ของ Node, Semgrep และ Trivy
- `docker compose up -d --build` — services เริ่มทำงาน; API health ตอบ `ok` สำหรับ API/PostgreSQL/Redis และ `scanner-runner` ทำงานโดยไม่มีการ restart
- Trivy DB maintenance profiles — provision local database จาก official GHCR repositories; runner อ่าน metadata แบบ read-only และบันทึก provenance
- Scanner assessment ผ่าน `POST /assessments/zip` ด้วย fixture ข้างต้น — Semgrep `1.185.0` และ Trivy `0.76.2` จบด้วย exit code `0`; artifacts เป็น `semgrep.json`, `semgrep.sarif` และ `trivy.json`; dashboard แสดง versions, config IDs/hash, Trivy DB provenance, findings, raw pointers และ artifact links
- ตรวจ API `GET /assessments/5e1c2d4d-41c0-44a4-9ca9-616402818deb` และ dashboard — แสดง assessment/coverage `completed`/`complete`, 2 finding groups และ artifacts ที่เก็บอยู่
- Local-path scanner run บน Windows/OneDrive ถูกยกเลิกหลังไม่มีความคืบหน้า; การรัน ZIP ที่มีเนื้อหาเดียวกันสำเร็จ
- `git diff --check` — ผ่าน; Git แสดงเฉพาะคำเตือนเรื่อง line-ending conversion ของ `apps/api/src/worker.ts`

ไม่ได้เพิ่มหรือรัน test suites; มีการรัน scanner assessment เฉพาะกับ fixture จำลองที่ระบุไว้ข้างต้นตามคำขอ validation เท่านั้น ขณะนี้ runtime stack ทำงานและ health check ผ่านแล้ว ขอบเขต Semgrep เป็น ruleset เริ่มต้นขนาดเล็ก Trivy ตรวจเฉพาะ vulnerabilities และ secrets และการ scan จะข้าม generated/dependency directories ที่ระบุไว้ ผล scan ที่ไม่พบ finding ไม่ควรถูกตีความว่าเป็นการประเมินความปลอดภัยที่ครอบคลุมทั้งหมด การตรวจนี้ไม่ได้ยืนยันผลกับ repository ของผู้ใช้หรือ production และยังต้องตรวจอาการ local-path บน Windows/OneDrive ต่อ
