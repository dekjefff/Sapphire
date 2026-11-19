# Milestone 3 completion report

สถานะ: **ปิดครบ 100% ตามขอบเขตแผน**

Milestone นี้เพิ่ม safe ZIP intake, discovery contracts/scope policy, runner adapters สำหรับ HTTPX และ Katana, authenticated egress gateway, orchestration/persistence, route matching, API pagination/provenance และ dashboard สำหรับตรวจ coverage โดยทุก runtime request ถูกจำกัดเป็น GET ภายใต้ exact origin, pinned IP และ budget ฝั่งเซิร์ฟเวอร์

## หลักฐาน end-to-end

- Assessment: `b9f7bc25-f9d3-4f89-8a4c-4cf0cc35917c`
- ผลรวม: assessment `completed`, coverage `complete`, discovery `complete`
- Runs: source intake, Semgrep, Trivy, HTTPX และ Katana เป็น `completed/complete` ทั้งหมด
- Runtime evidence: 4 endpoints, 4 matches (`matched` 2, `runtime_only` 2, `source_only` 0, `unresolved` 0)
- Target ledger: `GET /` สองครั้ง, `GET /items/42`, `GET /vulnerable`; ไม่มี POST/PUT/PATCH/DELETE และไม่มี gateway denial event
- Provenance ของ endpoint มี tool version, adapter version, config hash, scope-policy hash, artifact ID และ raw pointer
- Cancellation assessment `ec3ebd85-8ba9-45f5-90de-60762e23042c`: สั่งยกเลิกขณะ HTTPX กำลังทำงาน ผลเป็น assessment/discovery `cancelled`, coverage `incomplete`, target ได้รับ request เพิ่ม 0 รายการ และ audit เรียง `discovery.started → job.cancel_requested → discovery.cancelled → assessment.cancelled`

## ช่องโหว่จริงที่ใช้ทดสอบ

ไฟล์ `test/fixtures/wp8/vulnerable-source/routes.js` มี `eval(req.query.input)` จริง เพื่อพิสูจน์ static detection แบบเดียวกับ issue ก่อนหน้า แต่ไฟล์นี้เป็น source-only fixture และไม่ถูก execute เป็น server เป้าหมาย ส่วน runtime target แยกเป็น `test/fixtures/wp8/compose-target.mjs` ซึ่งตอบข้อมูลคงที่และบันทึกเฉพาะ method/path

Semgrep ตรวจพบ `scanner-config.sapphire.javascript.eval` ระดับ high, CWE-95 ที่ `routes.js:7` พร้อม artifact และ raw pointer; Trivy จบสมบูรณ์โดยไม่พบ finding เพิ่ม

## Verification

- Node tests: **68 passed, 0 failed, 0 skipped** รวม intake, Windows junction จริง, contracts, runner/parser, gateway adversarial controls, pipeline, matching/API/UI contracts และ live Compose API/Postgres integration
- API TypeScript build: ผ่าน
- Web production build และ TypeScript: ผ่าน
- Docker Compose build/runtime health และ profile `discovery-test`: ผ่าน
- Live isolated HTTPX/Katana assessment: ผ่านครบ
- Live cancellation ของ active discovery run: ผ่านและให้ coverage `incomplete`
- `docker compose --profile discovery-test config --quiet`: ผ่าน
- `git diff --check`: ผ่าน (มีเฉพาะคำเตือน line-ending ของ Git บน Windows)

Full-repository Prettier check ยังรายงานไฟล์ baseline เดิมที่อยู่นอกการเปลี่ยนแปลง milestone; ไฟล์ UI ที่เพิ่ม/แก้สำหรับ Milestone 3 ผ่าน targeted formatting/build verification และไม่มีผลต่อ functional closure

## Work-package closure

| WP | ขอบเขต | ปิด |
|---|---|---:|
| WP1 | ZIP/local intake safety | 100% |
| WP2 | Contracts, migration, scope policy | 100% |
| WP3 | Pinned runner adapters and parsers | 100% |
| WP4 | Authenticated fail-closed gateway | 100% |
| WP5 | Queue, orchestration, persistence | 100% |
| WP6 | Route matching and API | 100% |
| WP7 | Dashboard and operator guidance | 100% |
| WP8 | Fixtures, adversarial tests and live E2E | 100% |

หมายเหตุ: การปิด 100% หมายถึง acceptance scope ของ Milestone 3 ไม่ใช่การรับรองว่า scanner ครอบคลุมช่องโหว่ทุกชนิดหรือพร้อม production deployment โดยไม่ต้องทำ environment-specific hardening เพิ่ม
