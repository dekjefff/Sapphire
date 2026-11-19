# รายงานผล Issue #5 · ZAP runtime pipeline

วันที่ 2026-11-19 · [Sapphire Issue #5](https://github.com/dekjefff/Sapphire/issues/5) · [แผนตรวจรับ](MILESTONE_4_PLAN.md)

สถานะ **ผ่านการตรวจรับตามขอบเขตที่ปรับแล้ว** Sapphire วิเคราะห์ HAR แบบ passive และนำเข้ารายงานที่สร้างใน ZAP ภายนอกได้บน Docker

## ฟีเจอร์ที่ส่งมอบ

| ฟีเจอร์ | ใช้งานได้อย่างไร |
| --- | --- |
| แปลงรายงานในเครื่อง | CLI อ่าน ZAP Traditional JSON และ Traditional JSON with Requests and Responses ขนาดไม่เกิน 10 MiB แล้วส่งออกข้อมูลที่ผ่านการกรอง |
| ผูกรายงานกับ assessment | ส่งรายงานที่มีอยู่เข้า `POST /assessments/<id>/zap-report` หลังใช้ migration V7 ระบบเก็บผลที่รับล่าสุดของแต่ละ assessment การนำเข้าที่ล้มเหลวรักษาผลเดิม |
| ดูผลการนำเข้า | `GET /assessments/<id>` แสดง `missing` หรือ `imported` พร้อมเวอร์ชัน จำนวน findings และ coverage ถ้ารายงานระบุ errors หรือ warnings ของ Automation Framework จะมีรหัสสาเหตุโดยไม่เผยข้อความต้นฉบับ |
| ตรวจหลักฐาน | API แบ่งหน้ารายการ findings และ HTTP instances โดยมี revision ID, rule ID, severity, ตำแหน่งในรายงาน, HTTP method และ response status การเรียก instance ด้วย revision เก่าจะได้ HTTP 409 |

Sapphire เก็บเฉพาะผลที่กรองแล้ว ผู้ปฏิบัติงานเป็นคนเลือกว่าไฟล์จะผูกกับ assessment ใด ข้อมูลที่นำเข้าจึงเป็นหลักฐานที่ผู้ปฏิบัติงานส่งมา และ coverage ที่ไม่ทราบจะแสดงเป็น `unknown` แม้ไม่มี findings ฟีเจอร์นี้เปิดผ่าน API และ CLI

## การแบ่งงานและหลักฐานตรวจรับ

`gpt-6.1-terra` ระดับ `medium` รับผิดชอบการนำเข้ารายงาน การจัดเก็บ การแสดงผลผ่าน API การทดสอบ และเอกสารประกอบ โดยใช้ตัวแปลงออฟไลน์ที่มีจากรอบก่อน เอเจนต์หลักกำกับ ตรวจโค้ด รันทดสอบซ้ำ และทดสอบกับฐานข้อมูลจริงแยกต่างหาก

- Build API และชุดทดสอบ API ผ่าน **25/25** ทั้งรอบของเอเจนต์และรอบตรวจรับ
- Flyway อัปเกรด schema จาก V6 เป็น V7 บน PostgreSQL 16.6 ที่แยกจาก Compose เดิม โดยใช้ assessment ที่สร้างไว้ก่อนอัปเกรด
- ทดสอบผ่าน HTTP กับ API จริงและฐานข้อมูลจริง ครอบคลุมสถานะก่อนนำเข้า การแบ่งหน้า การรักษาผลเดิมหลังไฟล์เสีย การตอบ 409 เมื่อ revision เปลี่ยน และรายงานว่างที่มี coverage เป็น `unknown`
- ตรวจฐานข้อมูลและ API logs แล้วไม่พบค่าลับจำลองจากรายงาน ทดสอบยืนยันว่าไม่มี tool run ถูกสร้างจากการนำเข้า

## ผลตรวจ HTTP headers บน local benchmark

ตรวจ response ของ `GET /` หนึ่งครั้งจากภายในคอนเทนเนอร์ OWASP Juice Shop โดยใช้ HTTP ผ่าน loopback แบบไม่ล็อกอิน ได้สถานะ `200 OK` และ `Content-Type: text/html; charset=UTF-8` เก็บเฉพาะค่า headers ที่เลือกและสถานะการส่ง cookie ไม่เก็บ response body

| รายการตรวจ | ค่าที่พบ |
| --- | --- |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Content-Security-Policy` และ `Content-Security-Policy-Report-Only` | ไม่พบใน response |
| `Referrer-Policy` และ `Permissions-Policy` | ไม่พบใน response |
| `Set-Cookie` | ไม่พบใน response |

ผลนี้ครอบคลุม HTTP response ของหน้าแรกเพียงรายการเดียว รุ่นที่ทดสอบไม่ได้ส่งคำขอผ่าน TLS จึงไม่ได้ประเมิน HSTS ข้อสังเกตเรื่อง headers ใช้อ้างอิงจาก [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

ค้นหาแล้วไม่พบ ZAP report หรือ HTTP capture ของ session ที่ล็อกอินใน workspace รอบนี้จึงตรวจซ้ำส่วน CLI และ API import ด้วย fixture ผล build ผ่านและชุดทดสอบส่วน ZAP ผ่าน **10/10** ผลตรวจ headers และ fixture เป็นหลักฐานของขอบเขตที่ตรวจแล้ว ส่วนเกณฑ์ authenticated/passive ZAP benchmark ยังเปิดอยู่

## ผล benchmark หลังล็อกอินด้วย ZAP แบบ passive

ทดสอบ Juice Shop `v17.1.1` ในคอนเทนเนอร์ชั่วคราวที่ไม่มีเครือข่ายภายนอก ไม่มีพอร์ตที่เปิดให้ host และไม่มีข้อมูลจาก Compose เดิม ลงทะเบียนและล็อกอินด้วยบัญชีทดสอบผ่านการใช้งานปกติ แล้วเปรียบเทียบคำขออ่านตะกร้าของบัญชีเดียวกันก่อนและหลังล็อกอิน ผลคือ `401` และ `200` ตามลำดับ

นำ HTTP exchanges ที่ปกปิดแล้ว 3 รายการเข้า ZAP `2.17.0` จาก HAR แบบอ่านผลที่บันทึกไว้ ใช้ `sendRequests: false` และรัน ZAP ด้วย `--network none` จาก image digest `sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af` งาน import, passive scan และสร้างรายงานสำเร็จโดยไม่มี errors หรือ warnings ในรายงาน [ZAP HAR import](https://www.zaproxy.org/docs/desktop/addons/import-export/automation/) · [ZAP passive scan](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/)

| ZAP rule ID | Alert ที่รายงาน | Instances | จากคำขอหลังล็อกอิน |
| --- | --- | ---: | ---: |
| 10038 | Content Security Policy (CSP) Header Not Set | 2 | 0 |
| 10098 | Cross-Domain Misconfiguration | 2 | 1 |
| 10017 | Cross-Domain JavaScript Source File Inclusion | 2 | 0 |
| 10109 | Modern Web Application | 1 | 0 |

ทดสอบกับ Sapphire API และ PostgreSQL แยกโดยนำเข้ารายงานจริง ตรวจ assessment detail และเรียกหลักฐานแบบแบ่งหน้า ผลตรงกับ CLI ที่ **4 alerts และ 7 instances** ตรวจแล้วว่า PostgreSQL ไม่มี request/response ดิบหรือค่า token จาก HAR ส่วน coverage ใน Sapphire เป็น `unknown` ตามพฤติกรรมของรายงานที่ผู้นำเข้าส่งให้ระบบ

เก็บเฉพาะผลที่ผ่านการกรองในไฟล์ `artifacts/milestone-4-passive-benchmark.json` ของ workspace โดยมี SHA-256 `976BBF3024D123BF96FADB30D74B8268450361DB3C66CC82739476648930B2B4`

**ผลตรวจรับบางส่วน** ยืนยันเส้นทางจากทราฟฟิกหลังล็อกอินถึงผล ZAP และหลักฐานใน Sapphire แล้ว เกณฑ์เต็มยังเปิดเพราะ Sapphire ยังไม่มี runtime run ที่บันทึก authentication context, progress และ coverage จากการประมวลผลโดยตรง

## ผลตรวจรับบน Docker ที่ใช้ Auth.js

- Deploy API ล่าสุดแล้วและตรวจว่า assessment API ตอบ `401` หากไม่มี session ของ Sapphire
- บันทึก HAR 3 exchanges จาก Juice Shop `v17.1.1` โดยคำขออ่านตะกร้าตอบ `401` ก่อนล็อกอินและ `200` หลังล็อกอิน
- ZAP `2.17.0` ตรวจแบบ passive ในคอนเทนเนอร์ปิดเครือข่าย พบ 4 alerts รวม 7 instances ผลของ run `af18d9ca-88e0-498d-a507-372c8d8d85f1` นำเข้าผ่าน Auth.js และตรวจย้อนหลังได้จาก assessment และ API หลักฐาน
- ตรวจการนำเข้ารายงานภายนอกด้วย fixture และเทียบ SHA-256 ของไฟล์แล้ว ไฟล์เสียได้ `422` และ revision เดิมยังอยู่ ผลของ HAR แสดง authentication เป็น `unverified` และ coverage เป็น `unknown`
- API build ผ่านและเทสต์ผ่าน 25/25 ฐานข้อมูลเก็บเฉพาะข้อมูลที่ผ่านการกรอง

เก็บหลักฐานตรวจรับที่ผ่านการกรองในไฟล์ `artifacts/issue-5-passive-acceptance.json` ของ workspace หลังทดสอบลบบัญชีและ assessment ชั่วคราวแล้ว

## ผลตรวจรับ first-party capture

ทดสอบกับแอป first-party ชั่วคราวที่มี session ฝั่งเซิร์ฟเวอร์และรับคำขอ HTTP จริงใน Docker หน้า dashboard ตอบ `401` ก่อนล็อกอินและ `200` หลังล็อกอิน Runtime ตรวจ session ตอนเริ่มเก็บ จากนั้นบันทึกหน้า dashboard, profile และสองขั้นตอนของ flow เปิดรายการและดูรายละเอียด

Sapphire รับ HAR ที่ปกปิดข้อมูลพร้อม manifest ที่ลงนามและอ่านผลกลับจาก PostgreSQL ได้ ผลคือ `authentication: verified` (`authenticated`, role `user`), `coverage: known` (4 จาก 4 รายการ) และ progress `queued → running → completed` ตรวจแล้วไม่มีรหัสผ่าน ค่า cookie คีย์ลงนาม หรือ HAR ดิบในผลที่จัดเก็บ รอบนี้ตรวจเฉพาะการเก็บและนำเข้าหลักฐาน session ของแอป first-party ชั่วคราว

- Assessment `8e8f8c76-9173-4772-a0a0-cfd7552201f3`
- Run `4fa186e7-7bf4-480c-ac65-e3e97c5651a3`

## งานต่อยอด

การสำรวจเว็บสดผ่าน routes/OpenAPI การจัดการ session ของเว็บเป้าหมาย และการติดตาม live run เป็นขอบเขตงานถัดไป

ฝั่ง active scan ใช้รายงานจาก ZAP ภายนอก Sapphire และนำเข้าไปยัง assessment ผ่าน API เดิม รายงานที่รับได้มี rule ID, เวอร์ชัน, SHA-256 ของไฟล์ที่ส่ง และหลักฐานที่ผ่านการกรอง [วิธีนำเข้ารายงาน](../README.md#review-an-existing-zap-report)

Docker ในเครื่องใช้ schema V9 แล้ว โค้ดใน workspace ยังไม่ได้ push วิธีนำเข้า first-party capture อยู่ใน [คู่มือ](PASSIVE_EVIDENCE.md)
