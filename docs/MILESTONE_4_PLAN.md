# แผนและผลการส่งมอบ Milestone 4

วันที่ 2026-11-19 · [Sapphire Issue #5](https://github.com/dekjefff/Sapphire/issues/5)

Issue #5 ขอให้ Sapphire รองรับ runtime assessment ผ่าน ZAP พร้อมการควบคุมการรันและหลักฐาน HTTP ส่วนที่ส่งมอบแล้วคือ CLI และ API สำหรับอ่านและกรองรายงาน ZAP แบบออฟไลน์ แผนด้านล่างระบุลำดับงานและหลักฐานที่ต้องมีก่อนปิด Issue

## แบ่งงาน

| ผู้รับผิดชอบ | งาน | เกณฑ์ตรวจรับ |
| --- | --- | --- |
| เอเจนต์ gpt-6.2-sol ระดับ high | สร้างตัวแปลงรายงาน ZAP รุ่นเริ่มต้น | ตรวจโครงสร้าง จำกัดจำนวนข้อมูล ผูก finding กับ rule ID และเวอร์ชัน ZAP เก็บเฉพาะข้อมูล HTTP ที่กำหนด |
| เอเจนต์หลัก | สร้าง CLI และการทดสอบรุ่นเริ่มต้น กำกับงาน และตรวจสอบผลขั้นสุดท้ายอย่างอิสระ | อ่านไฟล์ จำกัดขนาด และตรวจผลลัพธ์ |
| เอเจนต์ gpt-6.1-terra ระดับ medium | รับผิดชอบงานออฟไลน์ทั้งหมดต่อ ตรวจเทียบ template ต้นทาง ปรับ CLI เพิ่มการทดสอบ และปรับเอกสาร | ตรวจกรณีข้อมูลว่างหรือผิดรูปแบบ ขีดจำกัดรวม การปกปิดหลักฐาน และสถานะ coverage |

เริ่มพัฒนาด้วย gpt-6.2-sol ระดับ high เพราะ gpt-luna-6-high ไม่มีในรายการโมเดลสำหรับเอเจนต์ย่อย จากนั้น gpt-6.1-terra ระดับ medium รับผิดชอบงานออฟไลน์ทั้งหมดต่อตามที่ผู้ใช้เลือก โดยเอเจนต์หลักกำกับและตรวจสอบขั้นสุดท้ายอย่างอิสระ ทั้งสองรอบ build API ผ่านและทดสอบ API ผ่าน 23 จาก 23 รายการ

## วิธีใช้

จากรากของ Sapphire ให้ build API แล้วเรียก CLI กับไฟล์ Traditional JSON ที่มีอยู่ รองรับรายงานแบบรวม request และ response ด้วย [Traditional JSON](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/) · [Traditional JSON with Requests and Responses](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json-plus/)

```powershell
npm.cmd --prefix apps/api run build
node apps/api/dist/zap-report-cli.js .\report.json
```

CLI ส่ง JSON ที่ผ่านการกรองออกทาง stdout และรับไฟล์ปกติขนาดไม่เกิน 10 MiB บน Windows จะปฏิเสธพาธ UNC และ device โดยตรง แต่ mapped drive และ symlink อาจชี้ไปยังที่เก็บระยะไกลได้ ผู้ใช้ควรส่งไฟล์ในเครื่อง หากไฟล์อ่านไม่ได้ ใหญ่เกิน หรือผิดรูปแบบ จะส่งรหัสข้อผิดพลาดทาง stderr และคืน exit code ที่ไม่เป็นศูนย์

แต่ละ finding มี rule ID, severity และตัวชี้ตำแหน่งใน JSON ต้นฉบับ ส่วนหลักฐานราย instance มี HTTP method และ response status เท่าที่อ่านได้ ข้อมูลที่คงไว้จึงใช้เชื่อม finding กลับไปยังรายงานต้นฉบับได้โดยไม่ใส่ URL, headers, cookies, bodies หรือข้อความหลักฐานดิบลงใน JSON ที่แปลงแล้ว

Coverage จากไฟล์รายงานมีสถานะ `unknown` หรือ `incomplete` เมื่อ `afPlanErrors` หรือ `afPlanWarns` ของ Automation Framework มีรายการ พร้อมรหัสสาเหตุที่ไม่เปิดเผยข้อความต้นฉบับ CLI ยังไม่ได้ตีความ diagnostics จากส่วนอื่นของรายงาน สถานะสำเร็จของ CLI หมายถึงแปลงรายงานได้ บางรายงานอาจไม่มี findings และยังไม่ทราบความครอบคลุมของการประเมิน

หลังใช้ migration V8 สามารถส่งรายงานที่สร้างใน ZAP เข้า `POST /assessments/<id>/zap-report` ด้วย `Content-Type: application/json` และ body ขนาดไม่เกิน 10 MiB ระบบเก็บผลที่กรองแล้วและ SHA-256 ของไฟล์ที่ส่ง ผู้ปฏิบัติงานเลือก assessment เอง การนำเข้าที่ล้มเหลวรักษาผลเดิมไว้ รายละเอียด assessment แยก `missing` จาก `imported` พร้อม coverage และรหัส diagnostics [วิธีนำเข้าและอ่าน findings](../README.md#review-an-existing-zap-report)

## ขอบเขต Issue #5 ที่ปรับแล้ว

Sapphire ใช้ ZAP วิเคราะห์ HTTP exchanges ที่บันทึกไว้ใน HAR ผ่าน CLI แล้วนำรายงานเข้า assessment ฝั่ง active scan รับรายงานที่สร้างจาก ZAP ภายนอกผ่าน API เดิม การสำรวจเว็บสดและการจัดการ session ของเว็บเป้าหมายเป็นงานต่อยอดจาก milestone นี้

| สิ่งส่งมอบ | เกณฑ์ตรวจรับ |
| --- | --- |
| Passive scan จาก HAR | ใช้ ZAP image ที่ตรึงด้วย digest ในคอนเทนเนอร์ที่ปิดเครือข่าย อ่านคำตอบที่บันทึกไว้โดยไม่ส่งคำขอซ้ำ จำกัด HAR ไม่เกิน 10 MiB และ 200 exchanges |
| ระบุผลของ run และขอบเขตข้อมูล | CLI แสดงรหัส run ระหว่างวิเคราะห์และนำเข้า ส่วน assessment แสดงรหัส run จำนวน exchanges และ origins จาก HAR ค่า authentication และ coverage สะท้อนข้อมูลที่ยืนยันได้ |
| นำเข้ารายงาน ZAP จากภายนอก | รับ Traditional JSON และ Traditional JSON with Requests and Responses ผูกกับ assessment โดยเก็บ rule ID, ZAP version, SHA-256 ของรายงาน และหลักฐานที่ปกปิดแล้ว |
| จัดการการนำเข้าที่ล้มเหลว | API ปฏิเสธ JSON ผิดรูปแบบหรือข้อมูล capture ผิดเงื่อนไข พร้อมรักษารายงานฉบับที่บันทึกไว้ก่อนหน้า |

### เกณฑ์ตัดสินก่อนปิด

ตรวจรับบน Docker ที่เปิด Auth.js โดยใช้ HAR จาก Juice Shop ในเครื่องที่มีคำขอเดียวกันก่อนและหลังล็อกอินเป็นหลักฐาน นำผลจาก ZAP เข้า assessment และตรวจรหัส run, coverage, rule ID และหลักฐาน HTTP ผ่าน API ตรวจด้วยว่ารายงาน ZAP จากภายนอกนำเข้าได้ และไฟล์ที่ผิดรูปแบบไม่แทนที่ผลที่บันทึกไว้
