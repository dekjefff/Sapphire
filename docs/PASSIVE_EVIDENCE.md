# Passive first-party evidence

`apps/api/src/passive-evidence.ts` provides a recorder for first-party application instrumentation. Call `await capture.start(checkSession)` with a server-side callback that reads the application's session state. The callback can be asynchronous. Use a fixed role such as `user`, `admin`, or `service` when relevant. The resulting proof covers the session check at collection start and records its time, method, state, and associated inclusive request range.

Before starting, construct `PassiveEvidenceCapture(assessmentId, items)` on the instrumented server. Give each expected page or flow step a UUID and an optional static label, such as `/dashboard` or `View item details`. Flow steps also take a `flow_id` UUID. Use fixed route templates for labels and keep actual request data out of them. Start the recorder, pass exchanges already observed by the application to `observeRequest` in HAR order, and call `recordItem` for observed, failed, and skipped items. Observed items require a 1-based inclusive request range.

`capture.progress()` provides the run ID, state, counts and timestamped events. `remaining` counts pending items. `uncovered` counts every expected item that was not observed. Unrecorded items remain pending gaps. Pass the HAR to `capture.finish(har, key)` to create the signed bundle. Use `capture.finish(har, key, true)` for a failed run. If the initial session check fails, finish with an empty HAR to record the failed run without a verified session.

The recorder keeps the exchange method, response status, normalized start timestamp, and a keyed tag for its origin and path. The tag is different for each run. URLs, credentials, query parameters, headers, cookies, and bodies are stripped from the bundle. The tag and exchange metadata bind the signed manifest to the ordered sanitized capture. Keep the key on the instrumented server and the Sapphire API under server-side secret management. Clients should receive only the redacted bundle produced by `finish`.

Record exchange start times on the same clock as the recorder, after the session check completes.

## Import and read back

To import through the web app, open the assessment card, expand **Import passive capture**, and choose the JSON bundle produced by `finish`. The card shows the latest stored capture when opened again.

Apply migration `V9__passive_capture_evidence.sql` and set `PASSIVE_CAPTURE_KEY_HEX` for the Sapphire API to the same 32-byte key, encoded as 64 hexadecimal characters. The recorder receives the equivalent bytes. Send the redacted output of `finish` as a JSON POST to `/assessments/<assessment-id>/passive-captures`. Its signed scope must match the assessment ID. Sapphire retains only the accepted report metadata and permits identical retries for a given run.

Read the stored result at `GET /assessments/<assessment-id>/passive-captures/<run-id>`. The report includes authentication evidence, observed items and gaps, and the recorded progress events for signed runs. Coverage is `known` when the plan has at least one recorded outcome. A HAR-only import is `unverified` and `unknown`. An unsigned submission may include `assertion: "authenticated"` or `assertion: "anonymous"` to record an `asserted` claim. Sapphire rejects an invalid or mismatched signed bundle. The existing Issue #5 ZAP import remains a separate evidence source.
