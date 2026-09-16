# Kế hoạch: Codex Security MCP App widget cho ChatGPT Web

## Tóm tắt

- Kiểu app: `interactive-decoupled MCP App`.
- Tạo **Security MCP App widget chạy bên trong ChatGPT Web**; giữ nguyên `control-panel-v2` local chỉ để quản trị/monitor bridge, tunnel, runtime và log.
- Security path chạy trực tiếp `codex-security` MCP bằng Node/Python, không qua `codex.exe app-server` cho phần Security.
- Chế độ zero-Codex-usage chỉ quảng bá `standard` và `chatgpt_deep`.
- `native_deep` không xuất hiện trong schema, `tools/list`, mô tả tool hoặc giao diện của V1.
- Security MCP là nguồn dữ liệu/trạng thái duy nhất; bridge đóng vai trò facade + định tuyến + kiểm tra quyền + idempotency + workflow guard; widget chỉ hiển thị/điều khiển.
- ChatGPT Web là bộ phân tích trong `standard` và `chatgpt_deep`; native Codex workers không được tạo ở hai mode này.

Đã xác nhận native app-only flow chạy được:

```text
open_codex_security_workspace
        ↓ workspace.id
submit_codex_security_setup(sessionId=workspace.id)
        ↓
start_codex_security_scan(sessionId=workspace.id)
        ↓ workspace.results.scanId
```

---

## 1. Direct Security MCP adapter

Tạo:

```text
H:\AI\Codex-app-tunnel\local-bridge\security_mcp.py
```

Adapter sẽ:

- Tìm đúng `server.mjs` của plugin `codex-security` đã cài và bundled `node.exe`.
- Chạy MCP server trực tiếp qua STDIO, không dùng shell và không gọi `codex.exe` cho Security path.
- Gắn tiến trình vào Windows Job Object để bridge đóng thì tiến trình con cũng dừng.
- Dùng môi trường đã làm sạch; chỉ đặt:
  - `CODEX_SECURITY_STATE_DIR`;
  - `CODEX_SECURITY_SCAN_ROOT`;
  - các biến hệ thống tối thiểu cần cho Node/Python chạy.
- Không truyền nguyên `env_vars` trong `.mcp.json` vì danh sách đó có thể chứa secret/API key.
- Dùng allowlist native tool cố định; không có proxy tùy ý dạng `call(server, tool, arguments)`.
- Không tự động replay mutation sau timeout.
- Retry mutation phải dùng cùng `request_id`, kiểm tra authoritative state từ Security MCP rồi mới quyết định trả scan cũ hay thực hiện tiếp.

State Security dùng:

```text
<existing state_dir>\security\
├── workbench-state
├── scans
└── bridge-journal
```

### Idempotency phải bền vững

Bridge phải lưu atomic mapping:

```text
request_id + payload_hash → scanId + status
```

Mapping này không chỉ giữ trong RAM. Nếu bridge chết sau khi Security MCP đã tạo scan nhưng trước khi response quay về widget, restart bridge vẫn phải nhận ra request đã được thực hiện và trả lại đúng `scanId`, không tạo scan thứ hai.

Yêu cầu:

- cùng `request_id` + cùng payload → trả lại scan cũ;
- cùng `request_id` + khác payload → từ chối;
- write journal theo kiểu atomic/transactional;
- không ghi handoff token, secret hoặc path nhạy cảm vào log.

---

## 2. Security Review Orchestrator cho ChatGPT Web

Không để ChatGPT tự suy đoán workflow chỉ từ câu “hãy quét repo”. Bridge/app phải có **workflow contract cố định** để mọi lần scan đều đi đúng chuỗi phase.

Có thể triển khai dưới dạng một skill/instruction nội bộ riêng, ví dụ `security-review`, hoặc instructions gắn với các facade tools. Dù dùng cách nào, workflow phải deterministic ở mức phase.

### Standard workflow

```text
preflight
  ↓
inventory + security boundaries
  ↓
threat model
  ↓
discovery (1 pass)
  ↓
validation
  ↓
attack-path analysis cho finding hợp lệ
  ↓
final findings + coverage
  ↓
complete
```

Đặc điểm:

- một discovery pass chính;
- chỉ source-backed findings;
- không kết luận từ tên file/regex đơn thuần;
- phải validate trước khi đưa finding vào final report;
- checkpoint sau mỗi phase.

### ChatGPT Deep workflow

`chatgpt_deep` **không phải native Codex Deep Scan**. Đây là nhiều vòng review do ChatGPT Web tự thực hiện.

```text
preflight
  ↓
inventory + security boundaries
  ↓
threat model
  ↓
Pass 1: attack surface / entry points / trust boundaries
  ↓
Pass 2: auth / authorization / secrets / data flow
  ↓
Pass 3: injection / file / process / network / unsafe execution / state handling
  ↓
deduplicate + merge candidates
  ↓
validation
  ↓
attack-path analysis
  ↓
final findings + coverage
  ↓
complete
```

Yêu cầu:

- các pass phải độc lập đủ để giảm bỏ sót, nhưng không tạo Codex worker;
- deduplicate trước validation;
- checkpoint authoritative state sau mỗi pass/phase;
- nếu chat bị ngắt, scan có thể tiếp tục từ phase gần nhất thay vì chạy lại từ đầu;
- bridge trả `nextPhase`/phase contract để ChatGPT biết bước tiếp theo, không dựa vào trí nhớ hội thoại.

### Workflow guard

Bridge phải từ chối:

- bỏ qua trực tiếp từ discovery sang complete khi chưa validation;
- ghi dữ liệu cho phase không khớp phase hiện tại;
- mutation vào scan đã `cancelled`, `failed` hoặc `completed`;
- tạo scan mới khi follow-up đang mang một `scanId` hợp lệ đang chạy.

---

## 3. Bridge API: facade nhỏ, không expose native lifecycle hàng loạt

Sửa:

- `H:\AI\Codex-app-tunnel\local-bridge\bridge.py`
- `H:\AI\Codex-app-tunnel\local-bridge\server.py`

### Public tools cho ChatGPT/Web widget

Giữ surface nhỏ và rõ nghĩa:

```text
show_security_scan_panel()
security_start_scan(review_mode, target, user_context?, request_id)
security_get_scan(scan_id? | request_id?)
security_continue_scan(scan_id)
security_commit_phase(scan_id, phase, <phase-specific fields>, request_id)
security_complete_scan(scan_id, request_id)
security_cancel_scan(scan_id, request_id)
security_list_findings(scan_id, ...)
security_export_findings(scan_id, format)
```

Không expose trực tiếp toàn bộ native lifecycle tools ra ChatGPT.

`security_start_scan` là app-only (`ui.visibility=["app"]`): model không thấy và không gọi tool này từ chat. Khi người dùng yêu cầu quét local project/folder trong chat, ChatGPT chỉ gọi `show_security_scan_panel`; sau click, model resolve request bằng `security_get_scan(request_id=...)`.

### `security_start_scan`

Hợp đồng cố định:

```json
{
  "review_mode": "standard | chatgpt_deep",
  "target": "codebase | changes",
  "user_context": "optional",
  "request_id": "required"
}
```

Kết quả bắt buộc:

```json
{
  "scanId": "UUID từ Security MCP",
  "reviewMode": "standard hoặc chatgpt_deep",
  "target": "codebase hoặc changes",
  "status": "running",
  "phase": "preflight",
  "nextPhase": "inventory",
  "updatedAt": "..."
}
```

Bridge phải lấy đúng:

```text
workspace.results.scanId
```

Nếu không có `scanId` hợp lệ thì trả lỗi và không báo đã bắt đầu scan.

### Mapping mode

- `standard` + `codebase` → native workspace mode `standard`.
- `standard` + `changes` → native workspace mode `diff`.
- `chatgpt_deep` + `codebase` → native workspace mode `standard`, ChatGPT Web chạy workflow nhiều pass ở trên.
- `chatgpt_deep` + `changes` → native workspace mode `diff`, ChatGPT Web chạy workflow nhiều pass ở trên.

Không truyền `model` hoặc `reasoningEffort` vào native app-only start.

### Target

- `codebase`: toàn bộ project cố định trong `project-path.txt`.
- `changes`: working tree hiện tại với `diffTarget.kind = "working_tree"`.
- Không cho ChatGPT/widget truyền arbitrary path.
- Nếu project không phải Git hoặc Security báo không hỗ trợ review changes thì khóa `changes`.

### `security_continue_scan`

Tool này đọc authoritative state và trả:

```text
scanId
status
currentPhase
nextPhase
phaseInstructions
coverageSoFar
findingCounts
resumeToken/opaque state nếu thực sự cần nội bộ
```

Không trả path nhạy cảm, handoff token hoặc internal secret.

ChatGPT phải dùng kết quả này để biết chính xác bước tiếp theo thay vì tự đoán.

### `security_commit_phase`

Đây là facade ghi checkpoint. Input phải là **discriminated union theo `phase`**, không có trường `payload` free-form.

Ví dụ các nhánh schema:

- `threat_model` → `threatModel`;
- `discovery` / deep pass → `candidates`, `coverage`;
- `validation` → `validations`;
- `attack_path` → `attackPaths`;
- `finalization` → `findings`, `coverage`.

Bridge tự map xuống native actions tương ứng như:

```text
security_update_scan_context
security_update_scan_progress
security_record_scan_draft
security_prepare_review_items
security_record_candidates
security_record_candidate_validations
security_record_attack_paths
security_set_finding_remediation
...
```

Các native action này là implementation detail và **không xuất hiện trong external `tools/list`**.

`start_codex_security_standard_scan`, `start_codex_security_deep_scan` và các action yêu cầu Codex thread/sandbox metadata không được expose ra ChatGPT Web.

---

## 4. Security MCP App widget trong ChatGPT

Tạo:

```text
H:\AI\Codex-app-tunnel\local-bridge\security_scan_panel.html
```

Đăng ký resource riêng:

```text
ui://local-bridge/security-scan-v1.html
```

### Phân biệt rõ hai UI

```text
Local Control Panel (`control-panel-v2`)
→ quản trị tunnel/runtime/log/bridge health

Security MCP App Widget (`security-scan-v1`)
→ chạy bên trong ChatGPT Web
→ tạo/quan sát/hủy Security scan
```

Không gọi cả hai là “panel” trong code/comment nếu dễ gây nhầm.

### Giao diện Security widget

> **Ghi chú thiết kế:** Security MCP App Widget phải có phong cách hình ảnh và ngôn ngữ thiết kế **nhất quán với panel hiện hữu `control-panel-v2`**. Ưu tiên tái sử dụng cùng hệ thống màu, typography, spacing, border radius, card, button, trạng thái, icon, mật độ thông tin và dark-mode treatment để người dùng cảm nhận đây là hai bề mặt của cùng một sản phẩm, không phải hai ứng dụng tách rời. Có thể mô phỏng bố cục của Codex Security native UI, nhưng không được đánh đổi tính nhất quán với giao diện bridge hiện hữu.

Mô phỏng ảnh tham khảo:

- “Lần quét mới”.
- Hai lựa chọn `Cơ sở mã` và `Thay đổi`.
- Thông tin repo/branch/commit ở chế độ chỉ đọc.
- Hai review mode:
  - `Standard`;
  - `ChatGPT Deep`.
- Không có model selector của Codex.
- Hiển thị “ChatGPT Web” là bộ phân tích hiện tại.
- Ô ngữ cảnh bổ sung, giới hạn kích thước.
- Nút `Bắt đầu quét`.
- Trạng thái phase/progress/finding count.
- Nút hủy khi scan đang chạy.

Widget dùng MCP Apps bridge trước:

- `ui/notifications/tool-result`;
- `tools/call`;
- `ui/message`.

`window.openai.callTool` và `window.openai.sendFollowUpMessage` chỉ là compatibility fallback.

### Widget state không phải persistence

Widget chỉ lưu state trình bày tạm thời:

```json
{
  "selectedMode": "...",
  "selectedTarget": "...",
  "scanId": "...",
  "requestId": "..."
}
```

Không coi `window.openai.widgetState`/iframe state là storage bền vững.

Khi widget được mở hoặc mở lại:

```text
show_security_scan_panel
        ↓
Security MCP authoritative state
        ↓
activeScan / latestScan / repo metadata
```

`show_security_scan_panel` phải trả ít nhất:

```text
repo metadata
supportedTargets
activeScan (nếu có)
latestScan (nếu có)
```

Status, findings, progress, completion luôn đọc lại từ Security MCP.

---

## 5. Luồng bắt buộc khi bấm “Bắt đầu quét”

```text
1. Widget tạo `request_id` và bộ arguments một lần.
2. Trong cùng lượt click, trước khi chờ response nào, widget dispatch song song:
   - `tools/call` → `security_start_scan` với bộ arguments đó;
   - `ui/message` với đúng `request_id` và bộ arguments đó.
3. `security_start_scan` là app-only; widget nhận `structuredContent.scanId` và lưu `scanId/requestId` cho UI.
4. ChatGPT không gọi/replay `security_start_scan`; ChatGPT dùng `security_get_scan(request_id)` để lấy cùng `scanId` authoritative từ request của widget.
5. ChatGPT gọi `security_continue_scan(scanId)` để lấy `nextPhase`.
6. ChatGPT thực hiện phase theo workflow contract.
7. ChatGPT checkpoint bằng `security_commit_phase(...)`.
8. Lặp continue → work → commit cho tới finalization.
9. ChatGPT gọi `security_complete_scan(scanId)`.
```

Nội dung `ui/message` phải được dispatch đồng bộ với cú click và có dạng tương đương:

```text
Người dùng vừa nhấn nút Bắt đầu quét trong Security MCP App.
Widget đã dispatch app-only security_start_scan với request_id=<request_id>.
Không gọi security_start_scan từ model. Hãy gọi security_get_scan(request_id=<request_id>), retry nếu còn pending, rồi tuân thủ workflow phase của bridge tới security_complete_scan.
Không dùng native Deep/Codex worker.
```

Nếu `ui/message` thất bại:

- Không tạo scan lần hai.
- Widget vẫn hiển thị scan đang chạy.
- Giữ nguyên `scanId` và `request_id`.
- Cho phép gửi lại message mà không gọi lại `security_start_scan`.
- Khi mở lại widget, lấy scan đang chạy từ server thay vì tin widget state cũ.

---

## 6. Cancel và terminal-state write guard

Khi bấm `Hủy`:

```text
Widget
  ↓
security_cancel_scan(scanId, request_id)
  ↓
Security MCP → status=cancelled
```

Không giả định thao tác này có thể ngay lập tức dừng một lượt reasoning ChatGPT đang chạy trong host.

Do đó bridge phải enforce:

```text
Nếu scan.status ∈ {cancelled, failed, completed}
→ từ chối mọi mutation tiếp theo
→ không nhận progress mới
→ không nhận candidate/finding mới
→ không cho complete lần nữa
```

Nếu một lượt ChatGPT cũ vẫn chạy sau khi người dùng hủy, các write tiếp theo phải nhận lỗi terminal-state rõ ràng và dừng workflow.

Cancel phải idempotent: gọi lại cùng request không tạo side effect mới.

---

## 7. Kiểm thử và cổng nghiệm thu

### Gate 1 — Direct MCP

- Khởi tạo Security MCP thành công.
- Internal `tools/list` nhận đủ native tools cần thiết.
- App-only sequence tạo được `workspace.id` và `workspace.results.scanId`.
- Standard/ChatGPT Deep không gọi `start_codex_security_deep_scan`.
- Standard/ChatGPT Deep không tạo `CodexSdkWorkerExecutor` hoặc native Codex model worker.
- Nếu có metric usage đáng tin cậy, xác nhận Codex usage không tăng trong Standard/ChatGPT Deep.
- Secret không xuất hiện trong môi trường/log.
- Plugin thiếu hoặc sai path thì fail-closed.

> Không dùng tiêu chí “không có `codex.exe` trong process tree” làm bằng chứng zero-Codex-usage, vì bridge có thể đang dùng Codex App Server cho các chức năng khác như đọc/search source.

### Gate 2 — Bridge contract

- `security_start_scan` trả `scanId` không rỗng.
- Retry cùng `request_id` + cùng payload trả scan cũ kể cả sau restart bridge.
- Retry cùng `request_id` + khác payload bị từ chối.
- Mode ngoài allowlist bị từ chối trước khi gọi native MCP.
- `native_deep` không xuất hiện trong external `tools/list`.
- Native lifecycle tool thấp tầng không xuất hiện trong external `tools/list`.
- Không trả `scanDir`, handoff token, sandbox metadata hoặc path nhạy cảm ra widget/model nếu không cần.
- `security_continue_scan` trả đúng `nextPhase` theo authoritative state.
- `security_commit_phase` từ chối phase sai thứ tự.
- Scan terminal từ chối mọi mutation.

### Gate 3 — Workflow

#### Standard

- Đi đúng chuỗi preflight → inventory → threat model → discovery → validation → attack path → finalization → complete.
- Không complete nếu chưa validation.
- Checkpoint tồn tại sau mỗi phase.
- Resume sau gián đoạn tiếp tục từ phase gần nhất.

#### ChatGPT Deep

- Chạy đủ 3 pass đã định nghĩa.
- Không tạo Codex workers.
- Deduplicate candidates trước validation.
- Checkpoint sau từng pass.
- Resume không chạy lại các pass đã commit thành công.

### Gate 4 — Widget

- Widget xuất hiện trong ChatGPT App iframe.
- `control-panel-v2` local vẫn hoạt động độc lập.
- Bấm Standard và ChatGPT Deep đều gọi đúng `security_start_scan`.
- `security_start_scan` chỉ callable từ widget sau click; model/chat không được gọi trực tiếp.
- Nút widget dispatch `security_start_scan` và `ui/message` trong cùng lượt click; `request_id`/arguments khớp tuyệt đối.
- ChatGPT tự tiếp tục từ kết quả `security_start_scan`; người dùng không cần gửi thêm lệnh trong chat.
- Polling cập nhật đúng authoritative scan.
- Mở lại widget lấy `activeScan/latestScan` từ Security MCP, không phụ thuộc widget state.
- Nút hủy không tạo scan mới.
- Sau khi hủy, write từ lượt ChatGPT cũ bị bridge từ chối.

### Gate 5 — ChatGPT Web thật

- Refresh app sau khi đổi tool/resource.
- Nếu host vẫn giữ resource hoặc behavior cũ sau khi refresh, remove/reinstall plugin MCP Bridge local trong ChatGPT Web, mở lại chat/widget rồi kiểm tra lại; đây là bước loại cache plugin/host, không thay đổi kiến trúc MCP.
- Text request “quét bảo mật thư mục local” chỉ gọi `show_security_scan_panel`; không gọi `security_start_scan` trước khi người dùng bấm nút.
- Sau khi người dùng bấm nút trong widget, `security_start_scan` được gọi app-only và ChatGPT dùng `security_get_scan(request_id=...)` để lấy scanId.
- Nút widget gửi message vào đúng phiên chat.
- ChatGPT tiếp tục dùng đúng `scanId`.
- ChatGPT gọi `security_continue_scan`/`security_commit_phase` theo workflow contract.
- Xác nhận end-to-end qua ChatGPT Web thật; `healthz/readyz` riêng lẻ không được tính là nghiệm thu connector.

---

## 8. Giả định đã khóa

- V1 là app private dùng tunnel/developer mode, không phải public submission.
- `standard` và `chatgpt_deep` dùng ChatGPT Web để reasoning; usage ChatGPT vẫn bị tính, Codex model usage không được dùng bởi Security workflow V1.
- Native Deep nằm ngoài V1 và chỉ có thể là profile riêng sau này, có cảnh báo usage rõ ràng và trust/sandbox contract hợp lệ.
- Không thêm repo dropdown; project vẫn lấy từ `project-path.txt`.
- Không cho widget/model truyền arbitrary repository path.
- Không sửa hoặc ghi đè các thay đổi đang có trong worktree ngoài các file được task triển khai cho phép.
- Security MCP là source of truth cho scan/status/findings/coverage.
- Widget state chỉ phục vụ presentation.
- Bridge facade chịu trách nhiệm workflow guard, idempotency và chống ghi vào terminal scan.
- Tài liệu triển khai bám theo OpenAI Apps SDK UI và OpenAI MCP server guidance.
