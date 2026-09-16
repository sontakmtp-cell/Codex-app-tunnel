# Nghiệm thu Plan-remake-tunnel.md — 2026-09-15

**Chưa đạt toàn bộ kế hoạch.** Đã triển khai các nhóm A–F và kiểm tra được phần đọc/sửa/hoàn tác, MCP Docs, skills, lịch sử theo project và UI local. Sau khi đổi allowlist không chồng lấn và reload tunnel, doctor live cùng task bảo vệ thật đã đạt; vẫn còn gate riêng của MCP child và kiểm tra task từ ChatGPT.

## Bằng chứng hiện có

| Yêu cầu | Kết quả và bằng chứng |
|---|---|
| A — App Server riêng, ẩn, STDIO lâu dài, request ID và notification | **Đạt:** `runtime.py`, `windows_job.py`; [runtime-result.json](.verification/runtime-result.json) xác nhận initialize, filesystem và watch thật. Đây là Codex App Server nội bộ, độc lập với MCP server ngoài. |
| A — không sinh code/review, không shell/API tùy ý trong Normal, không tự replay/restart | **Đạt trong Normal:** danh sách API cố định không có `turn/start`, `review/start`, resume hay chuyển tiếp tùy ý; self-test kiểm tra điều này. Task mất kết nối giữ trạng thái lỗi và ID. Turbo là ngoại lệ có chủ ý, chỉ mở sau xác nhận trong panel. |
| A — kiểm tra phiên bản, schema và quyền thực tế | **Đạt live sau reload:** doctor báo `codex-cli 0.153.0`, `connected`, `commands_enabled=true`; canary xác nhận `outside_blocked=false`, `network_blocked=false`, `key_absent=true`. Root mẫu ngoài project là `H:/AI/Codex-app-tunnel`, không chồng với project test `H:/AI/autolab`. |
| B — preview nhiều file, SHA, exact patch, lưu SQLite ngoài project | **Đạt:** [self-test.log](.verification/self-test.log), 22 bài qua; preview không ghi, apply đúng bản đã chuẩn bị, SHA sai/patch mơ hồ bị từ chối. |
| B — hoàn tác cả đợt, bảo vệ sửa ngoài bridge, tạo file rồi gỡ đúng file | **Đạt:** bài nhiều file có nội dung có sẵn, từ chối cả đợt khi một file xung đột; kiểm tra nút Apply/Undo thật trên ChatGPT. |
| B — lỗi giữa đợt, khởi động lại, phục hồi theo SHA | **Đạt:** giả lập lỗi và ngắt giữa apply/undo; theo dõi file pending/writing/written; không phục hồi nhầm file chưa từng ghi. File bị sửa ngoài bridge được giữ lại và khóa ghi tiếp khi có xung đột. |
| B — giữ 30 đợt hoàn tất, không dọn lỗi, không sửa Git index | **Đạt:** mặc định 30; bài retention dùng giới hạn nhỏ để chứng minh cùng cơ chế. Bài Git trên project mẫu đối chiếu byte của index. Không có Git reset/clean trong cơ chế hoàn tác. |
| C — đọc khoảng dòng, toàn bộ SHA, UTF-8/CRLF, đường dẫn có khoảng trắng | **Đạt:** self-test so byte, dòng, hash; đọc API App Server thật trên project mẫu có khoảng trắng. |
| C — rg và Git diff dùng bộ lọc nhạy cảm | **Đạt qua App Server thật:** Git lấy tên từ index, helper chỉ truyền các đường dẫn không bị policy chặn vào `git diff --check`; `.env` và file nhạy cảm không bị mở. |
| D — start nhanh, log từng phần, thành công/thất bại/timeout, ID ổn định, một task, khóa ghi | **Đạt qua App Server thật:** `verify_runtime.py` đã chạy task Git, success/failure, timeout, replay, khóa ghi và dừng tiến trình con trên Windows. |
| D — Dừng cả tiến trình con, không dừng chương trình ngoài bridge | **Đạt Windows Job Object dự phòng thật:** self-test tạo cha/con và tiến trình đối chứng, đóng đúng nhóm riêng. **Chưa xác nhận `command/exec/terminate` và nút Dừng trên ChatGPT với task được bảo vệ.** |
| D — Normal/Turbo, Bash và quyền runtime | **Đã có code/test contract:** Normal mặc định giữ `permissionProfile=bridge`; panel yêu cầu xác nhận Turbo; Turbo dùng `sandboxPolicy={type:"dangerFullAccess"}` theo từng lệnh và `run_bash` dùng Git Bash thật. Chưa coi đây là nghiệm thu live cho tới khi reload tunnel và bật thử trong ChatGPT. |
| E — chỉ hai Docs MCP, không mở model turn, tắt MCP/plugin khác riêng cho child | **Chưa đạt:** search/fetch Docs thật đã qua, nhưng `mcpServerStatus/list` còn thấy `codex-security` và `openai-api-key-local-confirmation` ngoài `openaiDeveloperDocs`. Không nới policy để che lỗi này. |
| E — đọc skill đã tìm, giới hạn thư mục, không chạy script | **Đạt:** discovery/read thật; kiểm thử từ chối đường dẫn tham chiếu thoát thư mục và ID tự bịa. |
| E — chỉ đọc hội thoại đúng project, không tiếp tục/sửa | **Đạt phạm vi kiểm tra:** request list có cwd, lọc kết quả, đọc metadata kiểm tra cwd trước khi lấy nội dung; giới hạn văn bản user/assistant và bỏ output riêng tư. Live project mẫu trả danh sách rỗng đúng phạm vi. |
| F — MCP Apps UI, bốn tab React/Vite, diff theo file, Apply/Undo thật | **Đạt local; cần xác nhận live sau khi restart tunnel:** `panel.html` là resource tự chứa được build từ `H:/AI/panel-new`; `test_ui.cjs` chạy MCP `2026-07-28`, Chromium, chuyển tab Runtime/Changes/Tasks/Workspace, diff/apply/undo và XSS. ChatGPT vẫn dùng đúng `ui://local-bridge/control-panel-v2.html`; cần làm mới app để bỏ resource cache. |
| F — không mở lại bảng khi đọc dữ liệu, polling 2 giây khi thấy task chạy | **Đạt cấu trúc/logic và mở lại panel live;** polling/task thật trên ChatGPT chưa chạy đến cuối, nhưng nút `Chạy` đã được mở sau doctor. `show_control_panel` và `show_security_scan_panel` dùng hai resource UI riêng; data tools chỉ cập nhật bề mặt đang mở. |
| F — text an toàn, không thực thi HTML từ project | **Đạt kiểm thử Chromium với MCP server thật và host mẫu:** `test_ui.cjs`, [ảnh kiểm thử](../output/playwright/control-panel-applied.png). Bài này dùng file chứa HTML và xác nhận không tạo thẻ ảnh/thực thi script. |
| Tương thích sáu tool cũ | **Đạt:** [legacy-signatures.json](.verification/legacy-signatures.json) đối chiếu bản gốc; chỉ `read_file` thêm `end_line`. Write/patch cũ cùng journal; run_task cũ cùng runner. |
| Chống gửi lại yêu cầu và mất kết nối qua tunnel | **Đạt với đợt sửa:** bảng tải lại sau tunnel ngắt, vẫn thấy đợt pending; gửi lại đúng hai ID Apply/Undo sau hoàn tác đều trả `undone`, không tạo lại file. |
| Chặn đường dẫn, ADS, junction/symlink/hardlink và file nhạy cảm | **Đạt kiểm thử lớp file:** gồm junction và hardlink thật trên Windows, file nhị phân, đường dẫn thoát project; task Git thật cũng bỏ qua file bị policy chặn. |
| PowerShell 5.1, tunnel doctor, healthz/readyz, không ảnh hưởng tunnel khác | **Đạt:** script chạy thật bằng 5.1; tunnel doctor, bridge doctor và hai endpoint đã đạt. Đối chiếu SHA xác nhận config coding và file Blender/SolidWorks giữ nguyên. |
| Đổi project và task không sửa `config.json` mỗi lần | **Đạt local:** `project-path.txt` là selector một dòng; profile ngoài project trong `project-profiles/` được chọn theo `workspace_root`; `${PROJECT_ROOT}` được mở rộng cho task/runtime roots; runtime root token thiếu được bỏ qua; `-ProjectPath` hỗ trợ đổi tạm. Fingerprint có cả đường dẫn project để lần chạy kế tiếp nhận ra đổi; `autolab` chỉ là fixture kiểm thử. |

## Lượt kiểm thử ChatGPT thật

Đợt `24fcefea43d141c3a96130aeef14ec32` chỉ chứa file mới `bridge-ui-check-20260913.txt`. Preview chưa tạo file; nút Apply tạo đúng từng byte đã lưu trong bản xem trước; nút Undo gỡ file. Sau gửi lại request ID cũ, SQLite vẫn là `undone` và file vẫn không tồn tại. Cả 7 file có sẵn giữ nguyên SHA.

ChatGPT chuẩn bị nội dung dùng LF trong lượt này; bridge ghi đúng LF đã nhận. Khả năng giữ CRLF được xác nhận riêng bằng self-test so từng byte, không suy ra từ ảnh diff.

Khi kiểm tra quyền, Windows từng tự tạo `.git` rỗng do profile khai báo đường dẫn đọc chưa tồn tại. Đã sửa profile chỉ thêm `.git` khi là repo có metadata; nhận diện project không còn coi thư mục rỗng là repo. Chỉ thư mục rỗng có timestamp đúng lần kiểm tra được gỡ, không xóa dữ liệu Git có sẵn.

## Policy gate sau khi đổi kiến trúc

Policy Normal phải đạt đồng thời: `outside_blocked=false` qua `external_read_roots`, `network_blocked=false` qua egress ngoài, `key_absent=true`, và quyền ghi chỉ còn project/cache. Doctor live sau reload đã đạt cả ba canary; `verify_runtime.py` cũng ghi nhận `commands_enabled=true`. Turbo không làm yếu canary Normal; nó là policy full-access riêng do người dùng bật.

Chưa được công nhận đạt:

- Bảng ChatGPT theo dõi và Dừng một task thật.
- `mcpServerStatus/list` chỉ còn hai tool Docs được duyệt; hiện vẫn còn hai MCP child ngoài danh sách.

Không hạ Codex hoặc bỏ canary Normal để làm kết quả xanh. Turbo chỉ được bật qua xác nhận rõ ràng vì full-access có thể sửa/xóa dữ liệu ngoài project. `verify_runtime.py` đã đạt canary, filesystem, watch, skills, history, Docs, privacy/index và toàn bộ nhóm task App Server; gate MCP child dư vẫn còn.

## Bước tiếp theo

Đã reload tunnel để child Codex nhận profile mới, chạy lại doctor và kiểm tra task App Server thật. Bước còn lại là xử lý MCP child dư và kiểm tra nút Chạy/Dừng từ ChatGPT; nếu canary đọc ngoài hoặc egress thất bại ở project tương lai, bridge vẫn khóa task.

Khi doctor đạt, vào Settings → Apps → Codex app → Làm mới để host bỏ resource cache cũ, rồi kiểm tra `show_control_panel` trong tunnel. Chi tiết cách chạy và dùng bridge nằm trong [README.md](README.md).

## Security MCP V1 theo `PLAN.md` — 2026-09-16

| Gate | Kết quả và bằng chứng |
|---|---|
| 1 — Direct MCP | **Đạt local:** adapter chạy `codex-security` trực tiếp bằng bundled Node/STDIO, allowlist cố định, môi trường sạch, không model/native deep; direct adapter tests và probe thật xác nhận start/get/cancel. |
| 2 — Bridge contract | **Đạt local:** đúng 9 Security facade tools; schema không lộ `native_deep`, native lifecycle, `reasoningEffort` hay worker; `security_start_scan` là app-only, model không thấy tool này; ChatGPT có thể resolve scan sau click bằng `security_get_scan(request_id=...)`; restart STDIO trả lại cùng `scanId`, conflict/terminal guard/idempotency đã test. |
| 3 — Workflow | **Đạt local/native:** standard chạy đủ 7 checkpoint → complete; `chatgpt_deep` chạy đủ 10 checkpoint → complete. Probe restart thật giữ nguyên `scanId`, phase đã commit không chạy lại và tiếp tục đúng `nextPhase`. Hai mode có phase sequence typed, resume/checkpoint/terminal guard và không tạo Codex worker. Adapter tự claim/deliver handoff nội bộ bằng token bền vững; các pass Deep của ChatGPT chỉ dùng progress `review_receipts` trên native app-only standard session, không gửi `deepReviewPass`/native Deep. |
| 4 — Widget | **Đạt local + host retest:** `security-scan-v1` là resource riêng, MCP Apps `tools/call`/`ui/message` trước fallback, retry message không tạo scan thứ hai, cancel giữ nguyên `scanId`; Playwright security widget và `control-panel-v2` đều pass. |
| 5 — ChatGPT Web thật | **Đạt:** sau khi restart tunnel và làm mới resource, widget đã chạy Standard qua `scanId=ad009b3f-eb9d-4cb6-878e-2397f49c3fa2` tới `completed` theo `threat_model → discovery → validation → attack_path → finalization → complete`. Bằng chứng lịch sử trước khi áp dụng chat-to-panel routing: text command `Phân tích bằng ChatGPT Deep` và nút `ChatGPT Deep` đã chạy scan `e4746214-5a60-413b-8e27-293ca9a2b350` tới `completed` theo đủ `preflight → inventory → threat_model → Pass 1 → Pass 2 → Pass 3 → deduplicate → validation → attack_path → finalization → complete`. Cả hai đều dùng đúng scanId, không tạo native Deep/Codex worker, 0 finding hợp lệ. Trong lần retest thủ công ngày 2026-09-16, sau khi gỡ và cài lại plugin MCP Bridge local, bấm `Bắt đầu quét` đã tự động chạy workflow ngay, không cần gửi thêm lệnh trong chat. `healthz/readyz` không được dùng thay cho bằng chứng này. Target live là `H:/AI/New folder` (12 file tài liệu/log, không phải source của bridge), nên đây là bằng chứng connector/workflow end-to-end, không phải security audit của `H:/AI/Codex-app-tunnel`. |

### Reverification 2026-09-16

- Full Python suite bằng runtime của tunnel: **45/45 tests passed**.
- `test_security_ui.cjs`: **PASS** (Playwright DOM/MCP host loop).
- `test_ui.cjs`: **PASS** (`control-panel-v2` UI/MCP integration).
- `git diff --check`: **PASS**.
- Retest ChatGPT Web sau khi gỡ/cài lại plugin MCP Bridge local xác nhận nút `Bắt đầu quét` tự khởi động scan và workflow, không cần message thứ hai.
- Retest routing: yêu cầu quét từ chat chỉ mở chooser; scan không bắt đầu trước khi người dùng bấm `Bắt đầu quét`.

### Khôi phục cache của ChatGPT Web

Sau khi đổi tool hoặc UI resource, restart tunnel rồi vào Settings → Apps → Codex app → **Làm mới**. Nếu host vẫn hiển thị behavior cũ, gỡ và cài lại plugin MCP Bridge local, mở lại chat và `show_security_scan_panel`, rồi lặp lại kiểm tra nút `Bắt đầu quét`. Đây là quy trình làm mới cache plugin/host; không phải thay đổi flow hay kiến trúc MCP.
