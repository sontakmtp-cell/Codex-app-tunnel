1. Nâng cấp Task Runner sang MCP Tasks chuẩn 2026-07-28

Mục tiêu: chuyển hệ thống task hiện tại sang MCP Tasks extension chuẩn `2026-07-28`.

Hiện bridge đang tự quản lý:

* `start_task`
* `get_task_run`
* `stop_task_run`
* trạng thái task
* timeout
* cancel
* log

Yêu cầu:

* nghiên cứu MCP Tasks của spec 2026-07-28
* dùng Tasks làm lifecycle chính cho các tác vụ dài
* hỗ trợ get/update/cancel theo chuẩn MCP nếu SDK hỗ trợ
* giữ compatibility cho các tool cũ để không làm hỏng client hiện tại
* không phá journal, task lock, timeout và Windows process cleanup hiện có
* Security Scan chưa cần migrate nếu gây quá nhiều thay đổi, nhưng thiết kế phải cho phép dùng chung Tasks sau này
* request retry không được tạo task trùng

Sau khi sửa:

* chạy unit test
* chạy MCP workflow thực tế
* test start → running → completed
* test cancel
* test timeout
* test reconnect/retry
* kiểm tra task cũ vẫn dùng được

Chỉ kết luận PASS khi lifecycle task hoạt động đúng qua MCP thực tế, không chỉ dựa vào code.

2. Thay polling bằng MCP subscriptions/listen

Mục tiêu: bỏ hoặc giảm tối đa polling định kỳ trong `panel.html` và Security panel bằng cơ chế event-driven của MCP 2026-07-28.

Hiện panel có polling trạng thái task khoảng mỗi 2 giây.

Hãy nghiên cứu và triển khai `subscriptions/listen` hoặc cơ chế subscription/resource update tương ứng của SDK đang dùng.

Thiết kế resource tối thiểu:

* task state
* Security Scan state
* change/apply state

Có thể dùng URI dạng:

* `bridge://task/{run_id}`
* `bridge://scan/{scan_id}`
* `bridge://change/{change_id}`

Yêu cầu:

* khi state thay đổi, panel nhận update ngay
* không cần polling liên tục khi host hỗ trợ subscription
* có fallback polling cho client cũ không hỗ trợ capability mới
* không làm panel reload hoặc mở lại resource
* không tạo event storm
* reconnect phải lấy lại authoritative state

Kiểm tra thực tế:

* task đang chạy cập nhật log/status trên panel
* task complete đổi trạng thái ngay
* cancel phản ánh ngay
* Security Scan phase thay đổi đúng
* client legacy vẫn hoạt động

Đo số request trước và sau để chứng minh polling đã giảm.

3. Chuẩn hóa Structured Output cho toàn bộ MCP tools

Mục tiêu: chuẩn hóa output contract của toàn bộ MCP tools theo kiểu dữ liệu rõ ràng thay vì trả tự do `dict[str, Any]`.

Hãy:

* rà soát toàn bộ tool trong `server.py`
* tạo Pydantic response models phù hợp
* bật structured output cho các tool thích hợp
* chuẩn hóa error/result envelope

Các field chung nên xem xét:

* `status`
* `request_id`
* `resource_uri`
* `error_code`
* `message`
* `retryable`
* `warnings`
* `next_cursor`

Không ép tất cả tool dùng một schema nếu làm contract xấu; có thể dùng base model + response chuyên biệt.

Đặc biệt chuẩn hóa các lỗi:

* SHA mismatch
* stale change
* idempotency conflict
* task unavailable
* sandbox unavailable
* permission denied
* scan state conflict
* not found

Yêu cầu:

* không phá compatibility không cần thiết
* schema phải được MCP host discover đúng
* model không phải đoán field hoặc parse text lỗi
* error không được làm mất thông tin kỹ thuật cần debug

Test:

* inspect `tools/list`
* gọi các tool thành công
* cố tình tạo các lỗi phổ biến
* xác nhận structured output đúng schema
* chạy test legacy hiện tại.

4. Thêm MCP Protocol Diagnostics vào Control Panel

Mục tiêu: thêm tab hoặc section `MCP Diagnostics` vào control panel để debug trực tiếp trạng thái protocol giữa ChatGPT và bridge.

Hiển thị tối thiểu:

* MCP protocol version
* Python MCP SDK version
* bridge version
* server capabilities
* client capabilities nếu biết
* Apps support
* Tasks support
* subscriptions support
* structured output support
* cache hints support
* legacy compatibility mode
* connected/disconnected
* runtime state
* current project
* resource URI đang dùng

Nếu MCP 2026-07-28 dùng discovery/capability mechanism mới, hiển thị dữ liệu authoritative từ protocol thay vì hard-code.

Thêm nút:
`Copy diagnostics`

Output phải dễ gửi cho agent để debug.

Không hiển thị:

* token
* secret
* tunnel credential
* nội dung `.env`

Test trên ChatGPT Web thật hoặc MCP host tương đương và xác nhận dữ liệu phản ánh capability thực tế.

5. Triển khai MCP Cache Hints

Mục tiêu: tận dụng cache hints của MCP 2026-07-28 để giảm request không cần thiết mà không làm state bị stale.

Rà soát:

* tools metadata
* resources
* HTML Apps resources
* immutable change diff
* project state
* task state
* Security Scan state

Phân loại rõ:

* immutable / cache lâu
* semi-static
* dynamic / không cache

Ví dụ:

* panel HTML: cache tương đối lâu
* tool metadata: cache
* completed saved diff: cache lâu
* project_info: cache ngắn hoặc không cache
* running task: không cache
* scan đang chạy: không cache

Dùng `ttlMs`, `cacheScope` hoặc API tương ứng đúng với SDK/spec thực tế.

Yêu cầu:

* không hard-code field không được SDK hỗ trợ
* legacy clients vẫn hoạt động
* state động không được trả dữ liệu stale

Thêm test kiểm tra metadata/cache hint thực tế qua MCP.

6. Thay Turbo global bằng Temporary Permission Grants

Hiện Turbo cho quyền rất rộng sau khi bật.

Mục tiêu: giữ Turbo compatibility nhưng bổ sung hệ thống quyền tạm thời granular hơn.

Các capability nên tách:

* shell execution
* network access
* read ngoài project
* write ngoài project

Cho phép scope:

* một command
* một task
* 5 phút
* 10 phút
* đến khi user tắt

Yêu cầu:

* Normal vẫn là mặc định
* quyền phải do user xác nhận trực tiếp trong panel
* restart bridge phải revoke permission tạm thời
* expiration phải enforce ở backend, không chỉ UI
* model không được tự grant quyền
* panel hiển thị rõ capability nào đang bật và còn bao lâu
* command vượt scope phải bị từ chối
* tunnel/API secret vẫn không được truyền xuống child process

Giữ `Turbo` như full-access compatibility mode nếu cần, nhưng khuyến khích granular permission trong UI.

Test cả success, expiry, revoke và bypass attempt.

7. Nâng Change Engine hỗ trợ Rename/Delete/Mkdir

Mục tiêu: mở rộng hệ thống change hiện tại để agent có thể refactor project đầy đủ nhưng vẫn giữ workflow an toàn:

`prepare → preview → apply → undo`

Thêm operation:

* create file
* update file
* delete file
* rename/move file
* create directory
* nếu hợp lý: remove empty directory

Yêu cầu:

* SHA validation trước khi delete/rename
* không overwrite file đích ngoài ý muốn
* chống path traversal
* chống symlink/junction/hardlink bypass
* preserve line endings/file bytes cho file không bị sửa
* multi-file batch vẫn hỗ trợ rollback/recovery
* rename + edit trong cùng batch phải có behavior xác định
* undo phải phục hồi đúng tên và nội dung cũ
* crash giữa batch phải recover được
* Git index không được tự sửa

Thêm test:

* rename
* delete
* mkdir
* rename conflict
* stale SHA
* crash recovery
* undo batch nhiều loại operation.

8. Security Scan Incremental + Finding Baseline

Mục tiêu: nâng Security MCP để scan sau có thể so với scan trước thay vì luôn xem mọi finding là mới.

Tạo fingerprint ổn định cho finding dựa trên các yếu tố phù hợp:

* rule/type
* file
* source location
* normalized evidence
* semantic identity của vulnerability

Phân loại:

* NEW
* UNCHANGED
* FIXED
* REGRESSED

Yêu cầu:

* line number thay đổi nhẹ không được làm finding hoàn toàn mới nếu vulnerability vẫn cùng bản chất
* source location vẫn phải chính xác
* không fallback line 1 vô nghĩa
* baseline phải gắn với project/fingerprint phù hợp
* scan của project khác không được trộn
* export JSON/SARIF/Markdown chứa trạng thái baseline
* panel cho filter New / Existing / Fixed / Regressed

Nếu khả thi, thêm incremental scan:

* ưu tiên file thay đổi từ scan trước
* vẫn mở rộng dependency liên quan khi cần
* phải có full-scan fallback

Test bằng fixture:

1. tạo vulnerability
2. scan
3. scan lại không sửa
4. sửa vulnerability
5. scan lại
6. tái tạo vulnerability

Xác nhận state chuyển đúng.

9. Project Profile Auto-Detect

Hiện task riêng của project cần profile cấu hình thủ công.

Mục tiêu: khi bridge mở project mới, tự phát hiện stack và đề xuất profile.

Detect tối thiểu:

* `package.json`
* `pyproject.toml`
* `requirements.txt`
* `pytest`
* `Cargo.toml`
* `go.mod`
* `CMakeLists.txt`
* `.sln`
* `.csproj`

Từ đó đề xuất các task phù hợp như:

* test
* lint
* build
* typecheck

Quan trọng:

* chỉ đề xuất, không tự chạy
* không cho model tự thêm command tùy ý
* user phải duyệt task trong panel
* executable và args sau khi duyệt phải trở thành fixed allowlist
* không đọc script nguy hiểm rồi tự chạy
* detect package manager hợp lý
* hỗ trợ project monorepo cơ bản

Thêm UI:
`Detected project`
`Suggested tasks`
`Approve`
`Ignore`

Sau khi approve, lưu project profile ngoài source project như kiến trúc hiện tại.

Test ít nhất Python, Node và một project không nhận diện được.

10. Thêm Local Code Intelligence bằng Tree-sitter/LSP

Mục tiêu: giúp ChatGPT hiểu codebase nhanh hơn thay vì chỉ dựa vào `list_files`, `read_file` và literal `search_code`.

Ưu tiên local deterministic tooling, không gọi thêm AI.

Thêm các capability:

* `file_outline(path)`
* `find_symbol(name)`
* `find_references(symbol)`
* `project_symbols(query)`
* nếu khả thi: `go_to_definition`

Có thể dùng:

* Tree-sitter
* LSP đang có trong project
* hoặc hybrid

Yêu cầu:

* bắt đầu với Python, JS/TS nếu cần giới hạn scope
* response trả file + line/startLine/endLine chính xác
* hoạt động với file chưa commit
* không index `.git`, dependency lớn, build output, secrets
* incremental re-index khi file thay đổi
* giới hạn RAM/CPU
* fallback sang `search_code` nếu parser/LSP không hỗ trợ ngôn ngữ đó
* không bắt buộc user cài IDE extension riêng

Tích hợp vào MCP tool discovery rõ ràng.

Test bằng fixture có:

* class
* function
* duplicate symbol names
* imports
* references nhiều file

So source location với file thật và chỉ PASS nếu định vị hữu ích.
