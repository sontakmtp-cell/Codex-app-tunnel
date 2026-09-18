Trong quá trình dùng Codex Bridge để chạy Security Scan thực tế, tao gặp các vấn đề usability/reliability sau. Hãy kiểm tra và fix theo hành vi thực tế, không chỉ đọc code.

1. `search_code` rất dễ timeout
   Tao gọi tìm các pattern bảo mật như `subprocess`, `requests`, `api_key`… nhưng nhiều lần Code Mode báo:
   `Script error: Code Mode execution timed out.`

Ngay cả khi chỉ gọi vài search tương đối nhỏ vẫn timeout.

Yêu cầu:

* `search_code` phải phản hồi ổn định với repo cỡ trung bình.
* Nếu kết quả lớn, phân trang/truncate thay vì treo đến timeout.
* Timeout phải trả lỗi rõ tool nào bị timeout, không làm hỏng workflow đang chạy.

2. Security workflow bị kẹt khi `security_commit_phase` timeout
   Scan đã tạo thành công:
   `5eb5afa9-389e-40e0-a18c-50ac9ff8f2f1`

Nhưng khi commit phase `inventory`, tool timeout. Sau đó các lệnh:

* `security_get_scan`
* `security_continue_scan`

cũng tiếp tục timeout.

Đây là lỗi nghiêm trọng vì scan đang chạy nhưng client không thể biết:

* phase đã commit hay chưa
* state authoritative hiện tại là gì
* có thể resume an toàn hay không

Yêu cầu:

* Mọi `security_commit_phase` phải idempotent theo `request_id`.
* Nếu client timeout sau khi server đã commit, gọi lại phải trả state hiện tại thay vì commit trùng.
* `security_get_scan` phải luôn là đường recovery nhẹ và đáng tin cậy.
* Không để một phase lỗi/timeout làm toàn Security MCP bị treo theo.

3. Security state API cần ưu tiên khả năng recovery
   Sau một tool timeout, tao đáng lẽ phải có thể gọi ngay:
   `security_get_scan(scan_id=...)`

để biết authoritative state.

Nhưng chính API recovery này cũng timeout.

Yêu cầu:

* `security_get_scan` và `security_continue_scan` phải cực nhẹ, không chạy lại analysis hay công việc nặng.
* Chỉ đọc persisted state.
* Có thể dùng để resume sau disconnect, refresh trang, model/tool timeout.

4. `list_files` trả lượng dữ liệu quá lớn
   Khi scan codebase, `list_files(max_results=500)` trả một payload rất lớn gồm cả `reports/`, assets, generated files… và cuối cùng vẫn `truncated=true`.

Điều này vừa tốn context vừa làm Security workflow chậm.

Yêu cầu:

* Security Scan nên có file inventory riêng hoặc filter mặc định.
* Ưu tiên source code/config.
* Bỏ qua hoặc gom nhóm:

  * `reports/**`
  * images/PDF
  * generated artifacts
  * cache/build folders
  * dữ liệu không executable
* Trả summary trước, chi tiết qua pagination.

5. Thiếu API hỗ trợ repository-wide security discovery hiệu quả
   Do `search_code` timeout, tao phải fallback sang `run_bash + rg`.

Cách này chạy được nhưng Security workflow không nên phụ thuộc việc model tự dùng shell để rà repo.

Yêu cầu:

* Có API search nhanh, ổn định cho nhiều pattern.
* Cho phép batch patterns kiểu:
  `subprocess|eval|exec|shell=True|api_key|verify=False`
* Hỗ trợ include/exclude glob.
* Trả file + line + snippet.
* Pagination rõ ràng.

6. `run_bash` đôi lúc bị chặn khó hiểu
   Một command chỉ dùng để đọc source bằng `nl` + `sed` bị trả:
   `Lệnh gọi công cụ này đã bị OpenAI chặn vì chúng tôi không thể xác định trạng thái an toàn của yêu cầu.`

Trong khi các command `sed` gần giống ngay trước đó vẫn chạy được.

Yêu cầu:

* Với command read-only, nên có helper/tool riêng để tránh phụ thuộc shell-policy.
* Nếu bị chặn, Bridge nên trả lý do cụ thể hơn và gợi ý API tương đương như `read_file`.

7. Security scan chưa có cảm giác “transactional”
   Hiện workflow gồm nhiều phase:
   preflight → inventory → threat_model → discovery → ...

Nếu timeout ở giữa thì model rất khó biết server đã nhận gì.

Mong muốn:

* mỗi phase có `revision/version`
* response sau commit trả:

  * committed phase
  * revision mới
  * currentPhase
  * nextPhase
* retry cùng request phải an toàn tuyệt đối
* có audit log phase nào đã commit lúc nào

Mục tiêu cuối:
Security Scan phải chịu được:

* tool timeout
* refresh ChatGPT
* mất kết nối tạm thời
* retry request
* response bị thất lạc

mà vẫn resume đúng Scan ID, không cần tạo scan mới và không mất findings/state.
