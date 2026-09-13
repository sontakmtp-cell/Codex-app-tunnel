# Nghiệm thu Plan-remake-tunnel.md — 2026-09-13

**Chưa đạt toàn bộ kế hoạch.** Đã triển khai các nhóm A–F và kiểm tra được phần đọc/sửa/hoàn tác, MCP Docs, skills, lịch sử theo project và bảng ChatGPT thật. Phần thực thi lệnh còn bị chặn bởi sandbox Windows của Codex đang cài (`0.154.0-alpha.6.2`). Không đánh dấu hoàn tất khi các bài chạy lệnh thật chưa qua.

## Bằng chứng hiện có

| Yêu cầu | Kết quả và bằng chứng |
|---|---|
| A — App Server riêng, ẩn, STDIO lâu dài, request ID và notification | **Đạt:** `runtime.py`, `windows_job.py`; [runtime-result.json](.verification/runtime-result.json) xác nhận initialize, filesystem và watch thật. |
| A — không sinh code/review, không shell/API tùy ý, không tự replay/restart | **Đạt trong phạm vi bridge:** danh sách API cố định không có `turn/start`, `review/start`, resume hay chuyển tiếp tùy ý; self-test kiểm tra điều này. Task mất kết nối giữ trạng thái lỗi và ID. |
| A — kiểm tra phiên bản, schema và quyền thực tế | **Đạt cơ chế từ chối:** doctor kiểm tra executable/schema rồi chạy canary. **Chưa đạt quyền chạy lệnh** trên máy này. |
| B — preview nhiều file, SHA, exact patch, lưu SQLite ngoài project | **Đạt:** [self-test.log](.verification/self-test.log), 22 bài qua; preview không ghi, apply đúng bản đã chuẩn bị, SHA sai/patch mơ hồ bị từ chối. |
| B — hoàn tác cả đợt, bảo vệ sửa ngoài bridge, tạo file rồi gỡ đúng file | **Đạt:** bài nhiều file có nội dung có sẵn, từ chối cả đợt khi một file xung đột; kiểm tra nút Apply/Undo thật trên ChatGPT. |
| B — lỗi giữa đợt, khởi động lại, phục hồi theo SHA | **Đạt:** giả lập lỗi và ngắt giữa apply/undo; theo dõi file pending/writing/written; không phục hồi nhầm file chưa từng ghi. File bị sửa ngoài bridge được giữ lại và khóa ghi tiếp khi có xung đột. |
| B — giữ 30 đợt hoàn tất, không dọn lỗi, không sửa Git index | **Đạt:** mặc định 30; bài retention dùng giới hạn nhỏ để chứng minh cùng cơ chế. Bài Git trên project mẫu đối chiếu byte của index. Không có Git reset/clean trong cơ chế hoàn tác. |
| C — đọc khoảng dòng, toàn bộ SHA, UTF-8/CRLF, đường dẫn có khoảng trắng | **Đạt:** self-test so byte, dòng, hash; đọc API App Server thật trên project mẫu có khoảng trắng. |
| C — rg và Git diff dùng bộ lọc nhạy cảm | **Đạt logic với rg/Git thật trong project mẫu qua runtime kiểm thử. Chưa xác nhận qua App Server được bảo vệ.** Git lấy tên từ index trước, rồi chỉ đọc diff các đường dẫn đã lọc. |
| D — start nhanh, log từng phần, thành công/thất bại/timeout, ID ổn định, một task, khóa ghi | **Đạt kiểm thử logic với runtime giả. Chưa nghiệm thu task App Server thật.** Không lấy bài giả làm bằng chứng sandbox. |
| D — Dừng cả tiến trình con, không dừng chương trình ngoài bridge | **Đạt Windows Job Object dự phòng thật:** self-test tạo cha/con và tiến trình đối chứng, đóng đúng nhóm riêng. **Chưa xác nhận `command/exec/terminate` và nút Dừng trên ChatGPT với task được bảo vệ.** |
| E — chỉ hai Docs MCP, không mở model turn, tắt MCP/plugin khác riêng cho child | **Đạt:** live `mcpServerStatus/list` chỉ có hai tool Docs khả dụng; search/fetch thật đã qua ngữ cảnh kỹ thuật tạm. Override chỉ nằm trong argv của App Server. |
| E — đọc skill đã tìm, giới hạn thư mục, không chạy script | **Đạt:** discovery/read thật; kiểm thử từ chối đường dẫn tham chiếu thoát thư mục và ID tự bịa. |
| E — chỉ đọc hội thoại đúng project, không tiếp tục/sửa | **Đạt phạm vi kiểm tra:** request list có cwd, lọc kết quả, đọc metadata kiểm tra cwd trước khi lấy nội dung; giới hạn văn bản user/assistant và bỏ output riêng tư. Live project mẫu trả danh sách rỗng đúng phạm vi. |
| F — HTML nhỏ, ba phần, diff theo file, Apply/Undo thật | **Đạt qua tunnel trong ChatGPT:** [chatgpt-ui-result.json](.verification/chatgpt-ui-result.json), [hội thoại kiểm thử](https://chatgpt.com/c/6aa56369-4424-83ec-90cc-9ec041579900). |
| F — không mở lại bảng khi đọc dữ liệu, polling 2 giây khi thấy task chạy | **Đạt cấu trúc/logic UI; polling với task thật trên ChatGPT chưa xác nhận** vì bộ chạy bị khóa. Chỉ `show_control_panel` có resource UI. |
| F — text an toàn, không thực thi HTML từ project | **Đạt kiểm thử Chromium với MCP server thật và host mẫu:** `test_ui.cjs`, [ảnh kiểm thử](../output/playwright/control-panel-applied.png). Bài này dùng file chứa HTML và xác nhận không tạo thẻ ảnh/thực thi script. |
| Tương thích sáu tool cũ | **Đạt:** [legacy-signatures.json](.verification/legacy-signatures.json) đối chiếu bản gốc; chỉ `read_file` thêm `end_line`. Write/patch cũ cùng journal; run_task cũ cùng runner. |
| Chống gửi lại yêu cầu và mất kết nối qua tunnel | **Đạt với đợt sửa:** bảng tải lại sau tunnel ngắt, vẫn thấy đợt pending; gửi lại đúng hai ID Apply/Undo sau hoàn tác đều trả `undone`, không tạo lại file. |
| Chặn đường dẫn, ADS, junction/symlink/hardlink và file nhạy cảm | **Đạt kiểm thử lớp file:** gồm junction và hardlink thật trên Windows, file nhị phân, đường dẫn thoát project. **Quyền của lệnh thật chưa đạt.** |
| PowerShell 5.1, tunnel doctor, healthz/readyz, không ảnh hưởng tunnel khác | **Script chạy thật bằng 5.1; tunnel doctor và hai endpoint đã đạt. Bridge doctor chưa đạt** do sandbox. Đối chiếu SHA xác nhận config coding và file Blender/SolidWorks giữ nguyên. |

## Lượt kiểm thử ChatGPT thật

Đợt `24fcefea43d141c3a96130aeef14ec32` chỉ chứa file mới `bridge-ui-check-20260913.txt`. Preview chưa tạo file; nút Apply tạo đúng từng byte đã lưu trong bản xem trước; nút Undo gỡ file. Sau gửi lại request ID cũ, SQLite vẫn là `undone` và file vẫn không tồn tại. Cả 7 file có sẵn giữ nguyên SHA.

ChatGPT chuẩn bị nội dung dùng LF trong lượt này; bridge ghi đúng LF đã nhận. Khả năng giữ CRLF được xác nhận riêng bằng self-test so từng byte, không suy ra từ ảnh diff.

Khi kiểm tra quyền, Windows từng tự tạo `.git` rỗng do profile khai báo đường dẫn đọc chưa tồn tại. Đã sửa profile chỉ thêm `.git` khi là repo có metadata; nhận diện project không còn coi thư mục rỗng là repo. Chỉ thư mục rỗng có timestamp đúng lần kiểm tra được gỡ, không xóa dữ liệu Git có sẵn.

## Phần còn chặn nghiệm thu

Canary mới nhất trong project mẫu: `outside_blocked=true`, `key_absent=true`, **`network_blocked=false`**. Tiến trình được yêu cầu tắt mạng vẫn kết nối TCP tới listener canary trên `127.0.0.1`. Một số lần kiểm tra trước đó còn bị lỗi helper hoặc không chặn đọc ngoài project. Vì vậy bridge giữ `commands_enabled=false` và trả `SANDBOX_UNAVAILABLE` cho task/search/Git.

Chưa được công nhận đạt:

- Chạy test/build thật qua App Server với chính sách đủ quyền file và không mạng.
- Log, mã lỗi, timeout và dừng cả tiến trình con của chính task App Server đó.
- Search/Git diff thật qua cùng bộ thực thi được bảo vệ.
- Bảng ChatGPT theo dõi và Dừng một task thật.
- Bridge doctor trả thành công với canary đạt đầy đủ.

Không hạ Codex, đổi sang chạy không sandbox hoặc bỏ canary để làm kết quả xanh. `verify_runtime.py` đã có project mẫu và nhánh kiểm thử những task này, nhưng **nhánh đó chưa được chạy thành công**. Nó chỉ chạy khi policy thực tế đã đạt.

## Bước tiếp theo

Cần xử lý sandbox Windows của Codex trước. [Hướng dẫn chính thức](https://learn.chatgpt.com/docs/windows/windows-sandbox) đề nghị thử lại thiết lập `elevated` và chấp nhận yêu cầu quản trị; thiết lập này liên quan tới tài khoản sandbox, quyền đăng nhập và firewall. Chưa có bằng chứng việc chạy lại setup sẽ tự sửa hết lỗi mạng trên bản Codex hiện tại.

Sau khi môi trường được sửa, chạy lại `verify_runtime.py`, doctor của script và lượt task/Stop trên ChatGPT. Nếu canary vẫn thất bại, tiếp tục điều tra runtime; không mở khóa các lệnh bằng tay. Chi tiết cách chạy và dùng bridge nằm trong [README.md](README.md).
