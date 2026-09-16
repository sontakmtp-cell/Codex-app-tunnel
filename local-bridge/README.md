# Local MCP Bridge

Bridge nối ChatGPT Web với project được chọn bằng một dòng trong `project-path.txt` (hiện `H:/AI/autolab` chỉ là project kiểm thử). ChatGPT trực tiếp viết code; bridge không gọi lượt AI, sinh code hoặc review của Codex. Lớp MCP dùng Python SDK `mcp==2.2.0`, nói MCP `2026-07-28` và vẫn tương thích client đời 2025.

**Trạng thái nghiệm thu:** xem [ACCEPTANCE.md](ACCEPTANCE.md). Bảng và chức năng đọc/sửa/hoàn tác hoạt động. Sau khi đổi profile mạng và đọc ngoài project, phải chạy lại doctor trên tunnel mới; `healthz`/`readyz` không chứng nhận quyền chạy lệnh.

## Khởi động

Chạy script cũ bằng Windows PowerShell 5.1:

```powershell
& 'D:\AI\tunnel-client-v0.0.14-windows-arm64\start-chatgpt-coding-tunnel.ps1'
```

Script tự đọc khóa tunnel hiện có, chạy self-test, kiểm tra App Server rồi mở tunnel. Nếu đúng tunnel coding đã chạy, script báo PID và kết thúc; không mở thêm bridge cùng journal. Không sửa cấu hình Blender/SolidWorks.

Trong ChatGPT, dùng app **Codex app** đã kết nối. Sau khi thay đổi danh sách tool hoặc panel, vào Settings → Apps → Codex app → **Làm mới**. Nếu host vẫn giữ resource hoặc hành vi cũ, đặc biệt là nút `Bắt đầu quét` tạo scan nhưng không tự tiếp tục hội thoại, hãy gỡ rồi cài lại plugin **MCP Bridge local** trong ChatGPT Web, mở lại chat/panel và kiểm tra lại. Đây là bước loại cache của plugin/host, không thay đổi kiến trúc MCP. Hỏi: “Đọc project_info rồi mở show_control_panel”. Bảng mới có bốn tab Runtime, Đợt sửa/Diff, Task/Terminal và Workspace/Topology; Normal/Turbo vẫn yêu cầu xác nhận theo policy. Các tool dữ liệu cập nhật bề mặt hiện tại; `show_control_panel` mở control panel, còn `show_security_scan_panel` mở Security widget resource riêng. Xác nhận bắt buộc của ChatGPT vẫn do ChatGPT quản lý.

## Security MCP V1

Security widget dùng resource riêng `ui://local-bridge/security-scan-v1.html`; nó không thay thế và không chia sẻ trạng thái presentation với `control-panel-v2`. Khi người dùng bấm `Bắt đầu quét`, widget dispatch request của Security và message vào đúng phiên ChatGPT trong cùng lượt click; ChatGPT Web tự tiếp tục workflow, không cần người dùng gửi thêm lệnh trong chat.

V1 chỉ quảng bá `standard` và `chatgpt_deep`. Cả hai mode đều dùng ChatGPT Web để reasoning, không tạo Codex worker, không gọi native Deep và không expose `native_deep`, `model` hoặc `reasoningEffort` ra giao diện/tool contract.

Trong Codex desktop, mở cùng đường dẫn đang hiện trong `project_info` để xem file. Bảng đọc trạng thái Git hiện tại của folder; diff theo từng đợt sửa dùng được cả khi chưa có Git. Bridge không tự tạo repo hoặc chọn lệnh test/build cho folder này.

## Đổi project nhanh

Mặc định, chỉ sửa **một dòng** trong `local-bridge/project-path.txt` rồi chạy lại `start-chatgpt-coding-tunnel.ps1`. Nếu chỉ muốn đổi tạm cho một lần chạy, dùng:

```powershell
.\start-chatgpt-coding-tunnel.ps1 -ProjectPath 'D:/AI/project-khac'
```

`config.json` dùng token `${PROJECT_ROOT}` cho `workspace_root`; tunnel tự phát hiện project đổi và khởi động lại đúng bridge. Runtime root dạng token không tồn tại sẽ được bỏ qua, nên project không có môi trường test vẫn đọc/sửa file bình thường. `autolab` hiện chỉ là giá trị kiểm thử.

## Task theo từng project

Task chung nằm trong `config.json`; task riêng nằm ở `local-bridge/project-profiles/`, ngoài project nên ChatGPT không thể tự thêm lệnh. Copy `project-profiles/TEMPLATE.json` thành một file `.json`, sửa `workspace_root`, `runtime_read_roots` và `tasks` một lần cho project mới. Khi `project-path.txt` trỏ tới project đó, bridge tự nạp đúng profile; không cần sửa `config.json` mỗi lần đổi project. Nếu chưa có profile, các thao tác file và task Git chung vẫn dùng được.

## Xem trước, áp dụng, hoàn tác

1. `read_file` lấy nội dung và SHA-256 của file đang có. Có thể chọn `start_line`, `end_line`, `max_bytes`; SHA luôn tính trên toàn file.
2. `prepare_changes` tạo đợt có tên, lưu bản trước/sau ngoài project và trả diff. Bước này chưa ghi file.
3. Xem diff theo file trong bảng hoặc bằng `get_change`.
4. `apply_changes` áp dụng đợt đã chuẩn bị. Nếu Khầy chỉ yêu cầu xem trước, dừng ở bước 3.
5. `undo_changes` chỉ hoàn tác khi **tất cả** file còn khớp bản sau. Nếu có sửa mới từ bên ngoài, cả đợt bị từ chối và trả danh sách file xung đột.

Ví dụ tạo file mới trong một thư mục đã tồn tại:

```json
{
  "title": "Thêm lời chào",
  "request_id": "prepare-greeting-001",
  "edits": [
    {"path": "hello.txt", "content": "Chào Khầy\r\n", "expected_sha256": null}
  ]
}
```

Với file đã có, `expected_sha256` phải là SHA vừa đọc. Có thể thay `content` bằng `old_text` và `new_text`; đoạn cũ phải khớp chính xác **một lần**. Chưa có xóa/đổi tên file tổng quát. Hoàn tác được phép gỡ đúng file do đợt đó tạo nếu SHA còn khớp.

```json
{"change_id": "ID_TRẢ_VỀ", "request_id": "apply-greeting-001"}
```

Dùng JSON trên cho `apply_changes`; khi hoàn tác dùng `undo_changes` với một request ID khác. Khi mất kết nối, đọc lại trạng thái và **gửi lại đúng request ID ban đầu**. Không đổi ID để thử lại thao tác chưa rõ kết quả. Bridge lưu chống thực hiện trùng qua lần khởi động lại. Một ID đã dùng cho nội dung khác sẽ bị từ chối.

Mặc định mỗi file tối đa 2 MiB, mỗi đợt tối đa 100 file và 16 MiB tổng bản trước/sau. Thư mục cha phải có sẵn. Mỗi file được ghi qua file tạm rồi thay thế; cả đợt nhiều file không phải một lần ghi nguyên tử. Bridge không dùng `git reset`, không sửa Git index.

## Nhật ký và phục hồi

SQLite nằm trong `local-bridge/.state/<mã project>/`, ngoài project được phép sửa. Chỉ một bridge được giữ khóa journal đó. Giữ bản sao của 30 đợt hoàn tất gần nhất; đợt chưa áp dụng, bị lỗi hoặc có xung đột không bị dọn. ID nhỏ của đợt đã hết hạn vẫn được giữ để chống thực hiện lại.

Sau sự cố, bridge kiểm tra SHA và tiến độ ghi của từng file để phục hồi phần đã ghi. File bị chương trình khác sửa được giữ lại. Trạng thái `recovery_conflict` khóa những lần ghi tiếp theo. Xem `get_change` và `project_info` để biết file nào xung đột; xử lý nội dung trong máy sau khi giữ bản sửa ngoài bridge, rồi khởi động lại để kiểm tra phục hồi. Không xóa journal hoặc sửa SHA trong SQLite để vượt qua xung đột.

`recovered` nghĩa là lần áp dụng lỗi đã được trả về bản trước. `undo_failed` nghĩa là lần hoàn tác lỗi đã được trả về bản sau. Các lần lỗi này không tự chạy lại; đọc nội dung hiện tại và chuẩn bị một đợt mới nếu cần.

## Test/build

`list_tasks` hiện luôn có `git_status`, `git_diff_check`; task riêng xuất hiện từ profile khớp project, ví dụ `pytest` của profile `autolab`. `git_diff_check` chạy helper cố định trong bridge: lấy danh sách file tracked từ index, bỏ các đường dẫn bị policy chặn, rồi gọi `git diff --check` qua App Server nên không đụng `.env`. Task còn lại chạy executable và đối số cố định trong profile; token `${PROJECT_ROOT}` dùng được cho đường dẫn. Tắt cache provider để không ghi vào `.pytest_cache` có ACL riêng của sandbox. `start_task(task_id, request_id, timeout_seconds)` trả `run_id` ngay. Dùng `get_task_run(run_id, cursor)` để lấy phần log mới và `stop_task_run(run_id, request_id)` để dừng. `run_task` cũ dùng chung bộ chạy nhưng chờ kết quả đồng bộ.

Tối đa một task chạy; áp dụng/hoàn tác bị khóa trong lúc chạy. Log có trạng thái, thời gian và mã kết thúc, không tạo phần trăm giả. Bảng lấy trạng thái mỗi 2 giây khi đang hiển thị và có task hoạt động. Log giữ trong bộ nhớ cho 30 lượt gần nhất, giới hạn khoảng 256 KiB; sau restart chỉ còn trạng thái và ID trong SQLite. Timeout tối đa hiện cấu hình là 300 giây. Nếu mất App Server, không tự chạy lại task.

## Chế độ Normal và Turbo

Bridge luôn khởi động ở **Normal**. Normal giữ nguyên policy `bridge`: chỉ task đã cấu hình, search/Git qua App Server, project/cache được ghi, root ngoài chỉ đọc và phải qua doctor. Turbo chỉ bật bằng nút trong bảng sau cảnh báo xác nhận; trạng thái không lưu qua lần khởi động lại.

Khi Turbo bật, `command/exec` dùng policy `dangerFullAccess` theo từng lệnh, nên Bash có thể đọc/ghi ngoài project và dùng mạng. `run_bash(command, timeout_seconds)` chạy bằng Git Bash thật (`Git/bin/bash.exe`) và chỉ hoạt động trong Turbo; đây là lối dành cho skill như `last30days` hoặc task dự án cần Bash. Turbo có thể xóa/sửa dữ liệu ngoài project, vì vậy chỉ bật khi thật sự cần. Môi trường kế thừa vẫn được làm sạch để không tự truyền khóa tunnel/API vào tiến trình.

Muốn đổi project, sửa `local-bridge/project-path.txt` hoặc dùng `-ProjectPath`; chỉ sửa profile riêng một lần khi project có task/build mới. Trong Normal, ChatGPT không được thêm lệnh, đổi project, đổi root đọc hoặc thay policy mạng. Turbo là ngoại lệ do Khầy bật trực tiếp trong bảng. Trên Windows phải dùng executable thật; bridge từ chối shim `.cmd`, `.bat`, `.ps1`. Executable trong project chỉ được phép nếu nằm trong `runtime_read_roots` đã allowlist; `external_read_roots` là các thư mục ngoài project chỉ được đọc bởi App Server, không được là project hoặc thư mục cha của project và không được chồng lấn. Cả hai nhóm phải vượt qua doctor trước khi dùng Normal.

## Quyền và phạm vi

- App Server là tiến trình ẩn riêng qua STDIO, được bridge sở hữu cùng các tiến trình con bằng Windows Job Object. Đóng bridge sẽ đóng nhóm riêng này.
- Normal chỉ dùng profile `bridge`: project/cache được ghi; `runtime_read_roots` và `external_read_roots` chỉ được đọc; mạng ra ngoài được bật cố định cho task đã cấu hình. Doctor phải thấy `outside_blocked=false`, `network_blocked=false` và `key_absent=true`; nếu thất bại, Normal từ chối chạy lệnh, không có fallback không bảo vệ. Turbo là ngoại lệ có chủ ý, được bật bằng xác nhận UI và dùng policy toàn quyền theo từng lệnh.
- Không truyền khóa tunnel vào App Server/task. Không lưu nội dung file hoặc lịch sử đầy đủ vào log chẩn đoán. Nhật ký thay đổi riêng vẫn cần lưu bản trước/sau để hoàn tác.
- Đọc/tìm/diff cùng chặn `.env`, khóa/certificate, cấu hình nhạy cảm, file nhị phân, đường dẫn thoát project, Windows ADS, symlink/junction và hardlink không an toàn. Quản lý quyền file không phụ thuộc vào sandbox của lệnh.
- Chỉ hai tool `openaiDeveloperDocs` được gọi qua `mcpServer/tool/call`. MCP/plugin khác bị tắt bằng tham số của tiến trình bridge; cấu hình Codex toàn cục không đổi. Ngữ cảnh kỹ thuật tạm không có lượt sinh code.
- `list_skills` tìm skill; chỉ đọc tài liệu trong thư mục skill đã được xác định. Hướng dẫn skill không cấp quyền trong Normal; skill cần chạy script phải được người dùng bật Turbo rồi dùng `run_bash`.
- Chỉ liệt kê/đọc hội thoại Codex có `cwd` đúng project, theo yêu cầu. Không đọc task khác, tiếp tục task cũ hoặc xuất toàn bộ kết quả tool riêng tư.
- Bảng dùng MCP Apps resource `ui://local-bridge/control-panel-v2.html`, có trạng thái tổng quan, diff, log và task progress dạng indeterminate; không có frontend build hoặc cổng HTTP riêng. Code/log được hiển thị bằng văn bản.

## Kiểm tra trong máy

Self-test dùng project mẫu riêng, không thay đổi project của Khầy:

```powershell
Set-Location -LiteralPath 'D:\AI\tunnel-client-v0.0.14-windows-arm64'
uv run --with mcp==2.2.0 --python 3.13 local-bridge/server.py --self-test
uv run --with mcp==2.2.0 --python 3.13 local-bridge/verify_runtime.py
```

Self-test kiểm tra logic và nhóm tiến trình Windows; các bài dùng runtime giả **không** chứng nhận sandbox của App Server. `verify_runtime.py` kiểm tra App Server thật trên project mẫu. Mã kết thúc 2 nghĩa là phần chạy lệnh chưa đạt; khi chạy qua `uv`, công cụ ngoài có thể báo mã 1.

Khi tunnel coding đã dừng, chạy doctor đầy đủ của script:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\start-chatgpt-coding-tunnel.ps1 -DoctorOnly
```

Không chạy doctor thứ hai trên cùng journal đang bị bridge giữ khóa. Khi tunnel đang chạy, đọc `project_info` và hai endpoint từ địa chỉ trong `.tunnel-client/chatgpt-coding-health.url` (`/healthz`, `/readyz`). Không công khai địa chỉ/khóa của tunnel.

`test_ui.cjs` là kiểm thử Chromium với MCP host mẫu và project tạm; cần Playwright/Chrome đã cài. Bài này kiểm tra diff/áp dụng/hoàn tác và chống thực thi HTML, không thay thế kiểm thử iframe thật trên ChatGPT.

Kiểm thử Security MCP V1 và cả UI:

```powershell
uv run --with mcp==2.2.0 --python 3.13 python -m unittest discover -s .\local-bridge -p "test_*.py" -v
node .\local-bridge\test_security_ui.cjs
node .\local-bridge\test_ui.cjs
git diff --check
```

Phải chạy bộ Python bằng cùng runtime `uv`/`mcp==2.2.0` của tunnel; `python` hệ thống không có SDK `mcp` có thể báo lỗi import dù code không lỗi.

## Tài liệu giao thức

- [Codex App Server](https://learn.chatgpt.com/docs/app-server)
- [Phạm vi permission profiles](https://learn.chatgpt.com/docs/permissions#scope-and-enforcement)
- [Windows sandbox](https://learn.chatgpt.com/docs/windows/windows-sandbox)
- [MCP server cho ChatGPT](https://developers.openai.com/apps-sdk/build/mcp-server/)
- [Giao diện ChatGPT](https://developers.openai.com/apps-sdk/build/chatgpt-ui/)
- [MCP Apps](https://modelcontextprotocol.io/docs/extensions/apps)
