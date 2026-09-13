\# Nâng cấp Local MCP Bridge dùng Codex App Server



\## 1. Kiến trúc và lựa chọn đã chốt



```text

ChatGPT Web + bảng điều khiển

&#x20;             ↓

Secure MCP Tunnel hiện có

&#x20;             ↓

Python MCP Bridge — kiểm tra quyền, lưu đợt sửa

&#x20;             ↓

Codex App Server STDIO — chạy lệnh, đọc file, MCP, skills

&#x20;             ↓

Project local — mở cùng thư mục trong Codex desktop

```



\- ChatGPT Web trực tiếp suy nghĩ và viết code. Không sử dụng agent Codex để code, review hoặc tự duyệt quyền.

\- Giữ Python, SDK `mcp==1.30.0`, tunnel coding và script khởi động hiện có. Không thêm máy chủ public.

\- Bảng xem trước, hoàn tác, tiến độ và nút Dừng nằm ngay trong ChatGPT Web.

\- ChatGPT được tự áp dụng đợt sửa sau khi chuẩn bị diff; nếu Khầy chỉ yêu cầu xem trước thì không ghi file.

\- Giữ project hiện tại tại `D:/AI/New folder`. Kiểm thử Git/test/build bằng project mẫu tạm riêng.

\- Desktop dùng chung project; không đặt việc tự mở tab/panel làm điều kiện hoàn thành.



App Server hỗ trợ chạy lệnh không cần tạo lượt AI, nhưng các API filesystem và MCP vẫn cần lớp kiểm soát quyền riêng của bridge. \[Tài liệu App Server](https://learn.chatgpt.com/docs/app-server)



\## 2. Các nâng cấp cần thực hiện



\### A. Kết nối và sử dụng bộ thực thi của Codex



\- Bridge quản lý một tiến trình App Server riêng, chạy ẩn qua STDIO; không phụ thuộc daemon Unix hay tiến trình của cửa sổ Codex đang mở.

\- Xác định đúng `codex.exe` đã cài; không chạy trực tiếp shim `codex.ps1` bằng cơ chế subprocess không hỗ trợ nó.

\- Dùng một kết nối lâu dài, có khởi tạo, phân phối phản hồi theo request ID và tiếp nhận thông báo tiến độ.

\- Chỉ cho gọi danh sách API cần thiết. Không cung cấp tool chuyển tiếp API hoặc shell tùy ý.

\- Khi App Server mất kết nối: báo trạng thái lỗi, không tự chạy lại lệnh hoặc ghi lại đợt sửa chưa rõ kết quả.

\- Kiểm tra phiên bản và khả năng thực tế khi khởi động; không tự nâng Codex hay hạ xuống chế độ không bảo vệ.



\### B. Xem trước và hoàn tác từng đợt sửa



Một đợt sửa có mã riêng, tên mô tả, danh sách file, bản trước/sau và SHA-256.



Luồng xử lý:



```text

Chuẩn bị thay đổi → xem diff → áp dụng → có thể hoàn tác

```



\- Hỗ trợ tạo file, ghi lại file và thay đoạn text khớp chính xác; chưa thêm xóa/đổi tên file tổng quát.

\- Chuẩn bị diff không làm thay đổi project. Kiểm tra toàn bộ đường dẫn, kích thước và SHA trước khi áp dụng.

\- Tái sử dụng cách ghi file tạm rồi thay thế của bridge hiện tại. Không thay bằng `fs/writeFile` nếu việc đó làm mất tính an toàn.

\- Lưu nhật ký và bản sao bằng SQLite có sẵn trong Python, ngoài project. Giữ mặc định 30 đợt đã hoàn tất; không dọn đợt đang lỗi hoặc chưa phục hồi.

\- Chỉ hoàn tác khi tất cả file liên quan vẫn khớp bản sau của đợt đó. Nếu có sửa mới, từ chối cả đợt và chỉ rõ file xung đột.

\- File được tạo bởi đợt sửa chỉ được gỡ khi hoàn tác nếu nội dung vẫn khớp bản đã tạo.

\- Nếu ghi lỗi giữa chừng hoặc bridge khởi động lại sau sự cố, dùng nhật ký để phục hồi có kiểm tra SHA. Không tuyên bố nhiều file được ghi nguyên tử cùng lúc.

\- Hoàn tác không dùng `git reset`, không đụng Git index và không xóa thay đổi có sẵn của Khầy.



\### C. Tìm code nhanh và đọc đúng đoạn



\- Thêm tìm nội dung bằng `rg` đã cài, thực thi qua App Server; không xây cơ sở dữ liệu tìm kiếm riêng.

\- Cho lọc theo thư mục, loại file, chữ thường/hoa; mặc định tìm chuỗi chính xác.

\- Kết quả trả đường dẫn tương đối, số dòng và vài dòng ngữ cảnh; giới hạn số kết quả và có thông tin tiếp tục đọc.

\- Nâng `read\_file` để chọn khoảng dòng, trả tổng số dòng, phần đã đọc và SHA của toàn file.

\- Dùng API filesystem/watch của App Server để phát hiện thay đổi và làm mới trạng thái; luôn kiểm tra SHA trước khi ghi.

\- Tìm kiếm, đọc file và diff phải dùng chung bộ lọc file nhạy cảm, kể cả khi xem diff toàn project.



\### D. Test/build có tiến độ và nút Dừng



\- Chạy task qua `command/exec`, nhận `outputDelta` và dùng `command/exec/terminate` để dừng.

\- Task dài trả `run\_id` ngay; ChatGPT và bảng điều khiển lấy trạng thái/log theo từng phần.

\- Hiển thị trạng thái, thời gian chạy, log mới và mã kết thúc. Chỉ hiển thị phần trăm khi task thực sự cung cấp số liệu; không tạo tiến độ giả.

\- Mặc định một task chạy tại một thời điểm. Khóa thao tác áp dụng/hoàn tác trong lúc test/build chạy để tránh sửa file giữa bài kiểm tra.

\- Nút Dừng phải dừng được cả công việc con thuộc task; không dừng Codex desktop hoặc tiến trình không thuộc bridge.

\- Có timeout, giới hạn log và xử lý bấm Dừng nhiều lần. Không tự chạy lại task sau mất kết nối.

\- Chỉ nhận task ID được cấu hình local; không cho ChatGPT thêm lệnh, đổi thư mục chạy hoặc bật mạng tùy ý.

\- Giữ hai task Git hiện có. Không tự suy đoán lệnh test/build cho project hiện tại.



\### E. Dùng lại MCP, skills và ngữ cảnh Codex



\- Bản đầu chỉ xuất hai khả năng của MCP `openaiDeveloperDocs`: tìm kiếm và đọc tài liệu.

\- Gọi qua `mcpServer/tool/call`, dùng một ngữ cảnh kỹ thuật tạm khi API yêu cầu; không bắt đầu lượt sinh code.

\- Tắt MCP không được chọn trong tiến trình bridge; không sửa cấu hình Codex toàn cục và không tự xuất các tool riêng của desktop.

\- Dùng `skills/list` để tìm skill khả dụng; cho ChatGPT đọc hướng dẫn và tài liệu tham chiếu bên trong đúng thư mục skill đã xác định.

\- Skill chỉ cung cấp hướng dẫn; không tự cấp quyền chạy script hoặc mở thêm MCP.

\- Cho đọc danh sách/lịch sử task Codex thuộc đúng project, theo yêu cầu; không đọc toàn bộ lịch sử tài khoản, không tiếp tục hay sửa task cũ.

\- Thêm thông tin project: Git có khả dụng không, task được duyệt, trạng thái App Server và các khả năng đang bật.



\### F. Bảng điều khiển ChatGPT và sử dụng desktop



\- Một giao diện HTML/JavaScript nhỏ, không React và không thêm chuỗi build frontend.

\- Ba phần: \*\*Đợt sửa\*\*, \*\*Test/build\*\*, \*\*Project và kết nối\*\*.

\- Có xem diff theo file, Áp dụng đợt đang chờ, Hoàn tác đợt đã ghi và Dừng task.

\- Tách tool hiển thị khỏi tool dữ liệu để cập nhật log không làm bảng mở lại liên tục. Lấy trạng thái mỗi 2 giây khi bảng đang hiển thị và có task chạy.

\- Render code/log như văn bản, không thực thi HTML lấy từ project.

\- Các thao tác vẫn dùng được bằng hội thoại nếu bảng không hiển thị.

\- Codex desktop mở cùng thư mục để xem file; Git review chỉ có khi project là repo Git. Diff từng đợt trong ChatGPT vẫn hoạt động với thư mục không có Git.



Giao diện sử dụng MCP Apps bridge và tài nguyên UI trả qua MCP, không mở thêm cổng local cho trình duyệt truy cập. \[Hướng dẫn UI chính thức](https://developers.openai.com/apps-sdk/build/chatgpt-ui/)



\## 3. Giao diện tool và tương thích



| Nhóm | Tool bổ sung hoặc điều chỉnh |

|---|---|

| Trạng thái | `project\_info` |

| Tìm/đọc | `search\_code`; mở rộng `read\_file` bằng khoảng dòng |

| Đợt sửa | `prepare\_changes`, `list\_changes`, `get\_change`, `apply\_changes`, `undo\_changes` |

| Task dài | `list\_tasks`, `start\_task`, `get\_task\_run`, `stop\_task\_run` |

| Skills | `list\_skills`, `read\_skill`, `read\_skill\_resource` |

| Ngữ cảnh Codex | `list\_codex\_threads`, `read\_codex\_thread` |

| MCP tài liệu | `codex\_docs\_search`, `codex\_docs\_fetch` |

| Giao diện | `show\_control\_panel` |



\- Giữ tên và tham số của 6 tool cũ. `write\_file` và `apply\_patch` đi qua cơ chế đợt sửa một file để có lịch sử hoàn tác.

\- Giữ `run\_task` đồng bộ để tương thích, nhưng dùng chung bộ chạy mới; task dài dùng `start\_task`.

\- Các thao tác mới có ID chống thực hiện trùng khi mạng gửi lại yêu cầu.

\- Trả lỗi rõ ràng cho xung đột SHA, task đang bận, mất runtime và khả năng chưa hỗ trợ.

\- Annotation phản ánh đúng tác động; lựa chọn “tự áp dụng” không bỏ qua xác nhận bắt buộc của ChatGPT.



\## 4. Bảo vệ dữ liệu và giới hạn



\- Giữ một project được phép ghi; ChatGPT không được đổi cấu hình, sửa bridge hoặc truy cập kho bản sao trực tiếp.

\- Chặn đường dẫn thoát project, symlink/junction, hardlink không an toàn, Windows ADS, `.env`, khóa, certificate và file nhị phân.

\- Dùng permission profile riêng cho command: chỉ project và đường dẫn runtime/cache cần thiết, không mạng mặc định, chặn dữ liệu nhạy cảm.

\- Không coi `shell=False` hoặc danh sách task là sandbox. Nếu Windows không thực thi được policy đã chọn, từ chối chạy task.

\- Không truyền API key của tunnel vào App Server/task; không ghi key, nội dung file hay lịch sử đầy đủ vào log chẩn đoán.

\- Tool filesystem, skill, lịch sử và MCP phải tự kiểm tra phạm vi; quyền sandbox của command không tự bảo vệ các nhóm này. \[Phạm vi permission profiles](https://learn.chatgpt.com/docs/permissions#scope-and-enforcement)

\- Hoàn tác chỉ bao phủ đợt sửa do bridge ghi; không tự hoàn tác tác động của test/build hay công cụ bên ngoài.



\## 5. Trình tự triển khai và tiêu chí nghiệm thu



Triển khai theo thứ tự:



1\. Kết nối App Server, kiểm tra quyền Windows và vòng đời tiến trình.

2\. Cơ chế đợt sửa, phục hồi lỗi và tương thích tool cũ.

3\. Tìm kiếm, đọc theo đoạn và thông tin project.

4\. Task bất đồng bộ, log và dừng tiến trình.

5\. MCP Docs, đọc skills và lịch sử đúng project.

6\. Bảng điều khiển, kiểm thử qua tunnel và hướng dẫn dùng desktop cùng project.



Kiểm thử bắt buộc:



\- Kết nối STDIO, đọc file và thực thi task mà không xuất hiện yêu cầu sinh code/review.

\- Xem trước không ghi file; áp dụng nhiều file đúng diff; hoàn tác trả đúng nội dung cũ.

\- Từ chối SHA sai, patch mơ hồ, file bị sửa thêm, áp dụng trùng và đường dẫn không an toàn.

\- Giả lập lỗi giữa đợt ghi và khởi động lại; không mất thay đổi ngoài bridge.

\- Search/read/diff không lộ file bị chặn; hỗ trợ tiếng Việt, CRLF và đường dẫn có khoảng trắng.

\- Task có log tăng dần, kết thúc thành công/thất bại/timeout; Dừng hoạt động cả với tiến trình con.

\- Task không đọc được dữ liệu ngoài quyền, không nhận khóa tunnel và không tự mở mạng.

\- Chỉ MCP được duyệt được gọi; skill và lịch sử không mở rộng quyền project.

\- Bảng ChatGPT xem diff, hoàn tác và dừng thật qua tunnel; kiểm tra gửi lại yêu cầu và mất kết nối.

\- Script khởi động chạy được trên Windows PowerShell 5.1; `doctor`, `healthz`, `readyz` đạt và không ảnh hưởng tunnel Blender/SolidWorks.