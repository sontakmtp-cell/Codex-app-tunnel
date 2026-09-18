Trong quá trình chạy Security Scan trên Codex Bridge local, tôi gặp các vấn đề sau:

1. `security_complete_scan` hoàn tất thành công:

   * Scan ID: `abc8fa45-2589-499d-bed2-7a07e6d0738e`
   * `status: completed`
   * `phase: complete`
   * Toàn bộ các phase từ `preflight` đến `finalization` đều đã được commit.

2. Ngay sau khi scan hoàn tất, gọi:

`security_list_findings(scan_id="abc8fa45-2589-499d-bed2-7a07e6d0738e")`

thì request bị timeout.

Thông báo nhận được:

`Code Mode tool call timed out.`

3. Tôi retry lại riêng `security_list_findings` với cùng Scan ID và `max_results=100`.

Kết quả vẫn:

`Code Mode tool call timed out.`

Tức là lỗi lặp lại được ít nhất 2 lần liên tiếp sau khi scan đã ở trạng thái `completed`.

4. Ngoài ra, response từ `security_complete_scan` vẫn trả:

`findingCounts: null`

và:

`coverageSoFar: null`

mặc dù phase `finalization` trước đó đã được commit với 2 findings và coverage data.

Cần kiểm tra trực tiếp workflow:

`security_commit_phase(finalization)`
→ `security_complete_scan`
→ `security_list_findings`

và xác định vì sao scan hoàn thành nhưng `security_list_findings` bị timeout, đồng thời vì sao completed scan vẫn trả `findingCounts: null` và `coverageSoFar: null`.
