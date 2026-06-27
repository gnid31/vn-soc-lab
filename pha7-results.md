# Pha 7 — HIDS Installation & Integration Results (Windows 10 Agent)

> Cài đặt và cấu hình Wazuh Agent 4.9.2-1 trên Windows 10 client, đăng ký thành công với Wazuh Manager.
> Một phần của việc xây dựng hệ thống giám sát HIDS (Pha 7).

**Ngày thực hiện:** 2026-06-27
**Thời gian:** ~10 phút
**Endpoint:** `DESKTOP-L7FCMBQ` (IP: `192.168.154.164`)
**Wazuh Manager IP:** `192.168.154.163`

---

## 1. Tóm tắt thiết lập

Trong Pha 7, hệ thống giám sát Endpoint được mở rộng với **Wazuh HIDS Agent** hoạt động song song với Sysmon + Winlogbeat hiện tại. Việc cài đặt được thực hiện tự động qua PowerShell dưới quyền Administrator:

1. Tải bộ cài đặt MSI chính thức của Wazuh Agent 4.9.2.
2. Cài đặt chế độ Silent, cấu hình tham số Manager IP (`192.168.154.163`), Agent Name (`DESKTOP-L7FCMBQ`), và mặc định Group là `default`.
3. Kích hoạt và kiểm tra dịch vụ `WazuhSvc`.
4. Đăng ký nhận key thành công từ Wazuh Manager.

---

## 2. Nhật ký cài đặt chi tiết

### 2.1 Bước 1: Tải bộ cài đặt MSI
Tải gói MSI trực tiếp từ repo của Wazuh:
```powershell
$msiPath = "$env:TEMP\wazuh-agent-4.9.2-1.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -OutFile $msiPath
```
*Gói cài đặt có dung lượng ~30.6 MB, lưu tạm tại thư mục Temp của người dùng.*

### 2.2 Bước 2: Cài đặt Silent với cấu hình Manager
```powershell
$MANAGER_IP = "192.168.154.163"
$AGENT_NAME = $env:COMPUTERNAME
Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /q WAZUH_MANAGER=`"$MANAGER_IP`" WAZUH_AGENT_NAME=`"$AGENT_NAME`" WAZUH_AGENT_GROUP=`"default`"" -Wait
```
*Quá trình cài đặt hoàn tất với Exit Code: 0.*

### 2.3 Bước 3: Kích hoạt dịch vụ WazuhSvc
```powershell
Start-Service WazuhSvc
Get-Service WazuhSvc
```

**Kết quả trạng thái dịch vụ:**
```
Status   Name               DisplayName                           
------   ----               -----------                           
Running  WazuhSvc           Wazuh                                 
```

---

## 3. Xác thực kết nối tới Wazuh Manager

Kiểm tra file lưu khóa xác thực của Wazuh Agent (`C:\Program Files (x86)\ossec-agent\client.keys`) để verify kết quả đăng ký thành công:

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\client.keys"
```

**Kết quả key đã nhận:**
```
001 DESKTOP-L7FCMBQ any 8aeb6199d9c863256c39eaf8a8d189dd1607e210b55566c6f94f0eecd58fb331
```
*Agent đã đăng ký thành công với ID `001`, nhận khóa mật mã duy nhất và sẵn sàng gửi thông báo bảo mật (HIDS alerts) về Wazuh Manager.*

---

## 4. Bài học kinh nghiệm & Ghi chú (Lessons Learned)

1. **UAC và PowerShell Elevation**: Việc cấu hình và kích hoạt dịch vụ hệ thống của Wazuh yêu cầu phiên PowerShell chạy dưới quyền quản trị (`Run as Administrator`).
2. **Wazuh Manager Connectivity**: Cần đảm bảo các cổng `1514/TCP` (Agent connection) và `1515/TCP` (Registration) trên Wazuh Manager (VM `192.168.154.163`) đã mở và cho phép kết nối từ dải NAT.

---

## 5. Chẩn đoán và xử lý lỗi enrollment (Duplicate agent name)

### 5.1 Triệu chứng & Chẩn đoán
Mặc dù Agent đã chạy và port kết nối thông suốt, hệ thống báo cáo Agent không hiển thị `online` trên Wazuh Manager (`total_affected_items: 0`).
Kiểm tra `ossec.log` phát hiện lỗi lặp liên tục:
```
2026/06/27 12:08:16 wazuh-agent: ERROR: Duplicate agent name: DESKTOP-L7FCMBQ (from manager)
2026/06/27 12:08:16 wazuh-agent: ERROR: Unable to add agent (from manager)
```

### 5.2 Phân tích Nguyên nhân (Root Cause)
* Trong quá trình cài đặt ban đầu, dịch vụ `WazuhSvc` được kích hoạt trước khi công cụ `agent-auth.exe` hoàn tất việc xin khóa xác thực. 
* Do đó, Agent bắt đầu chạy với file `client.keys` trống và tự động kích hoạt tính năng tự đăng ký (auto-enrollment).
* Cùng lúc đó, `agent-auth.exe` đăng ký thành công tên máy `DESKTOP-L7FCMBQ` với Manager và tạo ra file `client.keys` trên máy local. Tuy nhiên, dịch vụ `WazuhSvc` đã chạy nên không tự động đọc lại file `client.keys` mới này.
* Dịch vụ Agent tiếp tục chạy vòng lặp auto-enrollment gửi yêu cầu đăng ký với tên `DESKTOP-L7FCMBQ` lên Manager. Manager từ chối vì tên này đã được đăng ký bởi phiên `agent-auth.exe` trước đó, dẫn đến lỗi "Duplicate agent name".

### 5.3 Giải pháp xử lý
Thực hiện khởi động lại dịch vụ `WazuhSvc` để buộc Agent nạp lại file `client.keys` đã có khóa xác thực hợp lệ:
```powershell
# Restart dịch vụ WazuhSvc
Restart-Service WazuhSvc
```

### 5.4 Kết quả xác thực (Verification)
Sau khi khởi động lại dịch vụ, kiểm tra `ossec.log` xác nhận kết nối thành công:
```
2026/06/27 12:10:15 wazuh-agent: INFO: Trying to connect to server ([192.168.154.163]:1514/tcp).
2026/06/27 12:10:15 wazuh-agent: INFO: (4102): Connected to the server ([192.168.154.163]:1514/tcp).
2026/06/27 12:10:15 wazuh-agent: INFO: Agent is now online. Process unlocked, continuing...
```
Agent đã kết nối thành công và chuyển sang trạng thái **online**.

