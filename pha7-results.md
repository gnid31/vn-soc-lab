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
