# AGENTS.md — Protocol cho multi-agent collaboration (OPTIONAL)

> **TÙY CHỌN — file này KHÔNG bắt buộc cho người reproduce lab.**
> Áp dụng khi có ≥2 actor (vd Claude Code trên Kali + Antigravity trên Win10) cùng sửa repo song song. Solo human user chỉ commit theo workflow git thông thường — bỏ qua file này không ảnh hưởng dự án.
>
> Nội dung dưới đây quy định protocol cho trường hợp multi-agent.

---

## 1. Nguyên tắc tối cao

> **Deploy-then-document.** CHỈ thêm vào `report.md` những gì ĐÃ thực thi và verify thành công. Kế hoạch / dự định / hypothetical → vào `roadmap.md`. Không bao giờ viết "tôi sẽ làm X" trong `report.md`.

Nếu bạn (AI) đang định thêm "Pha N sẽ làm…" hoặc "Detection rule dự kiến…" vào `report.md`, **STOP** — bài đó phải vào `roadmap.md`.

---

## 2. Workflow bắt buộc cho mỗi lần sửa file

```
┌────────────────────────────────────────────────────────────┐
│  1. git pull --rebase     (TRƯỚC khi sửa, mọi lần)         │
│  2. Sửa file (chỉ những gì đã verify nếu là report.md)     │
│  3. Append 1 dòng vào CHANGELOG.md                          │
│  4. git add <files>                                         │
│  5. git commit -m "<type>(phase-N): <verb> <object>"        │
│  6. git push                                                │
└────────────────────────────────────────────────────────────┘
```

### 2.1 Trường hợp `git pull` báo conflict

- **KHÔNG** tự resolve nếu không 100% chắc.
- Comment conflict markers ra (`<<<<<<<`, `=======`, `>>>>>>>`) trong reply cho user.
- Hỏi user chọn version nào trước khi commit.

### 2.2 Branch strategy

- Lab quy mô nhỏ + 2 AI: commit thẳng vào `main`, không cần branch/PR.
- Ngoại lệ: nếu thay đổi vượt 100 dòng hoặc đụng nhiều file → tạo branch `feat/<slug>`, push, mở PR (`gh pr create`).

---

## 3. Conventional commit message format

```
<type>(phase-<N>): <verb mệnh lệnh> <object>

[Optional body — giải thích why nếu không obvious]
```

| `<type>` | Khi nào dùng |
|---|---|
| `feat` | Thêm chức năng / file / cấu hình mới đã verify |
| `fix` | Sửa lỗi đã document trong CHANGELOG |
| `docs` | Chỉ sửa file `.md`, không đụng config |
| `config` | Thay đổi config production (winlogbeat.yml, kibana.yml, …) |
| `chore` | Việc tạp (cleanup, format, .gitignore) |
| `wip` | (Hạn chế) commit dở dang để đồng bộ giữa 2 máy |

**Ví dụ tốt:**
```
feat(phase-2): add winlogbeat config for win10 endpoint

Output trỏ Logstash:5044 thay vì ES trực tiếp — pipeline đã có
filter normalize Sysmon event_id, không nên bypass.
```

**Ví dụ xấu:**
```
update            ← không biết update cái gì
fix bug           ← không biết bug nào
final commit      ← không có "final" trong git
```

---

## 4. CHANGELOG.md — append-only log

Mỗi sửa file `report.md` PHẢI append 1 dòng vào `CHANGELOG.md`:

```
[YYYY-MM-DD HH:MM] [actor=claude|antigravity|gnid31] [phase=N] mô tả ngắn (1 dòng)
```

Dòng mới luôn ở **cuối file** (append-only, không insert giữa, không sửa dòng cũ).

**Ví dụ:**
```
[2026-06-25 02:00] [actor=claude] [phase=1] hoàn tất cài ELK 8.19.17 trên VPS, heap 512MB
[2026-06-25 02:30] [actor=antigravity] [phase=2] cài Sysmon + Winlogbeat trên Win10-LAPTOP01
```

---

## 5. Quy tắc về secrets

❌ **TUYỆT ĐỐI KHÔNG** commit:

- Password thật của user `elastic` hoặc bất kỳ user nào
- IP nội bộ / private (chỉ public IP `43.228.215.234` được phép)
- Token API (Anthropic, Google, GitHub PAT)
- File credentials nào dù chmod 600
- Output `gh auth status`, `gh auth token`

Thay vào đó dùng placeholder:

| Thực tế | Trong git |
|---|---|
| Password `TRNu...` | `<ELASTIC_PASSWORD>` hoặc `***` |
| API token cụ thể | `<GH_TOKEN>` |
| IP private nội bộ | `<INTERNAL_IP>` |

Nếu lỡ commit secret → **báo ngay user**, KHÔNG tự push thêm. Xử lý: `git reset --soft HEAD~1` rồi sửa, hoặc dùng `git filter-repo` nếu đã push.

`.gitignore` đã chặn các pattern phổ biến — kiểm tra `.gitignore` trước khi tạo file mới.

---

## 6. Cấu trúc thư mục — không tự thêm folder mới

```
vn-soc-lab/
├── README.md             # giới thiệu repo (tiếng Anh, cho recruiter)
├── report.md             # deliverable — CHỈ phần đã done
├── roadmap.md            # plan các pha sắp tới
├── CHANGELOG.md          # append-only log
├── AGENTS.md             # file này
├── .gitignore
├── configs/              # config production (pipeline, winlogbeat.yml, sysmon xml)
├── detection-rules/      # Pha 3 — file .md mô tả + .ndjson export
└── incidents/            # Pha 5 — Incident Report
```

Nếu thấy cần folder mới → propose trong commit message, KHÔNG tự tạo.

---

## 7. Kiểm tra trước commit (mental checklist)

Đọc qua trước khi `git commit`:

- [ ] `git pull --rebase` đã chạy trong vòng 5 phút gần nhất chưa?
- [ ] File `report.md` có chứa thứ gì hypothetical/chưa-verify không? → chuyển sang `roadmap.md`.
- [ ] Có secret thật trong diff không? → thay placeholder.
- [ ] Đã append 1 dòng vào `CHANGELOG.md`?
- [ ] Commit message có theo `<type>(phase-N): ...` không?

---

## 8. Bảo trì memory (chỉ Claude)

Claude Code có hệ memory tại `~/.claude/projects/-home-kali/memory/`. **Đừng** copy nội dung memory vào repo này. Nếu cần share context giữa 2 AI, viết vào `AGENTS.md` hoặc `README.md`.

---

## 9. Khi unsure

Nếu không chắc nên làm gì → **hỏi user**. Im lặng làm sai tốn nhiều thời gian hơn hỏi.
