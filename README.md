# n8n Global Error Handler (lite)

Free subset. Error Trigger, the classifier, and a Telegram notice. Email, the optional log branch, and the setup guide are in the full pack.

## English

### Deliverables

- `deliverables/classify_error.py` — map a payload to a class and a notice
- `deliverables/classify_error.sh` — bash wrapper
- `deliverables/workflows/error-handler-telegram.json` — Error Trigger plus Telegram
- `examples/execution_timeout.json` — an execution timeout payload
- `examples/trigger_upstream.json` — a trigger-node failure
- `examples/mapped_timeout.json` — classifier output for the timeout
- `examples/mapped_trigger_upstream.json` — classifier output for the trigger failure

Preview:

```bash
bash deliverables/classify_error.sh classify \
  --fixture examples/execution_timeout.json \
  --now 2026-04-12T08:06:00Z \
  --format text
```

Import `error-handler-telegram.json`. Copy the classifier to `/opt/n8n-error-handler/classify_error.py`. Telegram credential id `PLACEHOLDER_TELEGRAM`, chat id `PLACEHOLDER_CHAT_ID`. No bot token is in the file.

n8n documents that Error Trigger does not run on a manual test. Check upstream docs for your version.

Full version: GUMROAD_URL

## 中文

免费子集：Error Trigger、分类器和 Telegram 通知。邮件、可选日志和安装说明在完整版里。

### 交付物

- `deliverables/classify_error.py` — 把载荷映射成类别和通知
- `deliverables/classify_error.sh` — bash 包装
- `deliverables/workflows/error-handler-telegram.json` — Error Trigger 加 Telegram
- `examples/execution_timeout.json` — 执行超时载荷
- `examples/trigger_upstream.json` — 触发器失败
- `examples/mapped_timeout.json` — 超时的分类结果
- `examples/mapped_trigger_upstream.json` — 触发器失败的分类结果

导入 JSON 后，把分类器放到 `/opt/n8n-error-handler/classify_error.py`。Telegram 凭据 id 是 `PLACEHOLDER_TELEGRAM`，聊天 id 是 `PLACEHOLDER_CHAT_ID`。文件里没有 bot token。

Full version: GUMROAD_URL

## Delivery time / 交付时间

- Lite (this folder): free, available now. / 精简版（本目录）：免费，立即可用。
- Full version: instant download after purchase (GUMROAD_URL). / 完整版：购买后即时下载（GUMROAD_URL）。
