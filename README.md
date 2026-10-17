# اخوان پنل (Akhavan Panel)

پنل مدیریت سرور VPN شخصی: **Xray (VLESS + Reality)** با پنل وب فارسی، بک‌اند **Node.js** یا **Python**، و اجرای **Docker**.
هر دو بک‌اند یک کار را می‌کنند و فایل داده‌ی یکسان دارند؛ هر کدام را خواستی انتخاب کن.

> English summary at the bottom.

## امکانات

- ورود با نام کاربری/رمز، مسیر مخفی پنل، HTTPS (گواهی خودامضا یا گواهی خودت)، محدودیت تلاش ورود
- ساخت چند **کانفیگ** (هر دستگاه یک کانفیگ): لینک `vless://`، QR، فعال/غیرفعال، حذف، UUID جدید، مصرف ترافیک
- **آدرس اشتراک (Subscription)** برای هر کانفیگ: همهٔ سرورها یکجا و همیشه به‌روز
- چند **سرور** روی یک VPS (پورت و SNI متفاوت؛ اگر یکی فیلتر شد بقیه کار می‌کنند) + دکمهٔ تست SNI
- افزودن لینک سرورهای **VPS دیگر** تا همه در یک اشتراک جمع شوند (چند کشور)
- Xray خودکار بالا می‌آید، با هر تغییر پیکربندی اعتبارسنجی می‌شود و در صورت خطا دوباره راه می‌افتد
- ترافیک تورنت و آدرس‌های داخلی/خصوصی سرور بلاک است

## نیازمندی‌ها

یک VPS با Ubuntu/Debian (یا لینوکس مشابه)، IPv4 عمومی، دسترسی root، و دو پورت TCP باز: **443** (VPN) و **8443** (پنل).

> قبل از خرید، شرایط استفاده‌ی ارائه‌دهنده را بخوان و مطمئن شو اجرای پروکسی/VPN شخصی را مجاز می‌داند. بعضی میزبان‌ها آن را ممنوع کرده‌اند و حساب را می‌بندند. اینکه کدام ارائه‌دهنده به مشتری ایرانی سرویس می‌دهد یا پرداخت را می‌پذیرد، را نمی‌توانم از طرف تو بررسی کنم.

## نصب سریع (Docker، پیشنهادی)

```bash
git clone https://github.com/<حساب-تو>/<نام-مخزن>.git
cd <نام-مخزن>
sudo bash install.sh --name Akhavan-DE --country DE --bbr
```

(اگر فایل‌ها را از رابط وب گیت‌هاب آپلود کردی، دسترسی اجرایی از بین می‌رود؛ به همین دلیل با `bash` اجرا می‌کنیم.)

اسکریپت Docker را (اگر نباشد) نصب می‌کند، پنل را می‌سازد و در پایان چاپ می‌کند:
**آدرس پنل**، **نام کاربری**، **رمز** و **اولین لینک کانفیگ**. همان‌ها در `data/CREDENTIALS.txt` هم ذخیره می‌شود (بعد از ذخیره‌ی رمز پاکش کن).

گزینه‌ها: `--backend python` (به‌جای Node)، `--panel-port 8443`، `--reality-port 443`، `--sni www.microsoft.com`، `--host IP_یا_دامنه`، `--bbr` (سرعت بهتر روی مسیرهای طولانی).
دوباره اجرا کردنش امن است: داده‌ها می‌مانند و فقط به‌روز می‌شود.

مرورگر هشدار گواهی می‌دهد (گواهی خودامضاست). **اثر انگشت SHA-256** چاپ‌شده در خروجی نصب را با اثر انگشت گواهی در مرورگر مقایسه کن و ادامه بده.

## اجرا بدون Docker

```bash
sudo bash scripts/install-xray.sh              # نصب Xray با بررسی SHA-256
sudo mkdir -p /opt/akhavan-panel && sudo cp -r node python web scripts /opt/akhavan-panel/
sudo cp .env.example /opt/akhavan-panel/.env   # و مقادیرش را ویرایش کن
# Node ≥ 18 (روی ۲۲ تست شده) و openssl لازم است:
sudo cp scripts/akhavan-panel.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now akhavan-panel
sudo journalctl -u akhavan-panel -n 50          # آدرس پنل و رمز اولیه
```

برای نسخهٔ Python، در فایل service خط `ExecStart` را به `/usr/bin/python3 /opt/akhavan-panel/python/app.py` تغییر بده (Python ≥ 3.9، روی ۳٫۱۲ تست شده؛ فقط کتابخانه‌ی استاندارد).

## استفاده از پنل

1. **کانفیگ‌ها**: نام دستگاه را بنویس و «افزودن» بزن. لینک را کپی کن یا QR را اسکن کن.
2. **سرورها**: سرور دیگری (پورت/SNI دیگر) اضافه کن؛ برای هر کانفیگ یک لینک جدید ساخته می‌شود. پورت جدید را در فایروال باز کن.
   - SNI باید سایتی باشد که TLS 1.3 و h2 دارد؛ دکمهٔ «تست SNI از سمت سرور» همین را می‌سنجد.
3. **چند VPS**: روی هر VPS یک پنل نصب کن. لینک‌های سرور دوم را در پنل اول، بخش «سرورهای دیگر» بچسبان تا به آدرس اشتراک اضافه شود.
4. **تنظیمات**: آدرس سرور (IP یا دامنه) در همهٔ لینک‌ها، تغییر رمز.

## اتصال دستگاه‌ها

- **ویندوز**: برنامه‌ی اخوان VPN (فایل جدا). لینک را «افزودن سرور» کن، یا آدرس اشتراک را در تنظیمات بگذار تا لیست خودکار به‌روز شود.
- **اندروید / iOS**: v2rayNG، Hiddify یا Streisand؛ QR را اسکن کن یا لینک را از کلیپ‌بورد وارد کن.
- اگر اپی آدرس اشتراک را به‌خاطر گواهی خودامضا نپذیرفت، لینک‌ها را با «کپی همهٔ لینک‌ها» وارد کن، یا یک دامنه + گواهی معتبر بگذار (`TLS_CERT` و `TLS_KEY` در `.env`).

## امنیت

- رمز و کلیدها فقط در `data/` (دسترسی 600) هستند؛ هیچ‌چیز محرمانه‌ای در مخزن گیت‌هاب نیست. `data/` و `.env` را commit نکن.
- پنل پشت یک مسیر تصادفی است و ۵ ورود ناموفق، ۱۵ دقیقه قفل می‌کند. برای امن‌ترین حالت در `.env` بگذار `PANEL_BIND=127.0.0.1` و با تونل SSH وصل شو: `ssh -L 8443:127.0.0.1:8443 root@IP`.
- فراموشی رمز: `docker compose exec akhavan-panel node server.js --reset-password` (برای Python: `python3 app.py --reset-password`).
- فایل `data/state.json` همهٔ کانفیگ‌ها و کلیدهاست؛ از آن پشتیبان بگیر.

## به‌روزرسانی / حذف

```bash
git pull && sudo bash install.sh     # به‌روزرسانی (داده‌ها می‌مانند)
sudo bash uninstall.sh               # توقف   (با --purge داده‌ها هم پاک می‌شود)
```

## عیب‌یابی

- **پنل باز نمی‌شود**: پورت 8443 در فایروال ارائه‌دهنده باز است؟ `docker logs akhavan-panel`
- **VPN وصل نمی‌شود**: پورت 443 باز است؟ آدرس سرور در تنظیمات درست است؟ «تست SNI» را بزن و در صورت لزوم SNI دیگری انتخاب کن.
- **اتصال اول کند است**: DNS خود VPS را بررسی کن؛ سمت سرور، Xray درخواست‌ها را سریع پردازش می‌کند.
- **Xray بالا نیامد**: تب «وضعیت و گزارش» خطا را نشان می‌دهد (مثلاً پورت قبلاً توسط برنامهٔ دیگری گرفته شده).

## تست‌ها

```bash
BASE=http://127.0.0.1:8443/مسیر ADMIN_PASS=... DATA_DIR=... node tests/api.test.js   # قرارداد API (هر دو بک‌اند)
XRAY_BIN=xray python3 tests/crosscheck.py                                            # Node و Python باید یکسان رفتار کنند
XRAY_BIN=xray SINGBOX_BIN=sing-box CLIENT_DIR=... tests/e2e.sh node|python           # تونل واقعی تا اینترنت
```

---

## English summary

Akhavan Panel is a self-hosted web panel for a personal **Xray VLESS + Reality** VPN. Two interchangeable zero-dependency backends
(**Node.js** and **Python**, same `data/state.json` and identical Xray config) and a Docker setup.
Per-device configs with links/QR/subscription URLs, multiple servers (ports/SNIs) per VPS, aggregation of other VPSs into one subscription,
traffic stats, scrypt-hashed admin password, secret panel path, HTTPS (self-signed or your own certificate).

Quick start on a fresh Ubuntu/Debian VPS: `sudo bash install.sh --name Akhavan-DE --country DE --bbr` → prints the panel URL, username, password and the first config link.
Check your hosting provider's terms: personal proxy/VPN use is prohibited by some providers.

MIT licensed.
