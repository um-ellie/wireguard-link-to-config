# Wireguard link to Config

این برنامه یه ابزار کوچیک و ساده‌ست که نوشتم تا لینک‌های وایرگارد (wireguard:// یا wg://) رو خیلی راحت و بی‌دردسر به فایل استاندارد کانفیگ (.conf) تبدیل کنه، همین!

خیلی وقتا کانفیگ وایرگارد رو به صورت لینک دریافت می‌کنیم، اما کلاینت‌های رسمی دسکتاپ (مخصوصاً توی ویندوز و لینوکس) فایل .conf می‌خوان و نمیشه لینک رو مستقیم توشون ایمپورت کرد. برای اینکه هر دفعه نخواهیم دستی بشینیم کلیدها، آدرس‌ها و اندپوینت رو از داخل لینک جدا کنیم، این ابزار این کار رو خودکار و توی یه ثانیه انجام میده.

---

## ویژگی‌ها و نکات مهم

- **امن در ویندوز (بدون بلاک یا حذف توسط Defender):** خروجی کامپایل‌شده زبان Go یک فایل باینری واقعی (Native PE) است و برخلاف ابزارهایی مثل PyInstaller، هیچ نیازی به استخراج فایل در پوشه موقت (%TEMP%) ندارد و توسط سیستم‌های امنیتی ویندوز کاملاً معتبر شناخته می‌شود.
- **سازگاری کامل مسیرها و دسترسی‌ها:**
  - در ویندوز: ذخیره در مسیر جاری و جلوگیری از بسته شدن ناگهانی کنسول در صورت دابل‌کلیک.
  - در لینوکس: تنظیم خودکار دسترسی فایل روی chmod 600 جهت حفظ امنیت کلید خصوصی.
- **دست‌کاری نکردن MTU:** سرخود مقداری برای MTU تنظیم نمیکنه تا اتصال شبکه به هم نریزه؛ فقط در صورتی که خود لینک حاوی مقدار MTU باشه اون رو به فایل اضافه میکنه.
- **فهمیدن خودکار اسم کانفیگ:** اگه آخر لینک بعد از کاراکتر # اسم سرور یا لوکیشن قید شده باشه، خودش استخراجش میکنه و به عنوان اسم پیش‌فرض پیشنهاد میده.
- **نسخه پایتون:** اگه ترجیح میدید به جای باینری از اسکریپت پایتون استفاده کنید، فایل `wireguard-link-to-config.py` هم داخل پروژه در دسترسه.

---

## فایل‌های آماده اجرا

فایل‌های اجرایی در پوشه `dist/` قرار دارند:

- **ویندوز:** `dist/wireguard-link-to-config.exe`
- **لینوکس:** `dist/wireguard-link-to-config`

---

## نحوه استفاده

### ۱. اجرای تعاملی (Interactive)

- **در ویندوز:** دابل‌کلیک روی `wireguard-link-to-config.exe` یا اجرا در ترمینال:
  ```cmd
  wireguard-link-to-config.exe
  ```
- **در لینوکس:**
  ```bash
  ./dist/wireguard-link-to-config
  ```

برنامه لینک را می‌پرسد و نام کانفیگ و مسیر ذخیره را به صورت خودکار پیشنهاد می‌دهد (کافیست Enter بزنید).

### ۲. اجرای سریع با خط فرمان (CLI)

```bash
./dist/wireguard-link-to-config -l "wireguard://...#Germany" -o ./configs
```

**پارامترهای خط فرمان:**
- `-l`, `--link`: لینک وایرگارد (wireguard://... یا wg://...)
- `-n`, `--name`: نام دلخواه برای فایل کانفیگ
- `-o`, `--output`: مسیر ذخیره‌سازی فایل (پیش‌فرض: پوشه فعلی)
- `-y`, `--yes`: بازنویسی خودکار در صورت وجود فایل قبلی
- `--stdout`: چاپ متن کانفیگ در خروجی بدون ذخیره روی دیسک
- `-v`, `--version`: نمایش شماره نسخه برنامه

---

## تست‌ها (Tests)

برای اطمینان از سلامت کارکرد:

```bash
# تست‌های نسخه Go
go test -v ./...

# تست‌های نسخه Python
python3 test_wireguard_link_to_config.py
```

---

## کامپایل مجدد (Build)

برای کامپایل مجدد فایل‌های اجرایی لینوکس و ویندوز در هر زمان:

```bash
./build.sh
```

خروجی‌ها در پوشه `dist/` بازسازی خواهند شد.

---

# Wireguard link to Config (English)

This is a small, simple utility created to convert WireGuard links (wireguard:// or wg://) into standard .conf configuration files.

Often WireGuard configs are shared as URLs, but official desktop clients on Windows and Linux expect a .conf file instead of a link. Rather than manually parsing and copying keys, endpoints, and addresses by hand, this tool takes care of it automatically in a second.

---

## Key Features

- **Safe on Windows (No Defender false positives):** Compiled with Go as a true native binary (Native PE). Unlike tools like PyInstaller, it never extracts anything to %TEMP% and is recognized as safe by Windows security systems.
- **Cross-platform path and permission handling:**
  - On Windows: Saves to the current directory and prevents the console window from closing instantly when double-clicked.
  - On Linux: Automatically applies chmod 600 permissions to protect the private key.
- **Safe MTU handling:** Does not set an arbitrary MTU to prevent network disruption; it only includes MTU if the input link explicitly specifies one.
- **Automatic name detection:** Automatically extracts the server or location name from the # fragment at the end of the link and suggests it as default.
- **Python alternative:** If you prefer using Python directly, `wireguard-link-to-config.py` is also available in the repository.

---

## Prebuilt Binaries

Binaries are located in the `dist/` folder:

- **Windows:** `dist/wireguard-link-to-config.exe`
- **Linux:** `dist/wireguard-link-to-config`

---

## Usage

### 1. Interactive Mode

- **On Windows:** Double-click `wireguard-link-to-config.exe` or run in terminal:
  ```cmd
  wireguard-link-to-config.exe
  ```
- **On Linux:**
  ```bash
  ./dist/wireguard-link-to-config
  ```

The program prompts for the link and automatically suggests the config name and output path (just press Enter).

### 2. Command-line Mode (CLI)

```bash
./dist/wireguard-link-to-config -l "wireguard://...#Germany" -o ./configs
```

**CLI Flags:**
- `-l`, `--link`: WireGuard link (wireguard://... or wg://...)
- `-n`, `--name`: Desired config name
- `-o`, `--output`: Output directory path (default: current directory)
- `-y`, `--yes`: Overwrite existing file without confirmation
- `--stdout`: Print config content to stdout without saving to disk
- `-v`, `--version`: Show program version

---

## Tests

To verify functionality:

```bash
# Run Go unit tests
go test -v ./...

# Run Python unit tests
python3 test_wireguard_link_to_config.py
```

---

## Building from Source

To recompile both Linux and Windows binaries at any time:

```bash
./build.sh
```

Binaries will be generated inside the `dist/` directory.
