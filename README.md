# Wireguard link to Config

این برنامه یه ابزار کوچیک و کاربردی است که لینک‌های وایرگارد (`wireguard://` یا `wg://`) را به فایل‌های استاندارد کانفیگ (`.conf`) تبدیل می‌کند.

خیلی وقتا کانفیگ وایرگارد رو به صورت لینک دریافت می‌کنیم، اما کلاینت‌های رسمی دسکتاپ (مخصوصاً توی ویندوز و لینوکس) فایل `.conf` می‌خوان و نمیشه لینک رو مستقیم توشون ایمپورت کرد. این ابزار به راحتی لینک‌های تکی یا دسته‌ای را از متن یا فایل می‌خواند و کانفیگ‌های مرتب می‌سازد.

---

## ویژگی‌ها و نکات مهم

- **امن در ویندوز (بدون بلاک یا حذف توسط Defender):** خروجی کامپایل‌شده زبان Go یک فایل باینری واقعی (Native PE) است و هیچ وابستگی خارجی یا نیاز به استخراج فایل در پوشه موقت ندارد.
- **کنترل هوشمند سطح دسترسی فایل (اختیاری بودن chmod 600):** 
  - در حالت تعاملی (Interactive) در لینوکس از شما سوال پرسیده می‌شود که آیا مایل به اعمال سطح دسترسی ۶۰۰ (فقط خواندنی برای کاربر جاری) هستید یا سطح دسترسی پیش‌فرض سیستم را می‌خواهید.
  - در خط فرمان (CLI) با فلگ اختیاری `-p` یا `--chmod-600` فعال می‌شود.
- **پشتیبانی از فایل و تبدیل گروهی (Batch Processing):**
  - امکان معرفی یک فایل متنی حاوی چندین لینک وایرگارد با پارامتر `-f` یا وارد کردن آدرس فایل در ورودی تعاملی.
  - نام‌گذاری خودکار و هوشمند برای جلوگیری از تداخل نام‌ها در تبدیل گروهی (مثل `Server.conf` و `Server_1.conf`).
- **پارس دقیق و مقاوم در برابر کاراکترهای خاص:** پشتیبانی کامل از لینک‌های دارای URL Encode (`%3D`، `%2F`، `%2C`)، کاراکترهای `+` و `/` در کلیدهای Base64 و ساختارهای مختلف لینک‌ها.
- **دست‌کاری نکردن MTU:** سرخود مقداری برای MTU تنظیم نمی‌کند؛ فقط در صورتی که خود لینک حاوی مقدار MTU باشد آن را به فایل اضافه می‌کند.
- **فهمیدن خودکار اسم کانفیگ:** استخراج خودکار اسم سرور/لوکیشن از انتهای لینک بعد از کاراکتر `#`.
- **نسخه پایتون:** علاوه بر فایل اجرایی Go، اسکریپت `wireguard-link-to-config.py` نیز در دسترس است.

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

برنامه لینک را می‌پرسد (می‌توانید یک لینک تکی یا آدرس یک فایل متنی `.txt` حاوی چندین لینک را وارد کنید) و گزینه‌ها را به شما پیشنهاد می‌دهد.

### ۲. اجرای سریع با خط فرمان (CLI)

**تبدیل یک لینک تکی:**
```bash
./dist/wireguard-link-to-config -l "wireguard://...#Germany" -o ./configs
```

**تبدیل گروهی لینک‌ها از یک فایل متنی:**
```bash
./dist/wireguard-link-to-config -f links.txt -o ./configs
```

**اعمال دسترسی اختصاصی ۶۰۰ در لینوکس:**
```bash
./dist/wireguard-link-to-config -f links.txt -o ./configs -p
```

**پارامترهای خط فرمان:**
- `-l`, `--link`: لینک وایرگارد (`wireguard://...` یا `wg://...`)
- `-f`, `--file`: مسیر فایل متنی حاوی لینک(ها) برای تبدیل تکی یا گروهی
- `-n`, `--name`: نام دلخواه برای فایل کانفیگ (مخصوص لینک تکی)
- `-o`, `--output`: مسیر ذخیره‌سازی فایل (پیش‌فرض: پوشه فعلی)
- `-p`, `--chmod-600`: اعمال سطح دسترسی محدود ۶۰۰ روی فایل(ها)
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

A simple, fast, and robust utility to convert WireGuard links (`wireguard://` or `wg://`) into standard `.conf` configuration files.

Desktop clients (especially on Windows and Linux) require `.conf` files. This tool automates the process for single links or batch conversions from text files.

---

## Key Features

- **Safe on Windows (No Defender false positives):** Compiled with Go as a true native binary (Native PE) without temp-directory extractions.
- **Optional file permissions (chmod 600):** Does not force chmod 600 automatically; asks the user in interactive mode or enables via `-p / --chmod-600` CLI flag.
- **File input & Batch processing:** Read single or multiple links from a text file (`-f / --file`) with automatic collision-free file naming.
- **Robust URL & Base64 parsing:** Handles URL-encoded characters (`%3D`, `%2F`, `%2C`), plus `+` and `/` characters inside base64 keys without corruption.
- **Safe MTU handling:** MTU is only written if explicitly present in the link.
- **Automatic name detection:** Extracts names from the `#Fragment` section.
- **Python alternative:** `wireguard-link-to-config.py` is included with identical features.

---

## Usage

### Interactive Mode
```bash
./dist/wireguard-link-to-config
# or on Windows:
wireguard-link-to-config.exe
```
Enter a link or a path to a `.txt` file containing links.

### Command-line Mode (CLI)

**Single Link:**
```bash
./dist/wireguard-link-to-config -l "wireguard://...#Germany" -o ./configs
```

**Batch Convert from File:**
```bash
./dist/wireguard-link-to-config -f links.txt -o ./configs
```

**With chmod 600 permissions:**
```bash
./dist/wireguard-link-to-config -f links.txt -o ./configs -p
```

**CLI Flags:**
- `-l`, `--link`: WireGuard link (`wireguard://...` or `wg://...`)
- `-f`, `--file`: Path to file containing WireGuard link(s)
- `-n`, `--name`: Desired config name (for single link)
- `-o`, `--output`: Output directory path (default: current directory)
- `-p`, `--chmod-600`: Apply restrictive file permissions (chmod 600)
- `-y`, `--yes`: Overwrite existing files without confirmation
- `--stdout`: Print config content to stdout without saving to disk
- `-v`, `--version`: Show program version
