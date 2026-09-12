# Wireguard link to Config

این برنامه یه ابزار کوچیک و ساده‌ست که نوشتم تا لینک‌های وایرگارد (wireguard:// یا wg://) رو خیلی راحت و بی‌دردسر به فایل استاندارد کانفیگ (.conf) تبدیل کنه، همین!

خیلی وقتا کانفیگ وایرگارد رو به صورت لینک دریافت می‌کنیم، اما کلاینت‌های رسمی دسکتاپ (مخصوصاً توی ویندوز و لینوکس) فایل .conf می‌خوان و نمیشه لینک رو مستقیم توشون ایمپورت کرد. برای اینکه هر دفعه نخواهیم دستی بشینیم کلیدها، آدرس‌ها و اندپوینت رو از داخل لینک جدا کنیم، این ابزار این کار رو توی یه ثانیه انجام میده.

چند تا نکته که سعی کردم رعایت کنم:
- فایل اجرایی مستقل: با زبان Go کامپایل شده، بنابراین روی سیستمتون نیاز به نصب پایتون یا چیز دیگه‌ای ندارید. یک فایل exe برای ویندوز و یک فایل برای لینوکس توی پوشه dist هست. روی ویندوز هم مثل برنامه‌های تبدیل‌شده پایتونی نیست و دیفندر ویندوز بهش گیر نمیده.
- دست‌کاری نکردن MTU: سرخود مقداری برای MTU تنظیم نمیکنه تا اتصال شبکه به هم نریزه؛ فقط در صورتی که خود لینک حاوی مقدار MTU باشه اون رو به فایل اضافه میکنه.
- فهمیدن اسم کانفیگ: اگه آخر لینک بعد از کاراکتر # اسم سرور یا لوکیشن باشه، خودش متوجه میشه و پیشنهادش میده.
- استفاده آسون: هم میتونید روش دابل‌کلیک کنید و به سوالاتش جواب بدید، هم میتونید توی ترمینال با فلگ اجراش کنید.
- نسخه پایتون: اگه ترجیح میدید از اسکریپت پایتون استفاده کنید، فایل wireguard-link-to-config.py هم داخل پروژه هست.

نحوه استفاده:
۱. حالت تعاملی (ساده‌ترین روش):
فایل اجرایی مربوط به سیستم‌عاملتون رو باز کنید، لینک رو پیست کنید و اینتر بزنید. فایل کانفیگ کنار همون برنامه ساخته میشه.

۲. حالت خط فرمان:
wireguard-link-to-config -l "wireguard://...#Germany" -o ./

کامپایل دوباره:
اگه خواستید خودتون از سورس کامپایل کنید، اسکریپت build.sh رو اجرا کنید:
./build.sh

---

# Wireguard link to Config (English)

This is a small, simple tool created to convert WireGuard links (wireguard:// or wg://) into standard .conf configuration files.

Often WireGuard configs are shared as URLs, but official desktop clients on Windows and Linux expect a .conf file instead of a link. Rather than manually parsing and copying keys, endpoints, and addresses by hand, this tool takes care of it automatically.

A few practical details:
- Standalone binaries: Written in Go, so you do not need Python or extra runtimes installed. There is a ready-to-run .exe for Windows and a binary for Linux inside the dist folder. The Windows build is a clean native executable, so Windows Defender will not flag it as a false positive.
- Safe MTU handling: It does not force or guess an MTU value to avoid connection issues; MTU is only added to the config if the link explicitly specifies one.
- Auto-naming: If the link contains a name after the # fragment, it detects it and suggests it automatically.
- Flexible usage: You can just double-click and answer the prompts, or pass arguments via the terminal.
- Python alternative: If you prefer Python, the wireguard-link-to-config.py script is also available in the repository.

Usage:
1. Interactive mode:
Run the executable for your OS, paste your link, and press Enter. The .conf file will be created in the current directory.

2. Command-line mode:
wireguard-link-to-config -l "wireguard://...#Germany" -o ./

Building from source:
If you want to build it yourself, simply run:
./build.sh
