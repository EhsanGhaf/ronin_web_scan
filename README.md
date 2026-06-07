



# Ronin Core Engine

## معرفی پروژه
پروژه Ronin Core Engine یک پلتفرم تحلیل تلمتری (Telemetry) و نظارت بر تراکنش‌های بلاک‌چین است که به صورت چند زنجیره‌ای (Multi-Chain) طراحی شده است. این سیستم وظیفه تحلیل وضعیت قراردادهای هوشمند، بررسی لیست‌های سیاه (Blacklist) تتر در شبکه‌های مختلف و مدیریت گره‌های عملیاتی را بر عهده دارد.

## نیازمندی‌های سیستم
برای اجرای این محیط عملیاتی، نصب موارد زیر الزامی است:
- Node.js (نسخه 16.0.0 یا بالاتر)
- npm (نسخه مدیریت پکیج‌های Node)
- SQLite3 (جهت مدیریت پایگاه داده داخلی)

### نصب پیش‌نیازها
پس از استخراج فایل‌های پروژه، در ترمینال وارد مسیر اصلی شده و دستور زیر را اجرا کنید:
```bash
npm install express https sqlite3 bcryptjs jsonwebtoken path crypto

```

## نحوه اجرای پروژه

1. اطمینان حاصل کنید که فایل `server.js` در مسیر اصلی قرار دارد.
2. برای شروع اجرای سرور، دستور زیر را در ترمینال وارد کنید:

```bash
node server.js

```

3. پس از اجرای موفقیت‌آمیز، سرور بر روی پورت 8080 فعال می‌شود.
4. با استفاده از مرورگر وب، به آدرس `http://localhost:8080` برای دسترسی به بخش‌های مختلف پروژه مراجعه کنید.

## فرآیند ثبت‌نام (Provisioning)

برای ایجاد حساب کاربری اپراتور (Operator Node)، مراحل زیر را دنبال کنید:

1. به مسیر `/portal` مراجعه کنید.
2. اطلاعات کاربری شامل نام کاربری و رمز عبور را وارد کنید.
3. در فیلد Secret Master Key، کلید دسترسی زیر را وارد نمایید تا هویت شما جهت ثبت‌نام تایید شود:
`hs1ireZOvfdP7bL8x4fHWmM32wvP`
4. پس از تایید کلید و ثبت موفقیت‌آمیز، سیستم به صورت خودکار کاربر را احراز هویت کرده و اجازه دسترسی به داشبورد را صادر می‌کند.

## لینک‌های استعلام از شبکه

سیستم به صورت داخلی از RPCهای رسمی زیر برای دریافت و تحلیل داده‌های زنجیره‌ای استفاده می‌کند:

* اتریوم (Ethereum): https://ethereum-rpc.publicnode.com
* زنجیره هوشمند بایننس (BSC): https://bsc-rpc.publicnode.com
* پالیگان (Polygon): https://polygon-rpc.com
* ترون (Tron): https://api.trongrid.io

## مشخصات فنی و عملکرد

* **مدیریت نشست‌ها**: احراز هویت از طریق JSON Web Token (JWT) انجام می‌شود.
* **پایگاه داده**: استفاده از SQLite برای ذخیره‌سازی تاریخچه لاگ‌های تلمتری.
* **امنیت**: رمزنگاری کلمات عبور توسط کتابخانه bcryptjs.
* **هسته پردازش**: موتور پردازش تلمتری قابلیت تفکیک آدرس‌های مشکوک و غیرمشکوک بر اساس داده‌های بلک‌لیست قراردادهای USDT را دارد.

## نحوه استفاده از api 

درخواست ها باید به ادرس http://localhost:8080/api/v1/webhook ارسال بشن 
در هدر باید:
X-API-KEY کلید اکانت قرار بگیره
Content-Type = application/json; charset=utf-8
در بدنه باید درخواست زیر ارسال بشه (فقط یکی از درخواست های زیر)
{"address":"TFwBey8L5swmhRGEQSCnULT7ad68KFJe6L"}
{"tx_hash":"0xc9955e96400b92ed4c4572609943def28d2abcd39be0962c84e8f278d1ef624b"}

نمونه خروجی :
{
  "transaction_info": {
    "hash": "0xc9955e96400b92ed4c4572609943def28d2abcd39be0962c84e8f278d1ef624b",
    "network": "BSC",
    "status": "success",
    "block_height": 99064915,
    "timestamp": "2026-05-23T08:15:20.523Z",
    "confirmations": 12
  },
  "address_details": {
    "from": "0xbd7f6f91913e39413f9391cff1d367a65d8bdfc4",
    "to": "0x8748d7b321b80a45873d17dc2671bdefda96268d",
    "is_to_contract": true
  },
  "asset_transfer": {
    "type": "BEP20",
    "token_name": "Tеthеr",
    "token_symbol": "UЅⅮΤ",
    "contract_address": "0x332e54314db89ec5c9a483de82b9ecc7fc648888",
    "amount": "10000",
    "raw_value": "10000000000000000000000",
    "decimals": 18
  },
  "metadata": {
    "memo": null,
    "memo_type": null,
    "method_id": "0xa9059cbb",
    "method_name": "Token Transfer"
  },
  "authenticity_check": {
    "status": "UNKNOWN",
    "details": "Asset is not tracked or verified in the official local whitelist."
  },
  "deposit_compliance": {
    "is_valid_deposit": false,
    "exchange_minimum_required": 0,
    "user_deposited_amount": 10000,
    "status": "SECURITY_ALERT_FAILED: UNKNOWN_ASSET - Asset is not whitelisted on this exchange."
  },
  "financials": {
    "fee_native": "0.0012",
    "fee_usd": "0.00",
    "gas_price_gwei": 0
  }
}
```

```