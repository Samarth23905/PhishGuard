"""Curated trust hints. A sender/app match must never bypass phishing analysis."""
import re
from urllib.parse import urlparse

TRUSTED_SENDER_IDS = {"HDFCBK","HDFCBANK","ICICIBK","ICICIBAN","SBIINB","SBICRD","AXISBK","AXISBANK","KOTAKBK","INDUSB","YESBNK","PNBSMS","BOIIND","CANBNK","UNIONBK","BANDHAN","IDBIBK","FEDERALBANK","RBLBANK","AUBANK","IDBIBANK","BARODAB","PAYTMB","PHONEPE","GPAY","AMAZONP","BHIMUPI","NPCI","JIONET","JIOTMF","AIRTLM","BSNLSM","VILTM","VODAIN","FKFLIP","AMAZON","MYNTRA","SWIGGY","ZOMATO","BLINKIT","DUNZO","ZEPTO","BIGBSK","GROFER","IRCTCS","MAKEMYTP","GOAIR","INDIGO","AIRINDIA","SPICEJT","UIDAI","INCTAX","GOVTIN","EPFINB"}
TRUSTED_APP_PACKAGES = {"net.one97.paytm","com.phonepe.app","com.google.android.apps.nbu.paisa.user","in.amazon.mShop.android.shopping","com.flipkart.android","com.swiggy.android","com.application.zomato","com.blinkit.consumer","com.hdfcbank.mobilebanking","com.icici.bank.mobile","com.sbi.SBIFreedomPlus","com.axis.mobile","com.kotak.mahindra.kotak811"}
TRUSTED_DOMAINS = {"hdfcbank.com","icicibank.com","onlinesbi.sbi","axisbank.com","kotak.com","indusind.com","yesbank.in","pnbindia.in","bankofbaroda.in","canarabank.com","unionbankofindia.co.in","rblbank.com","federalbank.co.in","bandhanbank.com","paytm.com","phonepe.com","gpay.app","bhimupi.org.in","npci.org.in","amazon.in","amazon.com","flipkart.com","myntra.com","swiggy.com","zomato.com","bigbasket.com","blinkit.com","jio.com","airtel.in","bsnl.co.in","vi.in","irctc.co.in","makemytrip.com","goindigo.in","airindia.in","uidai.gov.in","incometaxindiaefiling.gov.in","epfindia.gov.in","mca.gov.in","india.gov.in","rbi.org.in","sebi.gov.in"}


def _normalize_domain(domain):
    value = (domain or "").strip().lower().rstrip(".")
    if "://" in value:
        value = urlparse(value).hostname or ""
    return value.split(":", 1)[0]


def is_trusted_domain(domain):
    host = _normalize_domain(domain)
    return any(host == trusted or host.endswith("." + trusted) for trusted in TRUSTED_DOMAINS)


def is_trusted_sender(sender, app_name, message_text):
    # Informational only; callers must still inspect message and links.
    sender_clean = re.sub(r"^[A-Z]{2}-", "", (sender or "").strip().upper())
    app = (app_name or "").strip().lower()
    return sender_clean in TRUSTED_SENDER_IDS or app in TRUSTED_APP_PACKAGES
