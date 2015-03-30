This is a VERY rough version of a Go SPF validator. It's invoked like this:


```bash
danny@MacBook-Pro ~ » gospfquery -id="danny@banno.com" -ip-address="147.202.96.4"
IP Sent from is in 147.202.96.0/24.  This email will be allowed to send.
danny@MacBook-Pro ~ » gospfquery -id="danny@banno.com" -ip-address="147.202.97.4"
IP Sent from is NOT found. This email would be allowed, but would be a "SoftFail" as your authorization is set to "~all"
danny@MacBook-Pro ~ » gospfquery -id="danny@amazon.com" -ip-address="147.202.97.4"
IP Sent from is NOT found. This email would NOT be allowed as your "ALL" authorization is set to "-all"
```

This does not implement REDIRECT, PTR, or EXISTS. The checking for the "ALL" record is very rough.
It also turns all IPv6 records that lack a hostmask into a /128, because I don't know anything about IPv6 addresses.
It turns IP4: records without a hostmask into a /32.

PRs welcome.
