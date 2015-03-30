This is a VERY rough version of a Go SPF validator. It's invoked like this:


```bash
danny@MacBook-Pro ~ » gospfquery -id="danny@banno.com" -ip-address="147.202.96.4"
Your SPF record is allowed to send from 147.202.96.4 for domain banno.com
danny@MacBook-Pro ~ » gospfquery -id="danny@banno.com" -ip-address="147.202.97.4"
The IP (147.202.97.4) was not found as a valid sender for your SPF record, but your "ALL" record is SoftFail, so sending would be permitted
danny@MacBook-Pro ~ » gospfquery -id="danny@amazon.com" -ip-address="147.202.97.4"
The IP (147.202.97.4) was not found as a valid sender for your SPF record, and your "ALL" record is Fail, so sending would NOT be permitted
```

This does not implement REDIRECT, PTR, or EXISTS. The checking for the "ALL" record is very rough.
It also turns all IPv6 records that lack a hostmask into a /128, because I don't know anything about IPv6 addresses.
It turns IP4: records without a hostmask into a /32.

PRs welcome.
