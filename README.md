# Incident Investigation - Local Business Domain Hijacking & Malicious Redirect Loop


## Summary

During a local OSINT analysis, I found that the domain `5280eatstogo.com` redirected visitors to an Indonesian online gambling site. The anomaly was identified on the Google Business Profile for a restaurant in Arvada, Colorado known as 5280 Eats. The listed web address initiated an automated server-side redirect sequence terminating at an external, high-risk gambling platform `detiktri.com`. I collected public DNS, IP, and WHOIS data to build a timeline of changes. I then notified the business so they could regain control of the domain.

---

## Background

5280 Eats is a local restaurant in Arvada, Colorado.
Address: 6156 Simms St unit A, Arvada, CO 80004
Phone: (303) 955-0644

The restaurant serves breakfast and American-Mexican food. It has active listings on DoorDash, Uber Eats, and Grubhub.

I discovered the issue while checking the domain. The site no longer showed restaurant content. Instead, it redirected to a gambling site.

*Pictured below is the Google Business Profile of 5280 Eats at the time of the investigation.*
<img width="1575" height="724" alt="firefox_CQ2XzTBM9p" src="https://github.com/user-attachments/assets/9c9126b9-3dc7-4b24-b672-2004a8f35f16" />

---

## Technical Investigation and Findings

### 1. HTTP Traffic & Redirect Chain 

Analysis performed via automated HTTP header tracing (`WhereGoes Trace ID: 20264381061`) revealed an explicit chain of three `301 Moved Permanently` status codes before returning a `200 OK` from the destination server.

The domain uses HTTP 301 redirects in this order:
`https://5280eatstogo.com` → `https://www.5280eatstogo.com`
`https://www.5280eatstogo.com` → `https://detiktri.com`

| Step  | HTTP Code               | URL Requested                   | Analysis                                                                        |
| :---- | :---------------------- | :------------------------------ | :------------------------------------------------------------------------------ |
| **1** | `301 Moved Permanently` | `http://5280eatstogo.com`       | Forces HTTPS upgrade.                                                           |
| **2** | `301 Moved Permanently` | `https://5280eatstogo.com/`     | Appends canonical trailing slash.                                               |
| **3** | `301 Moved Permanently` | `https://www.5280eatstogo.com/` | Enforces `www` sub-domain; executes HTTP `Location` redirect to `detiktri.com`. |
| **4** | `200 OK`                | `https://detiktri.com/`         | External threat infrastructure renders payload.                                 |


The presence of the `301 Moved Permanently` status code confirmed server-level or DNS-level redirection rather than a client-side browser extension or local adware issue.

**Evidence:** 

Firefox Developer Tools Network Tab Results -

![](attachment/982016aa48e865116503fc2e8fb31fcf.png)
<img width="1920" height="991" alt="firefox_fzEnzFnn8A" src="https://github.com/user-attachments/assets/5b7846bd-1ab9-4fc7-b9ce-f3faf381728c" />

![](attachment/a0dcf6e39906be1f8567f65096970919.png)
<img width="1920" height="991" alt="firefox_USictiyg1p" src="https://github.com/user-attachments/assets/dd4fa1a8-ab59-4f6e-b637-8028a4b22f3e" />

![](attachment/77000e85f4bda949f41b94da297c2fdf.png)
<img width="1920" height="991" alt="firefox_XiCbt74ai3" src="https://github.com/user-attachments/assets/22521e6f-19f3-40e3-8e78-2a45f77e27e2" />

WhereGoes Redirect Trace -

Can be found in the evidence folder or here:

![Trace Results](evidence/Trace_Results.pdf)

The final site (detiktri.com) is an Indonesian online gambling site that uses the brand name DETIK365.

*Pictured below is the detiktri.com site.*

<img width="1906" height="964" alt="firefox_sTc05HkY6S" src="https://github.com/user-attachments/assets/c9705302-410d-4838-8de5-729ee0c4368d" />


Note: A search of the URL on VirusTotal returned a community score of 0/91, but the redirect is concerning for patrons of the establishment.

<img width="1898" height="869" alt="firefox_HMH5f1RD7n" src="https://github.com/user-attachments/assets/f86ed754-5164-416a-a956-71cbc3c223e6" />

<img width="1901" height="869" alt="firefox_o6rTIQvzN6" src="https://github.com/user-attachments/assets/cfb334e8-726d-4b09-b2b6-7dd53348b24c" />


---

### DNS and IP History

The domain changed hosting providers over time:
- May 2026: Microsoft Azure IP (137.117.64.85)
- June 2026: Amazon AWS IPs (76.223.67.189 and 13.248.213.45)
- August 2026: Cloudflare IPs (104.21.68.109 and 172.67.194.150)

Current nameservers:  
`james.ns.cloudflare.com` and `olga.ns.cloudflare.com`

---
### Infrastructure Mapping

**5280 Eats:**
- Domain: 5280eatstogo.com  
- Created: 28 May 2024  
- Registrar: GoDaddy.com, LLC  
- Privacy: Domains By Proxy  
- Last updated: 9–10 July 2026  
- Expires: 28 May 2027

**Destination Site (detiktri.com):**
- Created: 20 August 2026  
- Registrar: Namecheap  
- Privacy: Enabled  
- Nameservers: Cloudflare  
- Content: Indonesian online gambling (togel and slot games) under the brand DETIK365

---

### Timeline of Events

|Date|Event|Details / Evidence|Source|
|---|---|---|---|
|**2024-05-28**|Domain registered|Created at GoDaddy. Privacy enabled (Domains By Proxy). Status flags set (clientTransferProhibited, etc.).|RDAP / WHOIS|
|**~2026-05-19**|Hosted on Microsoft Azure|A records pointed to 137.117.64.85 (Microsoft).|ViewDNS IP History|
|**~2026-06-03**|Moved to Amazon AWS|A records pointed to 76.223.67.189 and 13.248.213.45 (Amazon).|ViewDNS IP History|
|**2026-07-09/10**|WHOIS last updated|“Last changed” date in registry records. Likely when nameservers or other settings were modified.|RDAP (Verisign / GoDaddy)|
|**Mid-July 2026**|Site content partially altered|Page still showed restaurant information but carried “DETIK365 - 5280 Eats” branding.|Public web snapshots / search results|
|**~2026-08-10**|Moved to Cloudflare|A records now 104.21.68.109 and 172.67.194.150. Nameservers: james.ns.cloudflare.com + olga.ns.cloudflare.com.|ViewDNS IP History + current DNS|
|**2026-08-20**|Target gambling domain registered|detiktri.com created at Namecheap (privacy protected) and also placed on Cloudflare.|WHOIS for detiktri.com|
|**Current (Sep 2026)**|Full redirect active|301 → [www.5280eatstogo.com](http://www.5280eatstogo.com/) → [https://detiktri.com](https://detiktri.com/) (Indonesian online gambling / DETIK365 site).|Live HTTP headers + page content|
Screenshots of A Records:

<img width="1899" height="871" alt="firefox_l9lTh3hnce" src="https://github.com/user-attachments/assets/8a5999ca-8762-4330-b18f-4b709d519953" />

<img width="1892" height="865" alt="firefox_DOAyeZ4RVT" src="https://github.com/user-attachments/assets/c1e8a8dd-074a-4791-b873-b8a9915b49cb" />

---

## Evidence 

All evidence that was used to understand the infrastructure and create the timeline can be found in the evidence folder of this repository under the names:

` 5280eatstogo.com WHOIS Domain Name Lookup - Who.is.pdf `
` 104.21.68.109 WHOIS IP Address Lookup - Who.is.pdf `
` detiktri.com WHOIS Domain Name Lookup - Who.is.pdf `
` 104.21.95.84 WHOIS IP Address Lookup - Who.is.pdf `

---

## Remediation and Responsible Disclosure

First, I submitted an edit request via Google Maps moderation tools to remove the bad URL from the business listing in hopes of preventing further exposure to consumers.

Then, I contacted the business by phone and reported the redirect. I offered the timeline and recommended that they contact GoDaddy support and enable two-factor authentication.

---

## Takeaways

- Attackers can compromise domain registrar accounts like GoDaddy when two-factor authentication is not enabled. 
- After gaining access, attackers change nameservers and set redirects.
- Small business domains are frequent targets because they have residual traffic and backlinks.
	- Small businesses also are targeted because of their limited resources or awareness around IT.
- Public DNS and WHOIS data are sufficient to detect and document these compromises.
- Notification helps the business recover the domain before more damage occurs.

---

## Disclaimer

All data in this report came from public sources. I did not access private systems or customer information. The purpose of this investigation was to document a real case and notify the affected business.

*Note: The restaurant has since changed their domain.*



