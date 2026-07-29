# Chapter 19: Browser and Download Artifacts

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why browsers store history, download, cache, cookie, and session artifacts.
- Identify common browser artifact locations for Chromium-based browsers, Microsoft Edge, and Firefox.
- Interpret download records as origin and file-transfer evidence with appropriate limitations.
- Correlate browser artifacts with MFT, USN, LNK files, Zone.Identifier, Prefetch, Amcache, and EDR telemetry.
- Avoid confusing download, open, execution, and user intent.

## 2. Introduction

Browsers are often the entry point for payloads, documents, credentials, cloud storage access, and user activity. Browser artifacts can show visited URLs, search terms, downloads, referrers, cookies, cache entries, autofill data, saved sessions, and extension activity.

For DFIR, browser artifacts are especially important when answering:

- Where did this file come from?
- Was a suspicious executable downloaded?
- Did a user access webmail or cloud storage?
- Was a phishing page visited?
- Did browser activity align with file creation and execution?

Browser evidence is powerful but uneven. Different browsers store different data. Private browsing modes, sync behavior, clearing history, enterprise policies, and profile selection all affect what remains.

## 3. Why Windows Created This Artifact

Windows did not create most browser artifacts directly. Browsers create them to support user convenience, performance, download management, security decisions, session restoration, and site functionality.

Windows contributes related context through file system metadata, Mark-of-the-Web alternate data streams, Event Logs, Prefetch, Amcache, and endpoint telemetry. The investigator's job is to combine browser-origin evidence with Windows artifacts that show what happened after the file arrived.

## 4. Why Investigators Care

Browser artifacts often provide origin evidence that file system artifacts cannot.

| Investigative Need | Browser Contribution |
| --- | --- |
| Download origin | URL, referrer, target path, start and end time. |
| Phishing investigation | Visited URLs, page titles, redirects, downloads. |
| Cloud storage activity | Web history, cookies, cache, downloads/uploads leads. |
| Malware delivery | Download records and file creation alignment. |
| User activity | Profile-specific browsing and searches. |
| Timeline support | Visit and download timestamps. |
| Exfiltration leads | Access to webmail, cloud drives, file transfer sites. |

Browser artifacts help answer "how did the file or web activity begin?"

## 5. Internal Structure

Common browser artifacts include SQLite databases, JSON files, cache files, and session files.

### Chromium-Based Browsers

Google Chrome, Microsoft Edge, Brave, and many other browsers are Chromium-based. Common profile paths include:

```text
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\<Profile>\
C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\<Profile>\
```

Common files:

| File | Practical Meaning |
| --- | --- |
| `History` | SQLite database containing visits, URLs, and downloads in many versions. |
| `Cookies` | SQLite database, often under `Network\Cookies`. |
| `Login Data` | Saved login metadata, protected by platform encryption. |
| `Preferences` | JSON configuration and settings. |
| `Bookmarks` | JSON bookmark data. |
| `Cache` | Cached web content. |
| `Sessions` | Session and tab restoration data. |

### Firefox

Common profile path:

```text
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\
```

Common files:

| File | Practical Meaning |
| --- | --- |
| `places.sqlite` | History and bookmarks. |
| `cookies.sqlite` | Cookies. |
| `formhistory.sqlite` | Form and search history where available. |
| `downloads.json` or download-related records | Download history depending on version. |
| `sessionstore` files | Session restoration data. |
| cache directories | Cached content. |

## 6. Data Stored

Browser artifacts may include:

- visited URL
- page title
- visit count
- visit timestamp
- typed count
- transition type
- download URL
- referrer URL
- current path
- target path
- start time
- end time
- received bytes
- total bytes
- download state
- danger or interrupt indicators
- cookies and site data
- search terms
- cached content
- session tabs

Chromium download records can include fields such as `current_path`, `target_path`, `start_time`, `received_bytes`, `total_bytes`, `state`, `danger_type`, `interrupt_reason`, `end_time`, and `opened`, depending on version.

## 7. Acquisition Methods

Acquire the full browser profile when possible. Do not collect only one database if the case involves browser activity.

For Chromium-based browsers:

```text
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\
C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\
```

For Firefox:

```text
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\
C:\Users\<user>\AppData\Local\Mozilla\Firefox\Profiles\
```

Also collect:

- Downloads folder
- MFT and USN records for downloaded files
- Zone.Identifier alternate data streams
- LNK and Jump Lists
- Prefetch and Amcache
- EDR telemetry
- proxy, DNS, firewall, and web gateway logs

Document:

- browser name and version if known
- user profile
- browser profile name
- collection time in UTC
- whether the browser was running
- files collected
- parser and version
- time conversion method

## 8. Interpretation

Browser download evidence supports origin and transfer context.

Example observation:

```text
Browser: Microsoft Edge
Profile: Default
Download URL: https://example-download[.]com/winupdate.exe
Target path: C:\Users\alex\Downloads\winupdate.exe
Start time: 2026-07-14 03:21:52 UTC
End time: 2026-07-14 03:22:04 UTC
Received bytes: 842,752
```

Reasonable inference:

- Edge recorded a download from the listed URL to the listed path during that time window.
- The browser artifact supports file origin and timing.

Unsupported conclusion:

- "The downloaded executable ran."

Execution requires Prefetch, process creation logs, Amcache, EDR telemetry, or other execution artifacts.

## 9. Strengths

Browser artifacts have several strengths:

- Can provide URL and referrer context.
- Often user-profile-specific.
- Help establish file origin.
- Can show search and browsing behavior.
- Useful for phishing and drive-by download investigations.
- Support cloud storage and webmail activity analysis.
- Correlate strongly with file system and execution artifacts.

Browser artifacts often supply the "from where" part of a file-origin finding.

## 10. Weaknesses

Limitations include:

- Private browsing may reduce local artifacts.
- Users or attackers may clear history.
- Sync can introduce data from other devices.
- Timestamps vary by browser and storage format.
- Download completion does not prove file opening or execution.
- Browser cache does not prove the user read content.
- Multiple profiles can exist for one user.
- Enterprise policies may alter retention.

Browser evidence is strong, but profile and mode context matter.

## 11. Common Mistakes

### Mistake 1: Treating Download As Execution

A download record shows transfer or attempted transfer. It does not prove the file ran.

### Mistake 2: Ignoring Browser Profiles

A user may have Default, Profile 1, work profile, personal profile, or portable browser profiles. Scope all relevant profiles.

### Mistake 3: Ignoring Zone.Identifier

Mark-of-the-Web can preserve source zone and URL context for downloaded files.

### Mistake 4: Treating Cache As Intent

Cached content may be created automatically. It does not prove careful viewing or intent.

### Mistake 5: Ignoring Sync

Browser sync can make history appear on a device where the activity did not originate. Correlate with local file system and process evidence.

## 12. Questions It Can Answer

Browser artifacts can often help answer:

- Was a URL visited?
- Was a file downloaded?
- What URL or referrer was associated with a download?
- Where did the browser save the file?
- Did browsing activity precede file creation?
- Did the user access cloud storage, webmail, or file transfer services?
- Does browser activity align with alerts and endpoint artifacts?

## 13. Questions It Cannot Answer

Browser artifacts cannot answer by themselves:

- Whether a downloaded file executed.
- Whether a file was malicious.
- Whether the user knowingly chose the download.
- Whether cached content was read.
- Whether synced activity happened on this exact device.
- Whether a missing record means no browser activity occurred.

## 14. Evidence Correlation

Browser artifacts should be correlated with Windows file and execution evidence.

| Correlating Artifact | Added Value |
| --- | --- |
| MFT / USN | File creation, write, rename, and deletion timing. |
| Zone.Identifier | Source URL, referrer, and Internet zone context. |
| Prefetch / Amcache | Execution-related and program metadata evidence. |
| LNK / Jump Lists | User or application interaction after download. |
| Event Logs 4688 / EDR | Process creation and command line. |
| SRUM | Browser or application network usage volume. |
| DNS / proxy / firewall logs | Network confirmation and destination context. |
| Email artifacts | Phishing delivery or attachment context. |

### Correlation Map

```text
Browser: file downloaded from URL
        |
        +--> MFT / USN: file created at target path
        |
        +--> Zone.Identifier: source/referrer preserved on file
        |
        +--> LNK / Jump List: user/application interaction
        |
        +--> Prefetch / 4688 / EDR: execution evidence
        |
        +--> Proxy / DNS: network confirmation
```

## 15. Investigation Walkthrough

### Scenario

An endpoint alert identifies execution of `winupdate.exe` from the Downloads folder.

### Step 1: Parse Browser Downloads

Observation:

- Edge History records a download for `winupdate.exe` from a suspicious URL.
- Target path matches `C:\Users\alex\Downloads\winupdate.exe`.

Inference:

- Browser evidence supports the file's web origin and target path.

### Step 2: Correlate File System Evidence

Observation:

- MFT and USN show the file created at the target path during the browser download window.

Inference:

- File system evidence supports the download record.

### Step 3: Check Zone.Identifier

Observation:

- The downloaded file has a Zone.Identifier stream containing URL context.

Inference:

- Mark-of-the-Web supports Internet-origin context for the file.

### Step 4: Validate Execution

Observation:

- Prefetch and EDR telemetry show execution after the download.

Inference:

- Execution is supported by independent artifacts.

### Step 5: Write the Finding

Precise wording:

```text
Browser artifacts from Alex's Edge profile record a download of winupdate.exe from a suspicious URL to C:\Users\alex\Downloads. MFT and USN records show the file was created during the same window, and Zone.Identifier preserves Internet-origin context. Prefetch and EDR telemetry are required to support the separate conclusion that the downloaded file executed.
```

## 16. ASCII Timeline

```text
03:21:52  Browser: download starts
03:22:04  Browser: download ends
03:22:05  MFT / USN: file created in Downloads
03:22:06  Zone.Identifier: Internet-origin context if present
03:23:02  Prefetch / 4688 / EDR: execution evidence
```

## 17. Investigator's Mindset

Browser artifacts are origin evidence. They become much stronger when connected to local file creation and execution.

Ask:

- Which browser and profile produced the artifact?
- Is the record local or synced?
- Was the browser in normal or private mode?
- What URL, referrer, target path, and timestamps are present?
- Did MFT and USN show matching file creation?
- Is Zone.Identifier present?
- Did the file open or execute afterward?
- What network logs confirm the destination?

Separate web origin, file creation, file interaction, and execution.

## 18. Key Takeaways

- Browser artifacts can reveal visited URLs, downloads, referrers, searches, cache, cookies, and sessions.
- Chromium-based browsers commonly store history and downloads in SQLite databases under user profile paths.
- Firefox commonly stores history and bookmarks in `places.sqlite`.
- Download evidence does not prove file execution.
- Browser sync, private mode, history clearing, and multiple profiles affect interpretation.
- Strong findings correlate browser records with MFT, USN, Zone.Identifier, LNK, Jump Lists, Prefetch, event logs, EDR, and network logs.

## 19. Review Questions

1. Why does a download record not prove execution?
2. What browser profile files are commonly useful in Chromium-based browsers?
3. Why is Zone.Identifier useful in download investigations?
4. How can browser sync affect interpretation?
5. Which artifacts would you use to connect a downloaded executable to later execution?

## 20. References

- Chromium source, "download_database.cc": https://chromium.googlesource.com/experimental/chromium/src/+/5da3f11b21c507c882f076703a6b6717ff7fd7d9/chrome/browser/history/download_database.cc
- Plaso, "chrome_history.py": https://github.com/log2timeline/plaso/blob/main/plaso/parsers/sqlite_plugins/chrome_history.py
- SpecterOps Seatbelt, "ChromiumHistory": https://docs.specterops.io/ghostpack-docs/Seatbelt-mdx/commands/chromiumhistory
- Forensics Artifacts Knowledge Base, "Chrome": https://artifacts-kb.readthedocs.io/en/latest/sources/windows/Chrome.html
- Foxton Forensics, "Chrome History Location": https://www.foxtonforensics.com/browser-history-examiner/chrome-history-location
- Mozilla Support, "Profiles - Where Firefox stores your bookmarks, passwords and other user data": https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data
