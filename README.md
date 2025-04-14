⚡Tool usage

###  Basic SSRF Test:-

✔️ Tests for common SSRF vectors (cloud metadata, localhost access, file reads)

✔️ Looks for successful responses with metadata content

###  Advanced SSRF Test:-

 ✔️ Tests alternative IP representations (octal, hex, decimal)

 ✔️ Checks for URL parsing inconsistencies

 ✔️ Tests IPv6 and authentication bypass techniques

###  Internal Port Scan:-

 ✔️ Attempts to scan common internal ports

 ✔️ Reports open ports based on response codes

 ### Installation Requirements

    go mod init ssrf-tester
    go get
    go build

⚡ Consider using time-based detection for blind SSRF
