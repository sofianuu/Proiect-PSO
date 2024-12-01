$ORIGIN exemplu.com.        ; Designates the start of this zone file
$TTL 3600                   ; Default TTL (time to live) in seconds

; Start of Authority (SOA) record
exemplu.com.   IN   SOA ns.exemplu.com. admin.exemplu.com. (
                    2024091101  ; Serial number (date-based + version)
                    7200        ; Refresh (2 hours)
                    3600        ; Retry (1 hour)
                    1209600     ; Expire (2 weeks)
                    3600        ; Minimum TTL (1 hour)
)

; Name servers (NS) records
exemplu.com.   IN   NS    ns.exemplu.com.
exemplu.com.   IN   NS    ns.backup.com.

; Mail exchange (MX) records
exemplu.com.   IN   MX   10 mail.exemplu.com.  ; Primary mail server
exemplu.com.   IN   MX   20 mail2.exemplu.com. ; Secondary mail server

; A records (IPv4 addresses)
exemplu.com.   IN   A    192.0.2.1
www            IN   A    192.0.2.2
mail           IN   A    192.0.2.3

; CNAME records (aliases)
www            IN   CNAME exemplu.com.
ftp            IN   CNAME exemplu.com.

; AAAA records (IPv6 addresses)
exemplu.com.   IN   AAAA 2001:db8:10::1
ns             IN   AAAA 2001:db8:10::2

