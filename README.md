Acoustic
================

-   [Convert the PCAP](#convert-the-pcap)
-   [Examine and Process `log.txt`](#examine-and-process-log.txt)
-   [Process Zeek Logs](#process-zeek-logs)
-   [Process Packet Summary](#process-packet-summary)
-   [What is the transport protocol being
    used?](#what-is-the-transport-protocol-being-used)
-   [The attacker used a bunch of scanning tools that belong to the same
    suite. Provide the name of the
    suite.](#the-attacker-used-a-bunch-of-scanning-tools-that-belong-to-the-same-suite.-provide-the-name-of-the-suite.)
-   [“What is the User-Agent of the victim
    system?”](#what-is-the-user-agent-of-the-victim-system)
-   [Which tool was only used against the following extensions: 100,
    101, 102, 103, and
    111?](#which-tool-was-only-used-against-the-following-extensions-100-101-102-103-and-111)
-   [Which extension on the honeypot does NOT require
    authentication?](#which-extension-on-the-honeypot-does-not-require-authentication)
-   [How many extensions were scanned in
    total?](#how-many-extensions-were-scanned-in-total)
-   [There is a trace for a real SIP client. What is the corresponding
    user-agent? (two words, once space in
    between)](#there-is-a-trace-for-a-real-sip-client.-what-is-the-corresponding-user-agent-two-words-once-space-in-between)
-   [Multiple real-world phone numbers were dialed. Provide the first 11
    digits of the number dialed from extension
    101?](#multiple-real-world-phone-numbers-were-dialed.-provide-the-first-11-digits-of-the-number-dialed-from-extension-101)
-   [What are the default credentials used in the attempted basic
    authentication? (format is
    username:password)](#what-are-the-default-credentials-used-in-the-attempted-basic-authentication-format-is-usernamepassword)
-   [Which codec does the RTP stream use? (3 words, 2 spaces in
    between)](#which-codec-does-the-rtp-stream-use-3-words-2-spaces-in-between)
-   [How long is the sampling time (in
    milliseconds)?](#how-long-is-the-sampling-time-in-milliseconds)
-   [What was the password for the account with username
    555?](#what-was-the-password-for-the-account-with-username-555)
-   [Which RTP packet header field can be used to reorder out of sync
    RTP packets in the correct
    sequence?](#which-rtp-packet-header-field-can-be-used-to-reorder-out-of-sync-rtp-packets-in-the-correct-sequence)
-   [The trace includes a secret hidden message. Can you hear
    it?](#the-trace-includes-a-secret-hidden-message.-can-you-hear-it)

(See [this document](https://github.com/hrbrmstr/packet-maze-example)
for what’s going on here).

[This challenge](https://cyberdefenders.org/labs/46) takes us *“into the
world of voice communications on the internet. VoIP is becoming the
de-facto standard for voice communication. As this technology becomes
more common, malicious parties have more opportunities and stronger
motives to control these systems to conduct nefarious activities. This
challenge was designed to examine and explore some of the attributes of
the SIP and RTP protocols.”*

We have two files to work with:

-   `log.txt` which was generated from an unadvertised, passive honeypot
    located on the internet such that any traffic destined to it must be
    nefarious. Unknown parties scanned the honeypot with a range of
    tools, and this activity is represented in the log file.
    -   The IP address of the honeypot has been changed to
        “`honey.pot.IP.removed`”. In terms of geolocation, pick your
        favorite city.
    -   The MD5 hash in the authorization digest is replaced with
        “`MD5_hash_removedXXXXXXXXXXXXXXXX`”
    -   Some octets of external IP addresses have been replaced with an
        “X”
    -   Several trailing digits of phone numbers have been replaced with
        an “X”
    -   Assume the timestamps in the log files are UTC.
-   `Voip-trace.pcap` was created by honeynet members for this forensic
    challenge to allow participants to employ network analysis skills in
    the VOIP context.

There are 14 questions to answer.

If you are not familiar with
[SIP](https://en.wikipedia.org/wiki/Session_Initiation_Protocol) and/or
[RTP](https://en.wikipedia.org/wiki/Real-time_Transport_Protocol) you
should do a bit of research first. A good place to start is [RTC
3261](https://www.rfc-editor.org/rfc/rfc3261.html) (for SIP) and [RFC
3550](https://datatracker.ietf.org/doc/html/rfc3550) (for RTC). Some
questions may be able to be answered just by knowing the details of
these protocols.

## Convert the PCAP

``` r
library(stringi)
library(tidyverse)
```

We’ll pre-generate Zeek logs. The `-C` tells Zeek to not bother with
checksums, `-r` tells it to read from a file and the
`LogAscii::use_json=T` means we want JSON output vs the default
delimited files. JSON gives us data types (the headers in the delimited
files do as well, but we’d have to write something to read those types
then deal with it vs get this for free out of the box with JSON).

``` r
system("ZEEK_LOG_SUFFIX=json /opt/zeek/bin/zeek -C -r src/Voip-trace.pcap LogAscii::use_json=T HTTP::default_capture_password=T")
```

We process the PCAP twice with `tshark`. Once to get the handy (and
small) packet summary table, then dump the whole thing to JSON. We may
need to run `tshark` again down the road a bit.

``` r
system("tshark -T tabs -r src/Voip-trace.pcap > voip-packets.tsv")
system("tshark -T json -r src/Voip-trace.pcap > voip-trace")
```

## Examine and Process `log.txt`

We aren’t told what format `log.txt` is in, so let’s take a look:

``` r
cd_sip_log <- stri_read_lines("src/log.txt")

cat(head(cd_sip_log, 25), sep="\n")
```

    ## Source: 210.184.X.Y:1083
    ## Datetime: 2010-05-02 01:43:05.606584
    ## 
    ## Message:
    ## 
    ## OPTIONS sip:100@honey.pot.IP.removed SIP/2.0
    ## Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-2159139916;rport
    ## Content-Length: 0
    ## From: "sipvicious"<sip:100@1.1.1.1>; tag=X_removed
    ## Accept: application/sdp
    ## User-Agent: friendly-scanner
    ## To: "sipvicious"<sip:100@1.1.1.1>
    ## Contact: sip:100@127.0.0.1:5061
    ## CSeq: 1 OPTIONS
    ## Call-ID: 845752980453913316694142
    ## Max-Forwards: 70
    ## 
    ## 
    ## 
    ## 
    ## -------------------------
    ## Source: 210.184.X.Y:4956
    ## Datetime: 2010-05-02 01:43:12.488811
    ## 
    ## Message:

These look *a bit* like [HTTP server
responses](https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages),
but we know we’re working in SIP land and if you perused the RFC you’d
have noticed that SIP is an HTTP-like ASCII protocol. While some HTTP
response parsers *might* work on these records, it’s pretty
straightforward to whip up a bespoke pseudo-parser.

Let’s see how many records there are by counting the number of
“`Message:`” lines (we’re doing this, primarily, to see if we should use
the `{furrr}` package to speed up processing):

``` r
cd_sip_log[stri_detect_fixed(cd_sip_log, "Message:")] %>%
  table()
```

    ## .
    ## Message: 
    ##     4266

There are many, so we’ll avoid parallel processing the data and just use
a single thread.

One way to tackle the parsing is to look for the stop and start of each
record, extract fields (these have similar formats to HTTP headers), and
perhaps have to extract content as well. We know this because there are
“`Content-Length:`” fields. [According to the
RFC](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.14) they are
supposed to exist for every message. Let’s first see if any
“`Content-Length:`” header records are greater than 0. We’ll do this
with a little help from the
[`ripgrep`](https://github.com/BurntSushi/ripgrep) utility as it
provides a way to see context before and/or after matched patterns:

``` r
cat(system('rg --after-context=10 "^Content-Length: [^0]" src/log.txt', intern=TRUE), sep="\n")
```

    ## Content-Length: 330
    ## 
    ## v=0
    ## o=Zoiper_user 0 0 IN IP4 89.42.194.X
    ## s=Zoiper_session
    ## c=IN IP4 89.42.194.X
    ## t=0 0
    ## m=audio 52999 RTP/AVP 3 0 8 110 98 101
    ## a=rtpmap:3 GSM/8000
    ## a=rtpmap:0 PCMU/8000
    ## a=rtpmap:8 PCMA/8000
    ## --
    ## Content-Length: 330
    ## 
    ## v=0
    ## o=Zoiper_user 0 0 IN IP4 89.42.194.X
    ## s=Zoiper_session
    ## c=IN IP4 89.42.194.X
    ## t=0 0
    ## m=audio 52999 RTP/AVP 3 0 8 110 98 101
    ## a=rtpmap:3 GSM/8000
    ## a=rtpmap:0 PCMU/8000
    ## a=rtpmap:8 PCMA/8000
    ## --
    ## Content-Length: 330
    ## 
    ## v=0
    ## o=Zoiper_user 0 0 IN IP4 89.42.194.X
    ## s=Zoiper_session
    ## c=IN IP4 89.42.194.X
    ## t=0 0
    ## m=audio 52999 RTP/AVP 3 0 8 110 98 101
    ## a=rtpmap:3 GSM/8000
    ## a=rtpmap:0 PCMU/8000
    ## a=rtpmap:8 PCMA/8000
    ## --
    ## Content-Length: 330
    ## 
    ## v=0
    ## o=Zoiper_user 0 0 IN IP4 89.42.194.X
    ## s=Zoiper_session
    ## c=IN IP4 89.42.194.X
    ## t=0 0
    ## m=audio 52999 RTP/AVP 3 0 8 110 98 101
    ## a=rtpmap:3 GSM/8000
    ## a=rtpmap:0 PCMU/8000
    ## a=rtpmap:8 PCMA/8000

So,we *do* need to account for content. It’s still pretty
straightforward (explanatory comments inline):

``` r
starts <- which(stri_detect_regex(cd_sip_log, "^Source:"))
stops <- which(stri_detect_regex(cd_sip_log, "^----------"))

map2_dfr(starts, stops, ~{

  raw_rec <- stri_trim_both(cd_sip_log[.x:.y]) # target the record from the log
  raw_rec <- raw_rec[raw_rec != "-------------------------"] # remove separator

  msg_idx <- which(stri_detect_regex(raw_rec, "^Message:")) # find where "Message:" line is
  source_idx <- which(stri_detect_regex(raw_rec, "^Source: ")) # find where "Source:" line is
  datetime_idx <- which(stri_detect_regex(raw_rec, "^Datetime: ")) # find where "Datetime:" line is
  contents_idx <- which(stri_detect_regex(raw_rec[(msg_idx+2):length(raw_rec)], "^$"))[1] + 2 # get position of the "data"

  source <- stri_match_first_regex(raw_rec[source_idx], "^Source: (.*)$")[,2] # extract source
  datetime <- stri_match_first_regex(raw_rec[datetime_idx], "^Datetime: (.*)$")[,2] # extract datetime
  request <- raw_rec[msg_idx+2] # extract request line

  # build a matrix out of the remaining headers. header key will be in column 2, value will be in column 3
  tmp <- stri_match_first_regex(raw_rec[(msg_idx+3):contents_idx], "^([^:]+):[[:space:]]+(.*)$")
  tmp[,2] <- stri_trans_tolower(tmp[,2]) # lowercase the header key
  tmp[,2] <- stri_replace_all_fixed(tmp[,2], "-", "_") # turn dashes to underscores so we can more easily use the keys as column names

  contents <- raw_rec[(contents_idx+1):length(raw_rec)]
  contents <- paste0(contents[contents != ""], collapse = "\n")

  as.list(tmp[,3]) %>% # turn the header values into a list
    set_names(tmp[,2]) %>% # make their names the tranformed keys
    append(c(
      source = source, # add source to the list (etc)
      datetime = datetime,
      request = request,
      contents = contents
    ))

}) -> sip_log_parsed
```

Let’s see what we have:

``` r
sip_log_parsed
```

    ## # A tibble: 4,266 x 18
    ##    via     content_length from    accept  user_agent to     contact cseq  source
    ##    <chr>   <chr>          <chr>   <chr>   <chr>      <chr>  <chr>   <chr> <chr> 
    ##  1 SIP/2.… 0              "\"sip… applic… friendly-… "\"si… sip:10… 1 OP… 210.1…
    ##  2 SIP/2.… 0              "\"342… applic… friendly-… "\"34… sip:34… 1 RE… 210.1…
    ##  3 SIP/2.… 0              "\"172… applic… friendly-… "\"17… sip:17… 1 RE… 210.1…
    ##  4 SIP/2.… 0              "\"adm… applic… friendly-… "\"ad… sip:ad… 1 RE… 210.1…
    ##  5 SIP/2.… 0              "\"inf… applic… friendly-… "\"in… sip:in… 1 RE… 210.1…
    ##  6 SIP/2.… 0              "\"tes… applic… friendly-… "\"te… sip:te… 1 RE… 210.1…
    ##  7 SIP/2.… 0              "\"pos… applic… friendly-… "\"po… sip:po… 1 RE… 210.1…
    ##  8 SIP/2.… 0              "\"sal… applic… friendly-… "\"sa… sip:sa… 1 RE… 210.1…
    ##  9 SIP/2.… 0              "\"ser… applic… friendly-… "\"se… sip:se… 1 RE… 210.1…
    ## 10 SIP/2.… 0              "\"sup… applic… friendly-… "\"su… sip:su… 1 RE… 210.1…
    ## # … with 4,256 more rows, and 9 more variables: datetime <chr>, request <chr>,
    ## #   contents <chr>, call_id <chr>, max_forwards <chr>, expires <chr>,
    ## #   allow <chr>, authorization <chr>, content_type <chr>

``` r
glimpse(sip_log_parsed)
```

    ## Rows: 4,266
    ## Columns: 18
    ## $ via            <chr> "SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-2159139916;r…
    ## $ content_length <chr> "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", …
    ## $ from           <chr> "\"sipvicious\"<sip:100@1.1.1.1>; tag=X_removed", "\"34…
    ## $ accept         <chr> "application/sdp", "application/sdp", "application/sdp"…
    ## $ user_agent     <chr> "friendly-scanner", "friendly-scanner", "friendly-scann…
    ## $ to             <chr> "\"sipvicious\"<sip:100@1.1.1.1>", "\"3428948518\"<sip:…
    ## $ contact        <chr> "sip:100@127.0.0.1:5061", "sip:3428948518@honey.pot.IP.…
    ## $ cseq           <chr> "1 OPTIONS", "1 REGISTER", "1 REGISTER", "1 REGISTER", …
    ## $ source         <chr> "210.184.X.Y:1083", "210.184.X.Y:4956", "210.184.X.Y:51…
    ## $ datetime       <chr> "2010-05-02 01:43:05.606584", "2010-05-02 01:43:12.4888…
    ## $ request        <chr> "OPTIONS sip:100@honey.pot.IP.removed SIP/2.0", "REGIST…
    ## $ contents       <chr> "Call-ID: 845752980453913316694142\nMax-Forwards: 70", …
    ## $ call_id        <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ max_forwards   <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ expires        <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ allow          <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ authorization  <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ content_type   <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…

Looks 👍, but IRL there are edge-cases we’d have to deal with.

## Process Zeek Logs

Because they’re JSON files, and the names are reasonable, we can do some
magic incantations to read them all in and shove them into a list we’ll
call `zeek`:

``` r
zeek <- list()

list.files(
  pattern = "json$",
  full.names = TRUE
) %>%
  walk(~{
    append(zeek, list(file(.x) %>% 
      jsonlite::stream_in(verbose = FALSE) %>%
      as_tibble()) %>% 
        set_names(tools::file_path_sans_ext(basename(.x)))
    ) ->> zeek
  })

str(zeek, 1)
```

    ## List of 7
    ##  $ conn         : tibble [97 × 18] (S3: tbl_df/tbl/data.frame)
    ##  $ dpd          : tibble [1 × 9] (S3: tbl_df/tbl/data.frame)
    ##  $ files        : tibble [38 × 16] (S3: tbl_df/tbl/data.frame)
    ##  $ http         : tibble [92 × 24] (S3: tbl_df/tbl/data.frame)
    ##  $ packet_filter: tibble [1 × 5] (S3: tbl_df/tbl/data.frame)
    ##  $ sip          : tibble [9 × 23] (S3: tbl_df/tbl/data.frame)
    ##  $ weird        : tibble [1 × 9] (S3: tbl_df/tbl/data.frame)

``` r
walk2(names(zeek), zeek, ~{
  cat("File:", .x, "\n")
  glimpse(.y)
  cat("\n\n")
})
```

    ## File: conn 
    ## Rows: 97
    ## Columns: 18
    ## $ ts            <dbl> 1272737631, 1272737581, 1272737669, 1272737669, 12727376…
    ## $ uid           <chr> "Cb0OAQ1eC0ZhQTEKNl", "C2s0IU2SZFGVlZyH43", "CcEeLRD3cca…
    ## $ id.orig_h     <chr> "172.25.105.43", "172.25.105.43", "172.25.105.43", "172.…
    ## $ id.orig_p     <int> 57086, 5060, 57087, 57088, 57089, 57090, 57091, 57093, 5…
    ## $ id.resp_h     <chr> "172.25.105.40", "172.25.105.40", "172.25.105.40", "172.…
    ## $ id.resp_p     <int> 80, 5060, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80…
    ## $ proto         <chr> "tcp", "udp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", …
    ## $ service       <chr> "http", "sip", "http", "http", "http", "http", "http", "…
    ## $ duration      <dbl> 0.0180180073, 0.0003528595, 0.0245900154, 0.0740420818, …
    ## $ orig_bytes    <int> 502, 428, 380, 385, 476, 519, 520, 553, 558, 566, 566, 5…
    ## $ resp_bytes    <int> 720, 518, 231, 12233, 720, 539, 17499, 144, 144, 144, 14…
    ## $ conn_state    <chr> "SF", "SF", "SF", "SF", "SF", "SF", "SF", "SF", "SF", "S…
    ## $ missed_bytes  <int> 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,…
    ## $ history       <chr> "ShADadfF", "Dd", "ShADadfF", "ShADadfF", "ShADadfF", "S…
    ## $ orig_pkts     <int> 5, 1, 5, 12, 5, 6, 16, 6, 6, 5, 5, 5, 5, 5, 5, 5, 6, 5, …
    ## $ orig_ip_bytes <int> 770, 456, 648, 1017, 744, 839, 1360, 873, 878, 834, 834,…
    ## $ resp_pkts     <int> 5, 1, 5, 12, 5, 5, 16, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, …
    ## $ resp_ip_bytes <int> 988, 546, 499, 12865, 988, 807, 18339, 412, 412, 412, 41…
    ## 
    ## 
    ## File: dpd 
    ## Rows: 1
    ## Columns: 9
    ## $ ts             <dbl> 1272737798
    ## $ uid            <chr> "CADvMziC96POynR2e"
    ## $ id.orig_h      <chr> "172.25.105.3"
    ## $ id.orig_p      <int> 43204
    ## $ id.resp_h      <chr> "172.25.105.40"
    ## $ id.resp_p      <int> 5060
    ## $ proto          <chr> "udp"
    ## $ analyzer       <chr> "SIP"
    ## $ failure_reason <chr> "Binpac exception: binpac exception: string mismatch at…
    ## 
    ## 
    ## File: files 
    ## Rows: 38
    ## Columns: 16
    ## $ ts             <dbl> 1272737631, 1272737669, 1272737676, 1272737688, 1272737…
    ## $ fuid           <chr> "FRnb7P5EDeZE4Y3z4", "FOT2gC2yLxjfMCuE5f", "FmUCuA3dzcS…
    ## $ tx_hosts       <list> "172.25.105.40", "172.25.105.40", "172.25.105.40", "17…
    ## $ rx_hosts       <list> "172.25.105.43", "172.25.105.43", "172.25.105.43", "17…
    ## $ conn_uids      <list> "Cb0OAQ1eC0ZhQTEKNl", "CFfYtA0DqqrJk4gI5", "CHN4qA4UUH…
    ## $ source         <chr> "HTTP", "HTTP", "HTTP", "HTTP", "HTTP", "HTTP", "HTTP",…
    ## $ depth          <int> 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0…
    ## $ analyzers      <list> [], [], [], [], [], [], [], [], [], [], [], [], [], []…
    ## $ mime_type      <chr> "text/html", "text/html", "text/html", "text/html", "te…
    ## $ duration       <dbl> 0.000000e+00, 8.920908e-03, 0.000000e+00, 0.000000e+00,…
    ## $ is_orig        <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, TRUE, FALSE, FALSE, …
    ## $ seen_bytes     <int> 479, 11819, 479, 313, 17076, 55, 50, 30037, 31608, 1803…
    ## $ total_bytes    <int> 479, NA, 479, 313, NA, 55, 50, NA, NA, NA, 58, 313, 50,…
    ## $ missing_bytes  <int> 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0…
    ## $ overflow_bytes <int> 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0…
    ## $ timedout       <lgl> FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,…
    ## 
    ## 
    ## File: http 
    ## Rows: 92
    ## Columns: 24
    ## $ ts                <dbl> 1272737631, 1272737669, 1272737669, 1272737676, 1272…
    ## $ uid               <chr> "Cb0OAQ1eC0ZhQTEKNl", "CcEeLRD3cca3j4QGh", "CFfYtA0D…
    ## $ id.orig_h         <chr> "172.25.105.43", "172.25.105.43", "172.25.105.43", "…
    ## $ id.orig_p         <int> 57086, 57087, 57088, 57089, 57090, 57091, 57093, 570…
    ## $ id.resp_h         <chr> "172.25.105.40", "172.25.105.40", "172.25.105.40", "…
    ## $ id.resp_p         <int> 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, …
    ## $ trans_depth       <int> 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1…
    ## $ method            <chr> "GET", "GET", "GET", "GET", "GET", "GET", "GET", "GE…
    ## $ host              <chr> "172.25.105.40", "172.25.105.40", "172.25.105.40", "…
    ## $ uri               <chr> "/maint", "/", "/user/", "/maint", "/maint", "/maint…
    ## $ referrer          <chr> "http://172.25.105.40/user/", NA, NA, "http://172.25…
    ## $ version           <chr> "1.1", "1.1", "1.1", "1.1", "1.1", "1.1", "1.1", "1.…
    ## $ user_agent        <chr> "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9)…
    ## $ request_body_len  <int> 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0…
    ## $ response_body_len <int> 479, 0, 11819, 479, 313, 17076, 0, 0, 0, 0, 0, 0, 0,…
    ## $ status_code       <int> 401, 302, 200, 401, 301, 200, 304, 304, 304, 304, 30…
    ## $ status_msg        <chr> "Authorization Required", "Found", "OK", "Authorizat…
    ## $ tags              <list> [], [], [], [], [], [], [], [], [], [], [], [], [],…
    ## $ resp_fuids        <list> "FRnb7P5EDeZE4Y3z4", <NULL>, "FOT2gC2yLxjfMCuE5f", …
    ## $ resp_mime_types   <list> "text/html", <NULL>, "text/html", "text/html", "tex…
    ## $ username          <chr> NA, NA, NA, NA, "maint", "maint", "maint", "maint", …
    ## $ password          <chr> NA, NA, NA, NA, "password", "password", "password", …
    ## $ orig_fuids        <list> <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NU…
    ## $ orig_mime_types   <list> <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NULL>, <NU…
    ## 
    ## 
    ## File: packet_filter 
    ## Rows: 1
    ## Columns: 5
    ## $ ts      <dbl> 1627151196
    ## $ node    <chr> "zeek"
    ## $ filter  <chr> "ip or not ip"
    ## $ init    <lgl> TRUE
    ## $ success <lgl> TRUE
    ## 
    ## 
    ## File: sip 
    ## Rows: 9
    ## Columns: 23
    ## $ ts                <dbl> 1272737581, 1272737768, 1272737768, 1272737768, 1272…
    ## $ uid               <chr> "C2s0IU2SZFGVlZyH43", "CADvMziC96POynR2e", "CADvMziC…
    ## $ id.orig_h         <chr> "172.25.105.43", "172.25.105.3", "172.25.105.3", "17…
    ## $ id.orig_p         <int> 5060, 43204, 43204, 43204, 43204, 43204, 43204, 4320…
    ## $ id.resp_h         <chr> "172.25.105.40", "172.25.105.40", "172.25.105.40", "…
    ## $ id.resp_p         <int> 5060, 5060, 5060, 5060, 5060, 5060, 5060, 5060, 5060
    ## $ trans_depth       <int> 0, 0, 0, 0, 0, 0, 0, 0, 0
    ## $ method            <chr> "OPTIONS", "REGISTER", "REGISTER", "SUBSCRIBE", "SUB…
    ## $ uri               <chr> "sip:100@172.25.105.40", "sip:172.25.105.40", "sip:1…
    ## $ request_from      <chr> "\"sipvicious\"<sip:100@1.1.1.1>", "<sip:555@172.25.…
    ## $ request_to        <chr> "\"sipvicious\"<sip:100@1.1.1.1>", "<sip:555@172.25.…
    ## $ response_from     <chr> "\"sipvicious\"<sip:100@1.1.1.1>", "<sip:555@172.25.…
    ## $ response_to       <chr> "\"sipvicious\"<sip:100@1.1.1.1>;tag=as18cdb0c9", "<…
    ## $ call_id           <chr> "61127078793469957194131", "MzEwMmYyYWRiYTUxYTBhODY3…
    ## $ seq               <chr> "1 OPTIONS", "1 REGISTER", "2 REGISTER", "1 SUBSCRIB…
    ## $ request_path      <list> "SIP/2.0/UDP 127.0.1.1:5060", "SIP/2.0/UDP 172.25.10…
    ## $ response_path     <list> "SIP/2.0/UDP 127.0.1.1:5060", "SIP/2.0/UDP 172.25.10…
    ## $ user_agent        <chr> "UNfriendly-scanner - for demo purposes", "X-Lite B…
    ## $ status_code       <int> 200, 401, 200, 401, 404, 401, 100, 200, NA
    ## $ status_msg        <chr> "OK", "Unauthorized", "OK", "Unauthorized", "Not fo…
    ## $ request_body_len  <int> 0, 0, 0, 0, 0, 264, 264, 264, 0
    ## $ response_body_len <int> 0, 0, 0, 0, 0, 0, 0, 302, NA
    ## $ content_type      <chr> NA, NA, NA, NA, NA, NA, NA, "application/sdp", NA
    ## 
    ## 
    ## File: weird 
    ## Rows: 1
    ## Columns: 9
    ## $ ts        <dbl> 1272737805
    ## $ id.orig_h <chr> "172.25.105.3"
    ## $ id.orig_p <int> 0
    ## $ id.resp_h <chr> "172.25.105.40"
    ## $ id.resp_p <int> 0
    ## $ name      <chr> "truncated_IPv6"
    ## $ notice    <lgl> FALSE
    ## $ peer      <chr> "zeek"
    ## $ source    <chr> "IP"

## Process Packet Summary

We won’t process the big JSON file `tshark` generated for us util we
really have to, but we can read in the packet summary table now:

``` r
packet_cols <- c("packet_num", "ts", "src", "discard", "dst", "proto", "length", "info")

read_tsv(
  file = "voip-packets.tsv",
  col_names = packet_cols,
  col_types = "ddccccdc"
) %>%
  select(-discard) -> packets

packets
```

    ## # A tibble: 4,447 x 7
    ##    packet_num       ts src      dst     proto length info                       
    ##         <dbl>    <dbl> <chr>    <chr>   <chr>  <dbl> <chr>                      
    ##  1          1  0       172.25.… 172.25… SIP      470 Request: OPTIONS sip:100@1…
    ##  2          2  3.53e-4 172.25.… 172.25… SIP      560 Status: 200 OK |           
    ##  3          3  5.03e+1 172.25.… 172.25… TCP       74 57086 → 80 [SYN] Seq=0 Win…
    ##  4          4  5.03e+1 172.25.… 172.25… TCP       74 80 → 57086 [SYN, ACK] Seq=…
    ##  5          5  5.03e+1 172.25.… 172.25… TCP       66 57086 → 80 [ACK] Seq=1 Ack…
    ##  6          6  5.03e+1 172.25.… 172.25… HTTP     568 GET /maint HTTP/1.1        
    ##  7          7  5.03e+1 172.25.… 172.25… TCP       66 80 → 57086 [ACK] Seq=1 Ack…
    ##  8          8  5.03e+1 172.25.… 172.25… HTTP     786 HTTP/1.1 401 Authorization…
    ##  9          9  5.03e+1 172.25.… 172.25… TCP       66 80 → 57086 [FIN, ACK] Seq=…
    ## 10         10  5.03e+1 172.25.… 172.25… TCP       66 57086 → 80 [ACK] Seq=503 A…
    ## # … with 4,437 more rows

``` r
glimpse(packets)
```

    ## Rows: 4,447
    ## Columns: 7
    ## $ packet_num <dbl> 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, …
    ## $ ts         <dbl> 0.000000, 0.000353, 50.317176, 50.317365, 50.320071, 50.329…
    ## $ src        <chr> "172.25.105.43", "172.25.105.40", "172.25.105.43", "172.25.…
    ## $ dst        <chr> "172.25.105.40", "172.25.105.43", "172.25.105.40", "172.25.…
    ## $ proto      <chr> "SIP", "SIP", "TCP", "TCP", "TCP", "HTTP", "TCP", "HTTP", "…
    ## $ length     <dbl> 470, 560, 74, 74, 66, 568, 66, 786, 66, 66, 66, 66, 74, 74,…
    ## $ info       <chr> "Request: OPTIONS sip:100@172.25.105.40 |", "Status: 200 OK…

## What is the transport protocol being used?

SIP can use TCP or UDP and which transport it uses will be specified in
the [`Via:`
header](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.7).
Let’s take a look:

``` r
head(sip_log_parsed$via)
```

    ## [1] "SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-2159139916;rport"
    ## [2] "SIP/2.0/UDP 127.0.0.1:5087;branch=z9hG4bK-1189344537;rport"
    ## [3] "SIP/2.0/UDP 127.0.0.1:5066;branch=z9hG4bK-2119091576;rport"
    ## [4] "SIP/2.0/UDP 127.0.0.1:5087;branch=z9hG4bK-3226446220;rport"
    ## [5] "SIP/2.0/UDP 127.0.0.1:5087;branch=z9hG4bK-1330901245;rport"
    ## [6] "SIP/2.0/UDP 127.0.0.1:5087;branch=z9hG4bK-945386205;rport"

Are they *all* UDP? We can find out by performing some light processing
on the `via` column:

``` r
sip_log_parsed %>% 
  select(via) %>% 
  mutate(
    transport = stri_match_first_regex(via, "^([^[:space:]]+)")[,2]
  ) %>% 
  count(transport, sort=TRUE)
```

    ## # A tibble: 1 x 2
    ##   transport       n
    ##   <chr>       <int>
    ## 1 SIP/2.0/UDP  4266

Looks like they’re all UDP. Question 1: ✅

## The attacker used a bunch of scanning tools that belong to the same suite. Provide the name of the suite.

Don’t you, now, wish you had listen to your parents when they were
telling you about the facts of SIP life when you were a wee pup?

We’ll stick with the SIP log to answer this one and [peek back at the
RFC](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.41) to see
that there’s a “`User-Agent:`” field which contains information about
the client originating the request. Most scanners written by defenders
identify themselves in `User-Agent` fields when those fields are
available in a protocol exchange, and a large percentage of naive
malicious folks are too daft to change this value (or leave it default
to make you think they’re not behaving badly).

If you are a regular visitor to SIP land, you likely know the common SIP
scanning tools. These are a few:

-   [Nmap’s SIP library](https://nmap.org/nsedoc/lib/sip.html)
-   [Mr.SIP](https://github.com/meliht/Mr.SIP), a “SIP-Based Audit and
    Attack Tool”
-   [SIPVicious](https://github.com/EnableSecurity/sipvicious), a “set
    of security tools that can be used to audit SIP based VoIP systems”
-   [Sippts](https://github.com/Pepelux/sippts), a “set of tools to
    audit SIP based VoIP Systems”

(There are [many more](https://github.com/search?q=sip+audit).)

Let’s see what user-agent was used in this log extract:

``` r
count(sip_log_parsed, user_agent, sort=TRUE)
```

    ## # A tibble: 3 x 2
    ##   user_agent           n
    ##   <chr>            <int>
    ## 1 friendly-scanner  4248
    ## 2 Zoiper rev.6751     14
    ## 3 <NA>                 4

The overwhelming majority are `friendly-scanner`. Let’s look at a few of
those log entries:

``` r
sip_log_parsed %>% 
  filter(
    user_agent == "friendly-scanner"
  ) %>% 
  glimpse()
```

    ## Rows: 4,248
    ## Columns: 18
    ## $ via            <chr> "SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-2159139916;r…
    ## $ content_length <chr> "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", …
    ## $ from           <chr> "\"sipvicious\"<sip:100@1.1.1.1>; tag=X_removed", "\"34…
    ## $ accept         <chr> "application/sdp", "application/sdp", "application/sdp"…
    ## $ user_agent     <chr> "friendly-scanner", "friendly-scanner", "friendly-scann…
    ## $ to             <chr> "\"sipvicious\"<sip:100@1.1.1.1>", "\"3428948518\"<sip:…
    ## $ contact        <chr> "sip:100@127.0.0.1:5061", "sip:3428948518@honey.pot.IP.…
    ## $ cseq           <chr> "1 OPTIONS", "1 REGISTER", "1 REGISTER", "1 REGISTER", …
    ## $ source         <chr> "210.184.X.Y:1083", "210.184.X.Y:4956", "210.184.X.Y:51…
    ## $ datetime       <chr> "2010-05-02 01:43:05.606584", "2010-05-02 01:43:12.4888…
    ## $ request        <chr> "OPTIONS sip:100@honey.pot.IP.removed SIP/2.0", "REGIST…
    ## $ contents       <chr> "Call-ID: 845752980453913316694142\nMax-Forwards: 70", …
    ## $ call_id        <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ max_forwards   <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ expires        <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ allow          <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ authorization  <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…
    ## $ content_type   <chr> NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,…

Those `from` and `to` fields have an interesting name in them:
“`sipviscious`”. You’ve seen that before, right at the beginning of this
section.

Let’s do a quick check [over at the SIPvicious
repo](https://github.com/EnableSecurity/sipvicious/search?q=friendly-scanner)
just to make sure.

``` r
count(sip_log_parsed, user_agent)
```

    ## # A tibble: 3 x 2
    ##   user_agent           n
    ##   <chr>            <int>
    ## 1 friendly-scanner  4248
    ## 2 Zoiper rev.6751     14
    ## 3 <NA>                 4

## “What is the User-Agent of the victim system?”

We only have partial data in the text log so we’ll have to look
elsewhere (the PCAP) for this information. The “victim” is whatever was
the target of a this SIP-based attack and we can look for SIP messages,
user agents, and associated IPs in the PCAP thanks to `tshark`’s [rich
SIP filter library](https://www.wireshark.org/docs/dfref/s/sip.html):

``` r
system("tshark -Q -T fields -e ip.src -e ip.dst -e sip.User-Agent -r src/Voip-trace.pcap 'sip.User-Agent'")
```

That first exchange is all we really need. We see our rude poker talking
to `172.25.105.40` and it responding right after.

## Which tool was only used against the following extensions: 100, 101, 102, 103, and 111?

The question is a tad vague and is assuming — since we now know the
SIPvicious suite was used — that we also know to provide the [name of
the Python script in
SIPvicious](https://github.com/EnableSecurity/sipvicious/tree/master/sipvicious)
that was used. There are five tools:

-   `svmap`: this is a sip scanner. When launched against ranges of ip
    address space, it will identify any SIP servers which it finds on
    the way. Also has the option to scan hosts on ranges of ports.
    Usage:
    <https://github.com/EnableSecurity/sipvicious/wiki/SVMap-Usage>
-   `svwar`: identifies working extension lines on a PBX. A working
    extension is one that can be registered. Also tells you if the
    extension line requires authentication or not. Usage:
    <https://github.com/EnableSecurity/sipvicious/wiki/SVWar-Usage>
-   `svcrack`: a password cracker making use of digest authentication.
    It is able to crack passwords on both registrar servers and proxy
    servers. Current cracking modes are either numeric ranges or words
    from dictionary files. Usage:
    <https://github.com/EnableSecurity/sipvicious/wiki/SVCrack-Usage>
-   `svreport`: able to manage sessions created by the rest of the tools
    and export to pdf, xml, csv and plain text. Usage:
    <https://github.com/EnableSecurity/sipvicious/wiki/SVReport-Usage>
-   `svcrash`: responds to `svwar` and `svcrack` SIP messages with a
    message that causes old versions to crash. Usage:
    <https://github.com/EnableSecurity/sipvicious/wiki/SVCrash-FAQ>

The `svcrash` tool is something defenders can use to help curtail
scanner activity. We can cross that off the list. The `svreport` tool is
for working with data generated by `svmap`, `svwar` and/or `svcrack`.
One more crossed off. We also know that the attacker scanned the SIP
network looking for nodes, which means `svmap` and `svwar` are likely
not exclusive tool to the target extensions. (We *technically* have
enough information right now to answer the question especially if you
look carefully at the answer box on the site but that’s cheating).

The SIP request line and header field like
[“`To:`”](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.2)
destination information in the form of a [SIP
URI](https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1). Since we
only care about the extension component of the URI for this question, we
can use a regular expression to isolate them.

Back to the SIP log to see if we can find the identified extensions.
We’ll also process the “`From:`” header just in case we need it.

``` r
sip_log_parsed %>% 
  mutate_at(
    vars(request, from, to),
    ~stri_match_first_regex(.x, "sip:([^@]+)@")[,2]
  ) %>% 
  select(request, from, to)
```

    ## # A tibble: 4,266 x 3
    ##    request    from       to        
    ##    <chr>      <chr>      <chr>     
    ##  1 100        100        100       
    ##  2 3428948518 3428948518 3428948518
    ##  3 1729240413 1729240413 1729240413
    ##  4 admin      admin      admin     
    ##  5 info       info       info      
    ##  6 test       test       test      
    ##  7 postmaster postmaster postmaster
    ##  8 sales      sales      sales     
    ##  9 service    service    service   
    ## 10 support    support    support   
    ## # … with 4,256 more rows

That worked! We can now see what `friendly-scanner` attempted to
authenticate only to our targets:

``` r
sip_log_parsed %>%
  mutate_at(
    vars(request, from, to),
    ~stri_match_first_regex(.x, "sip:([^@]+)@")[,2]
  ) %>% 
  filter(
    user_agent == "friendly-scanner",
    stri_detect_fixed(contents, "Authorization")
  ) %>% 
  distinct(to)
```

    ## # A tibble: 4 x 1
    ##   to   
    ##   <chr>
    ## 1 102  
    ## 2 103  
    ## 3 101  
    ## 4 111

While we’re missing `100` that’s likely due to it not requiring
authentication (`svcrack` will `REGISTER` first to determine if a target
requires authentication and not send cracking requests if it doesn’t).

## Which extension on the honeypot does NOT require authentication?

We know this due to what we found in the previous question. Extension
`100` does not require authentication.

## How many extensions were scanned in total?

We just need to count the distinct `to`’s where the user agent is the
scanner:

``` r
sip_log_parsed %>% 
  mutate_at(
    vars(request, from, to),
    ~stri_match_first_regex(.x, "sip:([^@]+)@")[,2]
  ) %>% 
  filter(
    user_agent == "friendly-scanner"
  ) %>% 
  distinct(to)
```

    ## # A tibble: 2,652 x 1
    ##    to        
    ##    <chr>     
    ##  1 100       
    ##  2 3428948518
    ##  3 1729240413
    ##  4 admin     
    ##  5 info      
    ##  6 test      
    ##  7 postmaster
    ##  8 sales     
    ##  9 service   
    ## 10 support   
    ## # … with 2,642 more rows

## There is a trace for a real SIP client. What is the corresponding user-agent? (two words, once space in between)

We only need to look for user agent’s that aren’t our scanner:

``` r
sip_log_parsed %>% 
  filter(
    user_agent != "friendly-scanner"
  ) %>% 
  count(user_agent)
```

    ## # A tibble: 1 x 2
    ##   user_agent          n
    ##   <chr>           <int>
    ## 1 Zoiper rev.6751    14

## Multiple real-world phone numbers were dialed. Provide the first 11 digits of the number dialed from extension 101?

Calls are [“`INVITE`”
requests](https://www.rfc-editor.org/rfc/rfc3261.html#section-13)

``` r
sip_log_parsed %>% 
  mutate_at(
    vars(from, to),
    ~stri_match_first_regex(.x, "sip:([^@]+)@")[,2]
  ) %>% 
  filter(
    from == 101,
    stri_detect_regex(cseq, "INVITE")
  ) %>% 
  select(to) 
```

    ## # A tibble: 3 x 1
    ##   to              
    ##   <chr>           
    ## 1 900114382089XXXX
    ## 2 00112322228XXXX 
    ## 3 00112524021XXXX

The challenge answer box provides hint to what number they want. I’m not
sure but I suspect it may be randomized, so you’ll have to match the
pattern they expect with the correct digits above.

## What are the default credentials used in the attempted basic authentication? (format is username:password)

This question wants us to look at the HTTP requests that require
authentication. We can get he credentials info from the `zeek$http` log:

``` r
zeek$http %>% 
  distinct(username, password)
```

    ## # A tibble: 2 x 2
    ##   username password
    ##   <chr>    <chr>   
    ## 1 <NA>     <NA>    
    ## 2 maint    password

## Which codec does the RTP stream use? (3 words, 2 spaces in between)

“Codec” refers to the algorithm used to encode/decode an audio or video
stream. The RTP RFC uses the term [“payload
type”](https://datatracker.ietf.org/doc/html/rfc3550#page-71) to refer
to this during exchanges and even has a link to [RFC
3551](https://datatracker.ietf.org/doc/html/rfc3551) which provides
further information on these encodings.

The summary packet table that `tshark` generates helpfully provides
summary `info` for RTP packets and part of that info is `PT=…` which
indicates the payload type.

``` r
packets %>% 
  filter(proto == "RTP") %>% 
  select(info)
```

    ## # A tibble: 2,988 x 1
    ##    info                                                       
    ##    <chr>                                                      
    ##  1 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6402, Time=126160
    ##  2 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6403, Time=126320
    ##  3 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6404, Time=126480
    ##  4 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6405, Time=126640
    ##  5 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6406, Time=126800
    ##  6 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6407, Time=126960
    ##  7 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6408, Time=127120
    ##  8 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6409, Time=127280
    ##  9 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6410, Time=127440
    ## 10 PT=ITU-T G.711 PCMU, SSRC=0xA254E017, Seq=6411, Time=127600
    ## # … with 2,978 more rows

## How long is the sampling time (in milliseconds)?

-   `1` Hz = `1,000` ms
-   `1` ms = `1,000` Hz

`(1/8000) * 1000`

## What was the password for the account with username 555?

We don’t really need to use external programs for this but it will sure
go quite a bit faster if we do. While [the original reference
page](https://web.archive.org/web/20080731070643/http://www.remote-exploit.org/codes_sipcrack.html)
for `sipdump` and `sipcrack` is defunct, you can visit that link to go
to the Wayback machine’s capture of it. It will help if you have a linux
system handy (so Docker to the rescue for macOS and Windows folks) since
the following answer details are running on Ubunbu.

This question is taking advantage of the fact that the default
authentication method for SIP is extremely weak. The process uses an MD5
challenge/response, and if an attacker can capture call traffic it is
possible to brute force the password offline (which is what we’ll use
`sipcrack` for).

You can install them via `sudo apt install sipcrack`.

We’ll first generate a dump of the authentication attempts with
`sipdump`:

``` r
system("sipdump -p src/Voip-trace.pcap sip.dump", intern=TRUE)
```

    ##  [1] ""                                                               
    ##  [2] "SIPdump 0.2 "                                                   
    ##  [3] "---------------------------------------"                        
    ##  [4] ""                                                               
    ##  [5] "* Using pcap file 'src/Voip-trace.pcap' for sniffing"           
    ##  [6] "* Starting to sniff with packet filter 'tcp or udp'"            
    ##  [7] ""                                                               
    ##  [8] "* Dumped login from 172.25.105.40 -> 172.25.105.3 (User: '555')"
    ##  [9] "* Dumped login from 172.25.105.40 -> 172.25.105.3 (User: '555')"
    ## [10] "* Dumped login from 172.25.105.40 -> 172.25.105.3 (User: '555')"
    ## [11] ""                                                               
    ## [12] "* Exiting, sniffed 3 logins"

``` r
cat(readLines("sip.dump"), sep="\n")
```

    ## 172.25.105.3"172.25.105.40"555"asterisk"REGISTER"sip:172.25.105.40"4787f7ce""""MD5"1ac95ce17e1f0230751cf1fd3d278320
    ## 172.25.105.3"172.25.105.40"555"asterisk"INVITE"sip:1000@172.25.105.40"70fbfdae""""MD5"aa533f6efa2b2abac675c1ee6cbde327
    ## 172.25.105.3"172.25.105.40"555"asterisk"BYE"sip:1000@172.25.105.40"70fbfdae""""MD5"0b306e9db1f819dd824acf3227b60e07

It saves the IPs, caller, authentication realm, method, nonce and hash
which will all be fed into the `sipcrack`.

We know from the placeholder answer text that the “password” is 4
characters, and this is the land of telephony, so we can make an
assumption that it is really 4 digits. `sipcrack` needs a file of
passwords to try, so We’ll let R make a randomized file of 4 digit pins
for us:

``` r
cat(sprintf("%04d", sample(0:9999)), file = "4-digits", sep="\n")
```

We only have authenticaton packets for `555` so we can automate what
would normally be an interactive process:

``` r
cat(system('echo "1" | sipcrack -w 4-digits sip.dump', intern=TRUE), sep="\n")
```

    ## 
    ## SIPcrack 0.2 
    ## ----------------------------------------
    ## 
    ## * Found Accounts:
    ## 
    ## Num  Server      Client      User    Hash|Password
    ## 
    ## 1    172.25.105.3    172.25.105.40   555 1ac95ce17e1f0230751cf1fd3d278320
    ## 2    172.25.105.3    172.25.105.40   555 aa533f6efa2b2abac675c1ee6cbde327
    ## 3    172.25.105.3    172.25.105.40   555 0b306e9db1f819dd824acf3227b60e07
    ## 
    ## * Select which entry to crack (1 - 3): 
    ## * Generating static MD5 hash... c3e0f1664fde9fbc75a7cbd341877875
    ## * Loaded wordlist: '4-digits'
    ## * Starting bruteforce against user '555' (MD5: '1ac95ce17e1f0230751cf1fd3d278320')
    ## * Tried 8904 passwords in 0 seconds
    ## 
    ## * Found password: '1234'
    ## * Updating dump file 'sip.dump'... done

## Which RTP packet header field can be used to reorder out of sync RTP packets in the correct sequence?

Just reading involved here: [5.1 RTP Fixed Header
Fields](https://datatracker.ietf.org/doc/html/rfc3550#page-13).

## The trace includes a secret hidden message. Can you hear it?

We could command line this one but honestly Wireshark has a pretty keen
audio player. Fire it up, open up the PCAP, go to the “Telephony” menu,
pick SIP and play the streams.
