# go-away

Self-hosted abuse detection and rule enforcement against low-effort mass AI scraping and bots. 

[![Build Status](https://ci.gammaspectra.live/api/badges/git/go-away/status.svg)](https://ci.gammaspectra.live/git/go-away)
[![Go Reference](https://pkg.go.dev/badge/git.gammaspectra.live/git/go-away.svg)](https://pkg.go.dev/git.gammaspectra.live/git/go-away)

go-away sits in between your site and the Internet / upstream proxy.

Incoming requests can be selected by [rules](#rich-rule-matching) to be [actioned](#extended-rule-actions) or [challenged](#challenges) to filter suspicious requests.

The tool is designed highly flexible so the operator can minimize impact to legit users, while surgically targeting heavy endpoints or scrapers.

[Challenges](#challenges) can be transparent (not shown to user, depends on backend or other logic), [non-JavaScript](#non-javascript-challenges) (challenges common browser properties), or [custom JavaScript](#custom-javascript--wasm-challenges) (from Proof of Work to fingerprinting or Captcha is supported)

See _[Why?](#why)_ section for the challenges and reasoning behind this tool.

## Support

If you have some suggestion or issue, feel free to open a [New Issue](https://git.gammaspectra.live/git/go-away/issues/new) on the repository. 

[Pull Requests](https://git.gammaspectra.live/git/go-away/pulls) are encouraged and desired.

For real-time chat and other support join IRC on [##go-away](ircs://irc.libera.chat/##go-away) on Libera.Chat. The channel may not be monitored at all times, feel free to ping the operators there.


## Features

### Rich rule matching

[Common Expression Language (CEL)](https://cel.dev/overview/cel-overview) is used to allow arbitrary selection of client properties, not only limited to regex. Boolean operators are supported.

Templates can be defined in the Policy to allow reuse of such conditions on rule matching. Challenges can also be gated behind conditions.

See the [CEL Language Definition](https://github.com/google/cel-spec/blob/master/doc/langdef.md) for the syntax.

Rules and conditions are served with this environment:

```
remoteAddress (net.IP) - Connecting client remote address from headers or properties
host (string) - HTTP Host
method (string) - HTTP Method/Verb
userAgent (string) - HTTP User-Agent header
path (string) - HTTP request Path
query (map[string]string) - HTTP request Query arguments
headers (map[string]string) - HTTP request headers
   
Only available when TLS is enabled
   fpJA3N (string) JA3N TLS Fingerprint
   fpJA4 (string) JA4 TLS Fingerprint
```

Additionally, these functions are available:
```
Check whether a given IP is listed on the underlying defined network or CIDR
    inNetwork(networkName string, address net.IP) bool
    inNetwork(networkCIDR string, address net.IP) bool

Check whether a given IP is listed on the provided DNSBL
    inDNSBL(address net.IP) bool
```

### Template support

Internal or external templates can be loaded to customize the look of the challenge or error page. Additionally, themes can be configured to change the look of these quickly.

These templates are included by default:

* `anubis`: An anubis-like themed challenge.
* `forgejo`: Uses the Forgejo template and assets from your own instance. Supports specifying themes like `forgejo-light` and `forgejo-dark`.

External templates for your site can be loaded specifying a full path to the `.gohtml` file. See [embed/templates/](embed/templates/) for examples to follow.

### Extended rule actions

In addition to the common PASS / CHALLENGE / DENY rules, we offer CHECK and POISON.

CHECK allows the client to be challenged but continue matching rules after these.

POISON sends defined responses to bad clients that will annoy them.

### Multiple challenge matching

Several challenges can be offered as options for rules. This allows users that have passed other challenges before to not be affected.

For example:
```yaml
  - name: standard-browser
    action: challenge
    challenges: [http-cookie-check, self-preload-link, self-meta-refresh, self-resource-load, js-pow-sha256]
    conditions:
      - '($is-generic-browser)'
```

This rule has the user be checked against a backend, then attempts pass a few browser challenges.

In this case the processing would stop at `self-meta-refresh` due to the behavior of earlier challenges.

Any of these listed challenges being passed in the past will allow the client through, including non-offered `self-resource-load` and `js-pow-sha256`.

### Non-Javascript challenges

Several challenges that do not require JavaScript are offered, some targeting the HTTP stack and others a general browser behavior, or consulting with a backend service.

These can be used for light checking of requests that eliminate most of the low effort scraping.

See [Challenges](#challenges) below for a list of them.

### Custom JavaScript / WASM challenges

A WASM interface for server-side proof generation and checking is offered. We provide `js-pow-sha256` as an example of one.

An internal test has shown you can implement Captchas or other browser fingerprinting tests within this interface.

If you are interested in creating your own, see the [Development](#development) section below.

### Upstream PROXY support

Support for [HAProxy PROXY protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) can be enabled.

This allows sending the client IP without altering the connection or HTTP headers.

Supported by HAProxy, [Caddy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#proxy_protocol), [nginx](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_protocol) and others.

### Automatic TLS support and HTTP/2 support

You can enable automatic certificate generation and TLS for the site via any ACME directory, which enables HTTP/2.

Without TLS, HTTP/2 cleartext is supported, but you will need to configure the upstream proxy to send this protocol (`h2c://` on Caddy for example).


### TLS Fingerprinting

When running with TLS via autocert, TLS Fingerprinting of the incoming client is done.

This can be targeted on conditions or other application logic.

Read more about [JA3](https://medium.com/salesforce-engineering/tls-fingerprinting-with-ja3-and-ja3s-247362855967) and [JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md).


### DNSBL

You can configure a [DNSBL (Domain Name System blocklist)](https://en.wikipedia.org/wiki/Domain_Name_System_blocklist) to be queried on rules and conditions.

This allows you to serve harder or different challenges to higher risk clients, or block them from specific sections.

Only rules that match DNSBL will cause a query to be sent, meaning the bulk of requests will not be sent to this service upstream.

Results will be temporarily cached

By default, [DroneBL](https://dronebl.org/) is used.

### Network range loading

Network ranges can be loaded via fetched JSON / TXT / HTML pages, or via lists. You can filter these using _jq_ or a regex.

Example for _jq_:
```yaml
  aws-cloud:
    - url: https://ip-ranges.amazonaws.com/ip-ranges.json
      jq-path: '(.prefixes[] | select(has("ip_prefix")) | .ip_prefix), (.prefixes[] | select(has("ipv6_prefix")) | .ipv6_prefix)'
```

Example for _regex_:
```yaml
  cloudflare:
    - url: https://www.cloudflare.com/ips-v4
      regex: "(?P<prefix>[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+)"
    - url: https://www.cloudflare.com/ips-v6
      regex: "(?P<prefix>[0-9a-f:]+::/[0-9]+)"
```


### Sharing of signing seed across instances

You can share the signing secret across multiple of your instances if you'd like to deploy multiple across the world.

That way signed secrets will be verifiable across all the instances.

By default, a random temporary key is generated every run.

### Multiple backend support

Multiple backends are supported, and rules specific on backend can be defined, and conditions and rules can match this as well.

This allows one instance to run multiple domains or subdomains.

### Package path

You can modify the path where challenges are served and package name, if you don't want its presence to be easily discoverable.

No source code editing or forking necessary!

## Why?
In the past few years this small git instance has been hit by waves and waves of scraping.
This was usually fought back by random useragent blocks for bots that did not follow [robots.txt](/robots.txt), until the past half year, where low-effort mass scraping was used more prominently.

Recently these networks go from using residential IP blocks to sending requests at several hundred rps.

If the server gets sluggish, more requests pile up. Even when denied they scrape for weeks later. Effectively spray and pray scraping, process later.

At some point about 300Mbit/s of incoming requests (not including the responses) was hitting the server. And all at nonsense URLs

If AI is so smart, why not just git clone the repositories?


Xe (anubis creator) has written about similar frustrations in several blogposts:

* [Amazon's AI crawler is making my git server unstable](https://xeiaso.net/notes/2025/amazon-crawler/) [01/17/2025]
* [Anubis works](https://xeiaso.net/notes/2025/anubis-works/) [04/12/2025]

Drew DeVault (sourcehut) has posted several articles regarding the same issues:
* [Please stop externalizing your costs directly into my face](https://drewdevault.com/2025/03/17/2025-03-17-Stop-externalizing-your-costs-on-me.html) [17/03/2025]
  * (fun tidbit: I'm the one quoted as having the feedback discussion interrupted to deal with bots!)

Others were also suffering at the same time [[1]](https://donotsta.re/notice/AreSNZlRlJv73AW7tI) [[2]](https://community.ipfire.org/t/suricata-ruleset-to-prevent-ai-scraping/11974) [[3]](https://gabrielsimmer.com/blog/stop-scraping-git-forge) [[4]](https://gabrielsimmer.com/blog/stop-scraping-git-forge) [[5]](https://blog.nytsoi.net/2025/03/01/obliterated-by-ai).

---
Initially I deployed Anubis, and yeah, it does work!

This tool started as a way to replace [Anubis](https://anubis.techaro.lol/) as it was not found as featureful as desired.

go-away may not be as straight to configure as Anubis but this was chosen to reduce impact on legitimate users, and offers many more options to dynamically target new waves.

### Can't scrapers adapt?

Yes, they can. At the moment their spray-and-pray approach is cheap for them.

If they have to start adding an active browser in their scraping, that makes their collection expensive and slow. 

This would more or less eliminate the high rate low effort passive scraping and replace it with an active model. 

go-anubis offers a highly configurable set of challenges and rules that you can adapt to new ways.

## Example policies

### Forgejo

The policy file at [examples/forgejo.yml](examples/forgejo.yml) provides a ready template to be used on your own Forgejo instance.

Important notes:
* Edit the `homesite` rule, as it's targeted to common users or orgs on the instance. A better regex might be possible in the future.
* Edit the `http-cookie-check` challenge, as this will fetch the listed backend with the given session cookie to check for user login.
* Adjust the desired blocked networks or others. A template list of network ranges is provided, feel free to remove these if not needed.
* Check the conditions and base rules to change your challenges offered and other ordering.
* By default Googlebot / Bingbot / DuckDuckBot / Kagibot / Qwantbot / Yandexbot are allowed by useragent and network ranges.

### Generic

The policy file at [examples/generic.yml](examples/generic.yml) provides a baseline to place on any site, that can be modified to fit your needs.

Important notes:
* Edit the `homesite` rule, as it's targeted to pages you always want to have available, like landing pages.
* Edit the `is-static-asset` condition or the `allow-static-resources` rule to allow static file access as necessary.
* If you have an API, add a PASS rule targeting it.
* Check the conditions and base rules to change your challenges offered and other ordering.
* Add or modify rules to target specific pages on your site as desired.
* By default Googlebot / Bingbot / DuckDuckBot / Kagibot / Qwantbot / Yandexbot are allowed by useragent and network ranges.


## Setup

It is recommended to have another reverse proxy above (for example [Caddy](https://caddyserver.com/), nginx, HAProxy) to handle HTTPs or similar.

go-away for now only accepts plaintext connections, although it can take _HTTP/2_ / _h2c_ connections if desired over the same port.

### Binary / Go

Requires Go 1.24+. Builds statically without CGo usage.

```shell
git clone https://git.gammaspectra.live/git/go-away.git && cd go-away

CGO_ENABLED=0 go build -pgo=auto -v -trimpath -o ./go-away ./cmd/go-away

# Run on port 8080, forwarding matching requests on git.example.com to http://forgejo:3000
./go-away --bind :8080 \
--backend git.example.com=http://forgejo:3000 \
--policy examples/forgejo.yml \
--challenge-template forgejo --challenge-template-theme forgejo-dark

```

### Dockerfile

Available under [Dockerfile](Dockerfile). See the _docker compose_ below for the environment variables.

### docker compose

Example follows a hypothetical Forgejo server running on `http://forgejo:3000` serving `git.example.com`

```yaml
networks:
  forgejo:
    external: false
    
volumes:
  goaway_cache:
    
services:
  go-away:
    image: git.gammaspectra.live/git/go-away:latest
    restart: always
    ports:
      - "3000:8080"
    networks:
      - forgejo
    depends_on:
      - forgejo
    volumes:
      - "goaway_cache:/cache"
      - "./examples/forgejo.yml:/policy.yml:ro"
    environment:
      #GOAWAY_BIND: ":8080"
      # Supported tcp, unix, and proxy (for enabling PROXY module for request unwrapping)
      #GOAWAY_BIND_NETWORK: "tcp"
      #GOAWAY_SOCKET_MODE: "0770"
      
      # set to letsencrypt or other directory URL to enable HTTPS. Above ports will be TLS only.
      # enables request JA3N / JA4 client TLS fingerprinting
      # TLS fingerprints are served on X-TLS-Fingerprint-JA3N and X-TLS-Fingerprint-JA4 headers
      # TLS fingerprints can be matched against on CEL conditions
      #GOAWAY_ACME_AUTOCERT: ""
      
      # Cache path for several services like certificates and caching network ranges
      # Can be semi-ephemeral, recommended to be mapped to a permanent volume
      #GOAWAY_CACHE="/cache"
      
      # default is WARN, set to INFO to also see challenge successes and others
      #GOAWAY_SLOG_LEVEL: "INFO"
      
      # this value is used to sign cookies and challenges. by default a new one is generated each time
      # set to generate to create one, then set the same value across all your instances
      #GOAWAY_JWT_PRIVATE_KEY_SEED: ""
      
      # HTTP header that the client ip will be fetched from
      # Defaults to the connection ip itself, if set here make sure your upstream proxy sets this properly
      # Usually X-Forwarded-For is a good pick
      # Not necessary with GOAWAY_BIND_NETWORK: proxy
      GOAWAY_CLIENT_IP_HEADER: "X-Real-Ip"
      
      # HTTP header that go-away will set the obtained ip will be set to
      # If left empty, the header on GOAWAY_CLIENT_IP_HEADER will be left as-is
      #GOAWAY_BACKEND_IP_HEADER: ""
      
      GOAWAY_POLICY: "/policy.yml"
      
      # Template, and theme for the template to pick. defaults to an anubis-like one
      # An file path can be specified. See embed/templates for a few examples
      GOAWAY_CHALLENGE_TEMPLATE: forgejo
      GOAWAY_CHALLENGE_TEMPLATE_THEME: forgejo-dark
      
      # specify a DNSBL for usage in conditions. Defaults to DroneBL 
      # GOAWAY_DNSBL: "dnsbl.dronebl.org"
      
      GOAWAY_BACKEND: "git.example.com=http://forgejo:3000"
      
    # additional backends can be specified via more command arguments  
    # command: ["--backend", "ci.example.com=http://ci:3000"]

  forgejo:
    # etc.

```

## Challenges

#### http

Verify incoming requests against a specified backend to allow the user through. Cookies and some other headers are passed.

For example, this allows verifying the user cookies against the backend to have the user skip all other challenges.

Example on Forgejo, checks that current user is authenticated:
```yaml
  http-cookie-check:
    mode: http
    url: http://forgejo:3000/user/stopwatches
    # url: http://forgejo:3000/repo/search
    # url: http://forgejo:3000/notifications/new
    parameters:
      http-method: GET
      http-cookie: i_like_gitea
      http-code: 200
```

#### preload-link

Requires HTTP/2+ response parsing and logic, silent challenge (does not display a challenge page).

Browsers that support [103 Early Hints](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/103) are indicated to fetch a CSS resource via [Link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Link) preload that solves the challenge.

The server waits until solved or defined timeout, then continues on other challenges if failed.

Example:
```yaml
  self-preload-link:
    condition: '"Sec-Fetch-Mode" in headers && headers["Sec-Fetch-Mode"] == "navigate"'
    mode: "preload-link"
    runtime:
      # verifies that result = key
      mode: "key"
      probability: 0.1
    parameters:
      preload-early-hint-deadline: 3s
      key-code: 200
      key-mime: text/css
      key-content: ""
```

#### header-refresh

Requires HTTP response parsing and logic, displays challenge site instantly.

Have the browser solve the challenge by following the URL listed on HTTP [Refresh](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Refresh) instantly.


#### meta-refresh

Requires HTTP and HTML response parsing and logic, displays challenge site instantly.

Have the browser solve the challenge by following the URL listed on HTML `<meta http-equiv=refresh>` tag instantly. Equivalent to above.

#### resource-load

Requires HTTP and HTML response parsing and logic, displays challenge site.

Servers a challenge page with a linked resource that is loaded by the browser, which solves the challenge. Page refreshes a few seconds later via [Refresh](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Refresh).

Example:
```yaml
  self-resource-load:
    mode: "resource-load"
    runtime:
      # verifies that result = key
      mode: "key"
      probability: 0.1
    parameters:
      key-code: 200
      key-mime: text/css
      key-content: ""
```

#### cookie

Requires HTTP parsing and a Cookie Jar, silent challenge (does not display a challenge page unless failed).

Serves the client with a Set-Cookie that solves the challenge, and redirects it back to the same page. Browser must present the cookie to load.

Several tools implement this, but usually not mass scrapers.

#### js-pow-sha256

Requires JavaScript and workers, displays challenge site.

Has the user solve a Proof of Work using SHA256 hashes, with configurable difficulty.

Example:
```yaml
  js-pow-sha256:
    # Asset must be under challenges/{name}/static/{asset}
    # Other files here will be available under that path
    mode: js
    asset: load.mjs
    parameters:
      # difficulty is number of bits that must be set to 0 from start
      # Anubis challenge difficulty 5 becomes 5 * 8 = 20
      difficulty: 20
    runtime:
      mode: wasm
      # Verify must be under challenges/{name}/runtime/{asset}
      asset: runtime.wasm
      probability: 0.02
```




## Development

This Go package can be used as a command on `git.gammaspectra.live/git/go-away/cmd/go-away` or a library under `git.gammaspectra.live/git/go-away/lib`

### Compiling WASM runtime challenge modules

Custom WASM runtime modules follow the WASI `wasip1` preview syscall API.

It is recommended using TinyGo to compile / refresh modules, and some function helpers are provided.

If you want to use a different language or compiler, enable `wasip1` and the following interface must be exported:

```
// Allocation is a combination of pointer location in WASM memory and size of it
type Allocation uint64

func (p Allocation) Pointer() uint32 {
	return uint32(p >> 32)
}
func (p Allocation) Size() uint32 {
	return uint32(p)
}


// MakeChallenge MakeChallengeInput / MakeChallengeOutput are valid JSON.
// See lib/challenge/interface.go for a definition
func MakeChallenge(in Allocation[MakeChallengeInput]) Allocation[MakeChallengeOutput]

// VerifyChallenge VerifyChallengeInput is valid JSON.
// See lib/challenge/interface.go for a definition
func VerifyChallenge(in Allocation[VerifyChallengeInput]) VerifyChallengeOutput

func malloc(size uint32) uintptr
func free(size uintptr)

```

Modules will be recreated for each call, so there is no state leftover