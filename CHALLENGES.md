# Challenges

Challenges can be [transparent](#transparent) (not shown to user, depends on backend or other logic), [non-JavaScript](#non-javascript) (challenges common browser properties), or [custom JavaScript](README.md#custom-javascript) (from Proof of Work to fingerprinting or Captcha is supported)

## Transparent

### http

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

### preload-link

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

## Non-JavaScript

### cookie

Requires HTTP parsing and a Cookie Jar, silent challenge (does not display a challenge page unless failed).

Serves the client with a Set-Cookie that solves the challenge, and redirects it back to the same page. Browser must present the cookie to load.

Several tools implement this, but usually not mass scrapers.

### header-refresh

Requires HTTP response parsing and logic, displays challenge site instantly.

Have the browser solve the challenge by following the URL listed on HTTP [Refresh](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Refresh) instantly.


### meta-refresh

Requires HTTP and HTML response parsing and logic, displays challenge site instantly.

Have the browser solve the challenge by following the URL listed on HTML `<meta http-equiv=refresh>` tag instantly. Equivalent to above.

### resource-load

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

## Custom JavaScript

### js-pow-sha256

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

