# go-away

Self-hosted abuse detection and rule enforcement against low-effort mass AI scraping and bots.

[![Build Status](https://ci.gammaspectra.live/api/badges/git/go-away/status.svg)](https://ci.gammaspectra.live/git/go-away)
[![Go Reference](https://pkg.go.dev/badge/git.gammaspectra.live/git/go-away.svg)](https://pkg.go.dev/git.gammaspectra.live/git/go-away)

This documentation is a work in progress. For now, see policy examples under [examples/](examples/).

## Setup

It is recommended to have another reverse proxy above (for example [Caddy](https://caddyserver.com/), nginx, HAProxy) to handle HTTPs or similar.

go-away for now only accepts plaintext connections, although it can take _HTTP/2_ / _h2c_ connections if desired over the same port.

### Binary / Go

Requires Go 1.24+. Builds statically without CGo.

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

```yaml
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
      - "./examples/forgejo.yml:/policy.yml:ro"
    environment:
      #GOAWAY_BIND: ":8080"
      #GOAWAY_BIND_NETWORK: "tcp"
      #GOAWAY_SOCKET_MODE: "0770"
      
      # default is WARN, set to INFO to also see challenge successes and others
      #GOAWAY_SLOG_LEVEL: "INFO"
      
      # this value is used to sign cookies and challenges. by default a new one is generated each time
      # set to generate to create one, then set the same value across all your instances
      #GOAWAY_JWT_PRIVATE_KEY_SEED: ""
      
      # HTTP header that the client ip will be fetched from
      # Defaults to the connection ip itself, if set here make sure your upstream proxy sets this properly
      # Usually X-Forwarded-For is a good pick
      GOAWAY_CLIENT_IP_HEADER: "X-Real-Ip"
      
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

```


## Example policies

### Forgejo

The policy file at [examples/forgejo.yml](examples/forgejo.yml) provides a ready template to be used on your own Forgejo instance.

Important notes:
* Edit the `homesite` rule, as it's targeted to common users or orgs on the instance. A better regex might be possible in the future.
* Edit the `http-cookie-check` challenge, as this will fetch the listed backend with the given session cookie to check for user login.
* Adjust the desired blocked networks or others. A template list of network ranges is provided, feel free to remove these if not needed.
* Check the conditions and base rules to change your challenges offered and other ordering.


## Development

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