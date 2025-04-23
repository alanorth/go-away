// yaml_stream.jsonnet
local Build(go, alpine, os, arch) = {
    kind: "pipeline",
    type: "docker",
    name: "build-" + go + "-alpine" + alpine + "-" + arch,
    platform: {
        os: os,
        arch: arch
    },
    environment: {
        GOTOOLCHAIN: "local",
        CGO_ENABLED: "0",
        GOOS: os,
        GOARCH: arch,
    },
    steps: [
        {
            name: "build",
            image: "golang:" + go +"-alpine" + alpine,
            commands: [
                "apk update",
                "apk add --no-cache git",
                "mkdir .bin",
                "go build -v -o ./.bin/go-away ./cmd/go-away",
                "go build -v -o ./.bin/test-wasm-runtime ./cmd/test-wasm-runtime",
            ],
        },
        {
            name: "test-wasm-success",
            image: "alpine:" + alpine,
            depends_on: ["build"],
            commands: [
                "./.bin/test-wasm-runtime -wasm ./embed/challenge/js-pow-sha256/runtime/runtime.wasm " +
                "-make-challenge ./embed/challenge/js-pow-sha256/test/make-challenge.json " +
                "-make-challenge-out ./embed/challenge/js-pow-sha256/test/make-challenge-out.json " +
                "-verify-challenge ./embed/challenge/js-pow-sha256/test/verify-challenge.json " +
                "-verify-challenge-out 0",
            ],
        },
        {
            name: "test-wasm-fail",
            image: "alpine:" + alpine,
            depends_on: ["build"],
            commands: [
                "./.bin/test-wasm-runtime -wasm ./embed/challenge/js-pow-sha256/runtime/runtime.wasm " +
                "-make-challenge ./embed/challenge/js-pow-sha256/test/make-challenge.json " +
                "-make-challenge-out ./embed/challenge/js-pow-sha256/test/make-challenge-out.json " +
                "-verify-challenge ./embed/challenge/js-pow-sha256/test/verify-challenge-fail.json " +
                "-verify-challenge-out 1",
            ],
        },
    ]
};

local Publish(registry, repo, secret, go, alpine, os, arch, trigger, platforms, extra) = {
    kind: "pipeline",
    type: "docker",
    name: "publish-" + go + "-alpine" + alpine + "-" + secret,
    platform: {
        os: os,
        arch: arch,
    },
    trigger: trigger,
    steps: [
        {
            name: "docker",
            image: "plugins/buildx",
            privileged: true,
            environment: {
                DOCKER_BUILDKIT: "1"
            },
            settings: {
                  registry: registry,
                  repo: repo,
                  compress: true,
                  platform: platforms,
                  builder_driver: "docker-container",
                  build_args: {
                    from_builder: "golang:" + go +"-alpine" + alpine,
                    from: "alpine:" + alpine,
                  },
                  auto_tag_suffix: "alpine" + alpine,
                  username: {
                    from_secret: secret + "_username",
                  },
                  password: {
                    from_secret: secret + "_password",
                  },
            } + extra,
        },
    ]
};

#
local containerArchitectures = ["linux/amd64", "linux/arm64", "linux/riscv64"];

[
    Build("1.24", "3.21", "linux", "amd64"),
    Build("1.24", "3.21", "linux", "arm64"),

    # latest
    Publish("git.gammaspectra.live", "git.gammaspectra.live/git/go-away", "git", "1.24", "3.21", "linux", "amd64", {event: ["push"], branch: ["master"], }, containerArchitectures, {tags: ["latest"],}) + {name: "publish-latest-git"},
    Publish("codeberg.org", "codeberg.org/weebdatahoarder/go-away", "codeberg", "1.24", "3.21", "linux", "amd64", {event: ["push"], branch: ["master"], }, containerArchitectures, {tags: ["latest"],}) + {name: "publish-latest-codeberg"},

    # modern
    Publish("git.gammaspectra.live", "git.gammaspectra.live/git/go-away", "git", "1.24", "3.21", "linux", "amd64", {event: ["promote", "tag"], target: ["production"], }, containerArchitectures, {auto_tag: true,}),
    Publish("codeberg.org", "codeberg.org/weebdatahoarder/go-away", "codeberg", "1.24", "3.21", "linux", "amd64", {event: ["promote", "tag"], target: ["production"], }, containerArchitectures, {auto_tag: true,}),
]