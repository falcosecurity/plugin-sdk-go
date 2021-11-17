# Release Process

When we release we do the following process:

1. We decide together (usually in the #falco channel in [slack](https://kubernetes.slack.com/messages/falco)) what's the [next version](#About-versioning) to tag
2. A person with repository rights does the tag
3. The same person runs commands in their machine following the [Release commands](#Release-commands) section below
4. The tag is live on [Github](https://github.com/falcosecurity/plugin-sdk-go/releases) with the changelog attached

## Release commands

Just tag the [version](#About-versioning). For example:

```bash
git tag -a v0.1.0-rc.0 -m "v0.1.0-rc.0"
git push origin v0.1.0-rc.0
```

The [goreleaser](https://goreleaser.com/ci/) will run on CircleCI and do the magic :)

## About versioning

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Also, note that the `plugin-sdk-go` version is NOT paired with the Falco version nor with the Plugin API version.
However, any backward-incompatible changes introduced by Plugin API represent a breaking change for the `plugin-sdk-go` too.
In such a case, the major version (or the minor version when [major version is zero](https://semver.org/spec/v2.0.0.html#spec-item-4)) MUST be incremented.