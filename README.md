# plugin-sdk-go

[![Go Reference](https://pkg.go.dev/badge/github.com/falcosecurity/plugin-sdk-go/pkg/sdk.svg)](https://pkg.go.dev/github.com/falcosecurity/plugin-sdk-go/pkg/sdk)
[![Release](https://img.shields.io/github/release/falcosecurity/plugin-sdk-go.svg?style=flat-square)](https://github.com/falcosecurity/plugin-sdk-go/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/falcosecurity/plugin-sdk-go?style=flat-square)](https://goreportcard.com/report/github.com/falcosecurity/plugin-sdk-go)
[![License](https://img.shields.io/github/license/falcosecurity/plugin-sdk-go?style=flat-square)](LICENSE)


Note: *The plugin system is a new feature introduced since Falco 0.31.0. You can find more detail in the original [proposal document](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md).*

## Introduction

This SDK facilitates writing [plugins](https://falco.org/docs/plugins) for [Falco](https://github.com/falcosecurity/falco) or application using [Falcosecurity's libs](https://github.com/falcosecurity/libs).

## Quick start

Before using this SDK, review the [developer's guide](https://falco.org/docs/plugins/developers_guide/) which fully documents the API and provides best practices for writing plugins. The developer's guide includes a [walkthrough](https://falco.org/docs/plugins/developers_guide/#example-go-plugin-dummy) of a plugin written in Go that uses this package.

For a quick start, you can refer to the provided examples:
 - [extractor plugin](https://github.com/falcosecurity/plugin-sdk-go/tree/main/examples/extractor) 
 - [source plugin](https://github.com/falcosecurity/plugin-sdk-go/tree/main/examples/source)
 - [source plugin with extraction](https://github.com/falcosecurity/plugin-sdk-go/tree/main/examples/full)



## What's next

When ready to release your plugin, make sure to register the plugin with the Falcosecurity organization by creating a PR to the [falcosecurity/plugins](https://github.com/falcosecurity/plugins) respository with details on the new plugin. This ensures that a given ID is used by exactly one source plugin, and allows source plugin authors and extractor plugin authors to coordinate about event source formats.

## Join the Community

To get involved with The Falco Project please visit [the community repository](https://github.com/falcosecurity/community) to find more.

How to reach out?

 - Join the [#falco](https://kubernetes.slack.com/messages/falco) channel on the [Kubernetes Slack](https://slack.k8s.io)
 - [Join the Falco mailing list](https://lists.cncf.io/g/cncf-falco-dev)


## Contributing

See the [CONTRIBUTING.md](https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md).

## Security Audit

A third party security audit was performed by Cure53, you can see the full report [here](./audits/SECURITY_AUDIT_2019_07.pdf).

## Reporting security vulnerabilities

Please report security vulnerabilities following the community process documented [here](https://github.com/falcosecurity/.github/blob/master/SECURITY.md).

## License Terms

This project is licensed to you under the [Apache 2.0](./LICENSE) open source license.


