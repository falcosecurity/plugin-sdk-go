# plugin-sdk-go

Go package to facilitate writing [Falco/Falco libs](https://falco.org/docs/plugins/) plugins.

Before using this package, review the [developer's guide](https://falco.org/docs/plugins/developers_guide/) which fully documents the API and provides best practices for writing plugins. The developer's guide includes a [walkthrough](https://falco.org/docs/plugins/developers_guide/#example-go-plugin-dummy) of a plugin written in Go that uses this package.

When ready to release your plugin, make sure to register the plugin with the Falcosecurity organization by creating a PR to modify the [PLUGINS-REGISTRY.md](https://github.com/falcosecurity/plugins/blob/master/plugins/PLUGINS-REGISTRY.md) file with details on the new plugin. This ensures that a given ID is used by exactly one source plugin, and allows source plugin authors and extractor plugin authors to coordinate about event source formats.


