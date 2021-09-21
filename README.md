# plugin-sdk-go

Status: **Under development**

Note: *The plugin system is a new feature and is still under active development. You can find more detail in the original [proposal document](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md). Since this feature has not yet been released in Falco, consider it as experimental at the moment.*

Go package to facilitate writing [Falco/Falco libs](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins) plugins.

Before using this package, review the [developer's guide](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/developers_guide/) which fully documents the API and provides best practices for writing plugins. The developer's guide includes a [walkthrough](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/developers_guide/#example-go-plugin-dummy) of a plugin written in Go that uses this package.

When ready to release your plugin, make sure to register the plugin with the Falcosecurity organization by creating a PR to modify the [PLUGINS-REGISTRY.md](https://github.com/falcosecurity/plugins/blob/master/plugins/PLUGINS-REGISTRY.md) file with details on the new plugin. This ensures that a given ID is used by exactly one source plugin, and allows source plugin authors and extractor plugin authors to coordinate about event source formats.


