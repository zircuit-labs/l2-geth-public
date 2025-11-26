# L2 Geth Public

The L2 Geth is Zircuit’s modified version of the [Ethereum Geth client](https://github.com/ethereum/go-ethereum), adapted to function in the rollup setting.

This version of L2 Geth has been further modified for public use as a replica only. Certain proprietary functionality only required by the sequencer nodes has been removed.

## Zircuit Bug Bounty Program

This repository is subject to the Zircuit Bug Bounty Program. Please see [SECURITY.md](SECURITY.md) for more information.

## How To Test

Go test files are included, and can be run using the standard `go test` commands. Please be aware that some tests can take a very long time to execute.

## How To Build

You must have installed Docker with a version that supports [Bake](https://docs.docker.com/build/bake/). Simply run `make build` to build a local docker image based on this source code.

### Note On Repeatable Builds

We leverage images from [Chainguard](https://images.chainguard.dev/) to help ensure our supply chain is free from unexpected vulnerabilities. As a consequence, the `:latest` image tags from the base images used in this build may change frequently, and the final image produced may therefore have a different SHA depending on when it was built, even if the code itself remains identical.

## How To Run A Node

The best way to run a Zircuit replica node is to follow the instructions on the [Zircuit Docs](https://docs.zircuit.com/build/start/node) webpage.

## Contact Zircuit

We are happy to talk to you on [discord](https://discord.gg/zircuit)
