This repository contains a family of utilities and common libraries developed by primary for my own use.

- They serve narrow purposes
- They are designed with somewhat greater complexity at a somewhat higher level of abstraction than strictly necessary, primarily because building them should be fun, an interesting challenge and educational
- The code is littered with proof of concepts with no other purpose than to prove something could be done
- They are not well tested, but they were built with care and they are used in practice

The audience is intended to be a mix of Rust enthusiasts, hobbyist programmers, university students and those building small projects with a small budgets (think small volunteer organizations or cash-poor startups). I am or have been all of those.

Currently, two projects are contained in here that I wish to highlight, `borink-git` and it's dependent, `borink-git-derive`.

### `borink-git`

Sometimes you want to have part of a Git repository at a specific point in time, while minimizing the time spent cloning it and checking out commits you don't need. Modern Git offers great tools for this (sparse checkout, filtered clones) and `borink-git` simply seeks to be a thin wrapper around them to highlight those features and make them available in an easy-to-use interface. 

A lot of this is possible also with the APIs provided by software forges, but that would mean building different versions of e.g. GitHub and GitLab. Using the shared Git interface means both are equally well supported (provided they support these modern Git features). 

`borink-git`'s main API is can be summarized as the following:

> Give it a Git "address" (the triple consisting of a repository url, path within the repository, commit) and it provides you with a path on the filesystem that contains the subpath you requested at the exact commit state. 

This is a surprisingly useful API, that otherwise would require a full Git clone and a Git checkout, where in the clone you often download more than you need and with the checkout you get the full repository. `borink-git` does only a single clone for each combination of repository url and repository subpath, which it does in "sparse" mode (the `--sparse` option) and using a "treeless clone" (using `--filter:tree:0`). When a specific commit is requested, it checks it out and copies the files to a new path. It's also idempotent and doesn't redownload when a specific address has been requested before.

It relies on a modern version of Git being available in the path and on the presence of a filesystem. In practice, this means WASM isn't supported.

The main API of `borink-git` requires a full SHA-1 commit id. This is because the translation of a "commit-like" name to a specific commit uses quite a bit of "smarts" and thus would require multiple callouts to a Git process, which would be slow to do on every request. Instead, consumers of the `borink-git` API are expected to handle the translation. `borink-git` does provide a `GitRefStore` trait that could be used the store these translations. An implementation for an SQLite-backed key-value store and a HashMap are provided (the former behind the `kv` feature flag).

### `borink-git-derive`

Git repositories are source repositories and should not contain binary artifacts. In principle, such artifacts should be reproducible builds derived from the source. There are ways you can host these on software forges like GitHub, using e.g. release downloads built using GitHub Actions. However, you might not want to rely on GitHub also for your artifacts. Migrating your source code off GitHub is easy. Migrating away from those actions, less so. 

You might want to make "derivations" of source code available through a web server, which could be compiled on-demand. An example would be the compilation of Typst (a LaTeX alternative) PDFs from the source files in your repository. 

`borink-git-derive` aims to serve the above need and is built on top of `borink-git`. Its main API can be summarized as:

> Register a "plugin" that performs takes in a path to the filesystem and generates some bytes from it
> Call the `derive_with` function with a plugin name and a cache implementation. Note that derivations are expected to be reproducible and so a call for the same Git address and plugin name will return the cached response. By default responses are cached to an SQLite-backed key-value store.

The above example of a Typst compilation is built-in with the `typst-compile` feature flag.

To make it easy to immediately set up, a very simple web server is also provided. No async, just a single loop that handles a single request at a time (using `tinyhttp`), to ensure sequential execution and no data races when dealing with Git and the file system.

A CLI is also provided to start the web server and configure a variety of things, such as the repository URL. Furthermore, a client CLI is provided to populate the Git ref store with all the tags and current branch refs.

### `borink-kv`

`borink-kv` is a very simple key-value store built on top of SQLite using Rusqlite.