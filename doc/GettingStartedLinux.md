# Getting Started with Linux

Developing outside the container isn't recommended. See [Local Dev](#Local-Dev) for details.

## Dev Container

We use Ubuntu as the base image and validate two methods for consuming the build image. Ensure you have `docker-compose`
installed and can download ~5GB on first run for the Linux container. The repo provides a build image for Linux. Clone
the repo locally, then launch the container. Your local repo will be mounted with `rw`.

> On a Windows host, install with `winget install -e --id Docker.DockerDesktop`

### With Dev Containers

Use `/.devcontainer/devcontainer.json`. Launch however you prefer / is appropriate for your choice of tools.

If using VS Code with the repo already opened as your workspace, you can open the command palette and select
`Dev Container: Reopen in Container`.

### Manually

```shell
cd docker/linux
docker-compose build
docker-compose up --detach
docker-compose exec gpalinuxdev /bin/bash
```

### Once Within Container

The full build, all tests, and all packaging can be run with:

```shell
chmod +x ./build-linux.sh
./build-linux.sh
```

> A `uname -r` matched linux headers package isn't available under WSL2, so the
> generic package will be used instead. If you're still having issues building, or generic doesn't work with a different
> base image, you can disable the WSL2 backend in Docker Desktop's settings (note this will come with a performance
> penalty).

## Local Dev

The dockerfile relies upon [this script](../docker/linux/install.sh) which you can try to run directly. Keep in mind it
and the build script make changes to your system which may be undesired and your results may vary. If you chose to use
the script, run it as root to set up your machine then follow the [Once Within Container](#once-within-container) steps
to build.
