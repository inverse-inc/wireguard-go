# Inverse's implementation of the wireguard client

## How to build Windows client

NOTE: These instructions need to be executed on a Windows computer

First, clone this repo and then run:

```
.\build_windows.bat
cd windows_installer
.\build.bat
```

The first bat command will output the binaries in x86/ and amd64/

The second bat command will output MSI installers in windows_installer/dist/

The build script should poll all dependencies that are required so running this on a bare Windows should work fine.

## How to build Linux client

Building on Linux is easy enough, just run:

```
make
```

This client isn't packaged in .deb or .rpm yet but the binary doesn't depend on anything and should run fine on any recent kernel.

