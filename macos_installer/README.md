
# How to build the Mac OS agent

NOTE: Although you can build the wireguard-go binary on any platform, you can only build the DMG on Mac OS itself. Also, the guiwrapper will not build if you're not on Mac OS.

First you need to build the binaries using the build script in the parent directory:

```
cd ..
./build_macos.sh
```

Next, you need to build the DMG:

```
cd macos_installer
./build.sh
```

Once the build is complete, you will find the DMG in dist/

The build will also attempt to sign the code while building it using a key in your Mac OS keystore named 'Inverse'

