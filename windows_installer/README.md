
# Bumping the version

In order to adjust the version of the installer, modify traywrapper/version/version.h

# How to build the Windows agent

NOTE: Although you can build the wireguard-go binary on any platform, you can only build the DMG on Windows itself. Also, the guiwrapper will not build if you're not on Windows.

First you need to build the binaries using the build script in the parent directory:

```
cd ..
.\build_windows.bat
```

Next, you need to build the MSI:

```
cd windows_installer
.\build.bat
```

Once the build is complete, you will find the MSI in dist/

