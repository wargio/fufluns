# Fufluns

Easy to use APK/IPA Mobile App Inspector (experimental)

## Features

Detects common fails in compiled apps for Android and iOS (iPhones, iPads, etc..)

- Android
	- APKiD
	- Secrets (Private keys, API keys, etc..)
	- Insecure AndroidManifest.xml attributes
	- Network Security
	- Permissions
	- Root Detection
	- Source Code
	- SQL Injections

- iOS
	- Compiler options (-fstack-protector-all, -fobjc-arc, -pie, etc..)
	- Insecure C imports (memcmp, memcpy, memmove, me​mset, etc..)
	- Jailbreak Detection
	- Network Security
	- Permissions
	- Secrets (Private keys, API keys, etc..)
	- Source Code
	- SQL Injections

## Export

The tool allows to export the data in JSON, Markdown and Textile formats.

## Tools Required

- APKiD
- Apktool (and the Android Platform Tools)
- radare2 (python r2pipe)

# Docker

To build a docker image just run

```bash
docker build -t fufluns:latest .
```

# Debug

To debug http traffic, you need to define the environment variable 'DEBUG_MODE'.

For example:

```bash
DEBUG_MODE=1 ./fufluns.sh
```

# FAQ

I cannot reach the container from the browser.

```bash
docker run -it --rm -p 8080:8080 fufluns:latest
```
