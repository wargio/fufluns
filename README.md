[![CircleCI](https://circleci.com/gh/wargio/fufluns/tree/master.svg?style=svg)](https://circleci.com/gh/wargio/fufluns/tree/master) [![Docker Builds](https://img.shields.io/docker/cloud/build/deroad/fufluns)](https://hub.docker.com/r/deroad/fufluns/tags) [![Docker Pulls](https://img.shields.io/docker/pulls/deroad/fufluns)](https://hub.docker.com/r/deroad/fufluns/tags)

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

You can download it from docker hub or build it by yourself.

## Download from docker hub

```bash
# Download first the image
docker pull deroad/fufluns:latest .
# run the image
docker run -it --rm -p 8080:8080 deroad/fufluns:latest
```

## Or Build from sources

To build a docker image just run

```bash
# Build first the image
docker build -t fufluns:latest .
# Run the built image
docker run -it --rm -p 8080:8080 fufluns:latest
```

# Debug

To debug http traffic, you need to define the environment variable 'DEBUG_MODE'.

For example:

```bash
DEBUG_MODE=1 ./fufluns.sh
```
# Development

Check the documents here: https://github.com/wargio/fufluns/blob/master/DOCS.md
