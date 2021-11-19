## fufluns - Copyright 2019-2021 - deroad

FROM alpine:edge

WORKDIR /
RUN apk add --update py-pip wget curl tar unzip xz git bash openjdk11 android-tools alpine-sdk python3-dev
RUN mkdir -p /fufluns || sleep 0
RUN pip install tornado rzpipe wheel apkid
RUN wget -q https://github.com/rizinorg/rizin/releases/download/v0.3.1/rizin-v0.3.1-static-x86_64.tar.xz -O rizin.tar.xz && tar -xvkf rizin.tar.xz && rm -rf rizin.tar.xz

RUN pip wheel --wheel-dir=/tmp-build/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.11.0 && \
	pip uninstall -y yara-python && \
	pip install --no-index --find-links=/tmp-build/yara-python yara-python

WORKDIR /usr/local/bin
RUN curl -sLO https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool && chmod +x apktool
RUN curl -sL -o apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.5.0.jar && chmod +x apktool.jar

RUN apk del alpine-sdk python3-dev wget tar git curl xz

## copying fufluns
WORKDIR /

COPY ./www/     /fufluns/www
COPY ./android/ /fufluns/android
COPY ./ios/     /fufluns/ios
COPY ./*.py     /fufluns/
COPY ./*.sh     /fufluns/
COPY ./LICENSE  /fufluns/

RUN chmod +x /fufluns/*.sh

## creating the user and setting cmd.
RUN adduser -D user

EXPOSE 8080/tcp

RUN chown -R user /fufluns && chgrp -R user /fufluns

USER user

CMD ["/fufluns/fufluns.sh", "8080"]
