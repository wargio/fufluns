## fufluns - Copyright 2019-2021 - deroad

FROM alpine:edge

WORKDIR /
RUN apk add --update py-pip wget tar unzip xz bash openjdk11 android-tools
RUN mkdir -p /fufluns || sleep 0
RUN pip install tornado rzpipe wheel apkid urllib3
RUN wget -q https://github.com/rizinorg/rizin/releases/download/v0.4.0/rizin-v0.4.0-static-x86_64.tar.xz -O rizin.tar.xz && \
	tar -xvkf rizin.tar.xz && \
	rm -rfv rizin.tar.xz \
		share/rizin/sigdb/ \
		lib/pkgconfig/ \
		lib/*.a \
		share/man/ \
		include/

WORKDIR /usr/local/bin
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O apktool && \
	chmod +x apktool
RUN wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.6.1/apktool_2.6.1.jar -O apktool.jar && \
	chmod +x apktool.jar

RUN apk del wget tar unzip xz

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

RUN chown -R user /fufluns && \
	chgrp -R user /fufluns

USER user

CMD ["/fufluns/fufluns.sh", "8080"]
