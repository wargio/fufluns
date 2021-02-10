## fufluns - Copyright 2019-2021 - deroad

FROM archlinux/base:latest

RUN pacman -Syy --noconfirm python-pip wget tar unzip base-devel git

RUN mkdir -p /fufluns /tmp-build || sleep 0

RUN pip install tornado rzpipe wheel apkid meson ninja

WORKDIR /tmp-build

RUN chmod 777 /tmp-build

RUN cp /etc/sudoers /etc/sudoers.back || sleep 0

RUN pip wheel --wheel-dir=/tmp-build/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.11.0 && \
	pip uninstall -y yara-python && \
	pip install --no-index --find-links=/tmp-build/yara-python yara-python

RUN useradd builduser -m && passwd -d builduser && printf 'builduser ALL=(ALL) ALL\n' | tee -a /etc/sudoers

RUN git clone --depth=1 https://github.com/rizinorg/rizin rizin-master && chown -R builduser:builduser rizin-master
RUN su builduser -c 'cd /tmp-build/rizin-master && meson subprojects update && meson --reconfigure --prefix=/usr build && ninja -C build'
RUN cd /tmp-build/rizin-master && sudo ninja -C build install && cd - && sudo rm -rf rizin-master

RUN wget -q https://aur.archlinux.org/cgit/aur.git/snapshot/android-apktool.tar.gz && chmod 666 *.tar.gz
RUN su builduser -c 'cd /tmp-build && tar -xvf android-apktool.tar.gz && cd android-apktool && makepkg -s --noconfirm'
RUN cd /tmp-build/android-apktool && pacman -U --noconfirm *.xz && cd - && rm -rf *.tar.gz android-apktool

RUN wget -q https://aur.archlinux.org/cgit/aur.git/snapshot/android-sdk-platform-tools.tar.gz && chmod 666 *.tar.gz
RUN su builduser -c 'cd /tmp-build && tar -xvf android-sdk-platform-tools.tar.gz && cd android-sdk-platform-tools && makepkg -s --noconfirm'
RUN cd /tmp-build/android-sdk-platform-tools && pacman -U --noconfirm *.xz && cd - && rm -rf *.tar.gz android-sdk-platform-tools

## cleaning
RUN userdel builduser && mv /etc/sudoers.back /etc/sudoers || sleep 0

WORKDIR /

RUN rm -rf /tmp-build


## copying fufluns
COPY ./www/     /fufluns/www
COPY ./android/ /fufluns/android
COPY ./ios/     /fufluns/ios
COPY ./*.py     /fufluns/
COPY ./*.sh     /fufluns/
COPY ./LICENSE  /fufluns/

RUN chmod +x /fufluns/*.sh

## creating the user and setting cmd.
RUN useradd user -m && passwd -d user

EXPOSE 8080/tcp

RUN chown -R user /fufluns && chgrp -R user /fufluns

USER user

CMD ["/fufluns/fufluns.sh", "8080"]
