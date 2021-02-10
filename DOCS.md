# Fufluns Internals

The software is written in a way which allows you to add security tests as "plugins".

Each test has to be placed in the appropriate folder:
 - Android: `/android/tests`
 - iOS: `/ios/tests`

## Writing a test for Android

This is the template of a plugin for android
```py
def run_tests(apk, pipes, utils, rzhelper, android_utils):
	for rz in pipes:
        pass

def name_test():
	return "My Test Name"
```

### APK object

The `apk` python object contains the following data:

- `apk.apktool` Temp folder where the apktool has unpacked the app (contains the `*.smali`)
- `apk.unzip` Temp folder where the unzip has unpacked the app (contains the `*.dex`)
- `apk.binary` [BinDetails](https://github.com/wargio/fufluns/blob/master/report.py#L28) object
- `apk.extra` [Extra](https://github.com/wargio/fufluns/blob/master/report.py#L160) object
- `apk.issues` [Issues](https://github.com/wargio/fufluns/blob/master/report.py#L93) object
- `apk.logger` [WebLogger](https://github.com/wargio/fufluns/blob/master/report.py#L183) object
- `apk.permis` [Permissions](https://github.com/wargio/fufluns/blob/master/report.py#L72) object
- `apk.srccode` [SourceCode](https://github.com/wargio/fufluns/blob/master/report.py#L116) object
- `apk.strings` [Strings](https://github.com/wargio/fufluns/blob/master/report.py#L136) object

## Writing a test for iOS

This is the template of a plugin for android
```py
## fufluns - Copyright 2019-2021 - deroad

def run_tests(ipa, pipe, utils, rzhelper):
    pass

def name_test():
	return "My Test Name"
```

### IPA object

The `ipa` python object contains the following data:

- `ipa.directory` Temp folder where the unzip has unpacked the app
- `ipa.binary` [BinDetails](https://github.com/wargio/fufluns/blob/master/report.py#L28) object
- `ipa.extra` [Extra](https://github.com/wargio/fufluns/blob/master/report.py#L160) object
- `ipa.issues` [Issues](https://github.com/wargio/fufluns/blob/master/report.py#L93) object
- `ipa.logger` [WebLogger](https://github.com/wargio/fufluns/blob/master/report.py#L183) object
- `ipa.permis` [Permissions](https://github.com/wargio/fufluns/blob/master/report.py#L72) object
- `ipa.srccode` [SourceCode](https://github.com/wargio/fufluns/blob/master/report.py#L116) object
- `ipa.strings` [Strings](https://github.com/wargio/fufluns/blob/master/report.py#L136) object

## Create a test

The easiest way to create a test is to use the method `test` available in `utils`.

```py
utils.test(ipa_or_apk, boolean_value, detail, description, severity)
```
where:

- `ipa_or_apk` (object) is the `ipa` or `apk` object
- `boolean_value` (bool) if the test has failed (i.e. `False`) the detail, descr and severity will be added to the list of the security issues.
- `detail` (string) shortly describes the security issue
- `description` (string) is the full description of the issue.
- `severity` (float) is the CVSS score of the vulnerability; you can use the [CVSS calculator](https://www.first.org/cvss/calculator/3.0).

