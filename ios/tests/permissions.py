## fufluns - Copyright 2019-2021 - deroad

import glob
import os
import plistlib

ios_permissions = {
	"NSBluetoothAlwaysUsageDescription": "A message that tells the user why the app needs access to Bluetooth.",
	"NSBluetoothPeripheralUsageDescription": "A message that tells the user why the app is requesting the ability to connect to Bluetooth peripherals.",
	"NSCalendarsUsageDescription": "A message that tells the user why the app is requesting access to the user’s calendar data.",
	"NSRemindersUsageDescription": "A message that tells the user why the app is requesting access to the user’s reminders.",
	"NSCameraUsageDescription": "A message that tells the user why the app is requesting access to the device’s camera.",
	"NSMicrophoneUsageDescription": "A message that tells the user why the app is requesting access to the device’s microphone.",
	"NSContactsUsageDescription": "A message that tells the user why the app is requesting access to the user’s contacts.",
	"NSFaceIDUsageDescription": "A message that tells the user why the app is requesting the ability to authenticate with Face ID.",
	"NSDesktopFolderUsageDescription": "A message that tells the user why the app needs access to the user’s Desktop folder.",
	"NSDocumentsFolderUsageDescription": "A message that tells the user why the app needs access to the user’s Documents folder.",
	"NSDownloadsFolderUsageDescription": "A message that tells the user why the app needs access to the user’s Downloads folder.",
	"NSNetworkVolumesUsageDescription": "A message that tells the user why the app needs access to files on a network volume.",
	"NSRemovableVolumesUsageDescription": "A message that tells the user why the app needs access to files on a removable volume.",
	"NSFileProviderPresenceUsageDescription": "A message that tells the user why the app needs to be informed when other apps access files that it manages.",
	"NSFileProviderDomainUsageDescription": "A message that tells the user why the app needs access to files managed by a file provider.",
	"NSHealthClinicalHealthRecordsShareUsageDescription": "A message to the user that explains why the app requested permission to read clinical records.",
	"NSHealthShareUsageDescription": "A message to the user that explains why the app requested permission to read samples from the HealthKit store.",
	"NSHealthUpdateUsageDescription": "A message to the user that explains why the app requested permission to save samples to the HealthKit store.",
	"NSHealthRequiredReadAuthorizationTypeIdentifiers": "The clinical record data types that your app must get permission to read.",
	"NSHomeKitUsageDescription": "A message that tells the user why the app is requesting access to the user’s HomeKit configuration data.",
	"NSLocationAlwaysAndWhenInUseUsageDescription": "A message that tells the user why the app is requesting access to the user’s location information at all times.",
	"NSLocationUsageDescription": "A message that tells the user why the app is requesting access to the user’s location information.",
	"NSLocationWhenInUseUsageDescription": "A message that tells the user why the app is requesting access to the user’s location information while the app is running in the foreground.",
	"NSLocationAlwaysUsageDescription": "A message that tells the user why the app is requesting access to the user's location at all times.",
	"NSAppleMusicUsageDescription": "A message that tells the user why the app is requesting access to the user’s media library.",
	"NSMotionUsageDescription": "A message that tells the user why the app is requesting access to the device’s accelerometer.",
	"NFCReaderUsageDescription": "A message that tells the user why the app is requesting access to the device’s NFC hardware.",
	"NSPhotoLibraryAddUsageDescription": "A message that tells the user why the app is requesting write-only access to the user’s photo library.",
	"NSPhotoLibraryUsageDescription": "A message that tells the user why the app is requesting access to the user’s photo library.",
	"NSAppleScriptEnabled": "A Boolean value indicating whether AppleScript is enabled.",
	"NSAppleEventsUsageDescription": "A message that tells the user why the app is requesting the ability to send Apple events.",
	"NSSystemAdministrationUsageDescription": "A message in macOS that tells the user why the app is requesting to manipulate the system configuration.",
	"ITSAppUsesNonExemptEncryption": "A Boolean value indicating whether the app uses encryption.",
	"ITSEncryptionExportComplianceCode": "The export compliance code provided by App Store Connect for apps that require it.",
	"NSSiriUsageDescription": "A message that tells the user why the app is requesting to send user data to Siri.",
	"NSSpeechRecognitionUsageDescription": "A message that tells the user why the app is requesting to send user data to Apple’s speech recognition servers.",
	"NSVideoSubscriberAccountUsageDescription": "A message that tells the user why the app is requesting access to the user’s TV provider account.",
	"UIRequiresPersistentWiFi": "A Boolean value indicating whether the app requires a Wi-Fi connection.",
}

def has_permission(ipa, plist, u, permission, description):
	p = u.dk(plist, permission, "")
	if (isinstance(p, "".__class__) and len(p) > 0) or isinstance(p, bool):
		u.permission(ipa, permission, description)

def run_tests(ipa, pipe, u, rzh):
	tmp = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "Info.plist"), recursive=True)]
	plist = {}
	if len(tmp) > 0:
		plist = plistlib.readPlist(tmp[0])

	for key in ios_permissions:
		has_permission(ipa, plist, u, key, ios_permissions[key])

def name_test():
	return "Detection permission"
