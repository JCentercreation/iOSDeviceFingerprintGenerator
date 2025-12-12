# iOSDeviceFingerprintGenerator

**Swift Package Manager** • **MIT License**

Production-grade iOS device fingerprinting library. Generates persistent, unique device IDs using 25+ hardware and behavioral signals with Keychain caching and risk scoring.

<div align="center">

![Swift](https://img.shields.io/badge/Swift-5.9+-orange.svg)
![Platform](https://img.shields.io/badge/Platform-iOS15+-blue.svg)
![Xcode](https://img.shields.io/badge/Xcode-15.0+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

</div>

## Documentation

Find full documentation [here](https://jcentercreation.github.io/iOSDeviceFingerprintGenerator/documentation/iosdevicefingerprintgenerator/)

## Overview

Key features include:

- **25+ signals**: Hardware (model, disk, battery, thermal) + Behavioral (locale, network, VPN, tracking)
- **Persistent storage**: Keychain caching (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`)
- **Risk scoring**: VPN/proxy/emulator confidence (0.0-1.0)
- **Actor isolation**: Thread-safe, async API
- **No external dependencies**: Pure Foundation + UIKit + CryptoKit
- **Performance**: <200ms cold, <10ms cached

## Requirements

| Platform | Minimum Version |
|----------|-----------------|
| iOS | 15.0+ |
| Xcode | 15.0+ |
| Swift | 5.9+ |

## Installation

### Swift Package Manager

Add to `Package.swift`:
```swift
dependencies:  .package(url: “https://github.com/JCentercreation/iOSDeviceFingerprintGenerator.git”, from: “1.0.0”)
```

### Xcode

1. File → Add Package Dependencies
2. Enter package URL: `https://github.com/JCentercreation/iOSDeviceFingerprintGenerator.git`
3. Select version rule: "Up to Next Major Version"

## Usage

### Basic Fingerprinting
```swift
import iOSDeviceFingerprintGenerator
let fingerprint = await iOSDeviceFingerprintGenerator.shared.generateDeviceFingerprint()
print(“DeviceID: fingerprint.riskConfidenceLevel, format: .percent)”) print(“Hardware: fingerprint.behaviourSignals.count) signals”)
```

### Full Signal Inspection
```swift
let fingerprint = await iOSDeviceFingerprintGenerator.shared.generateDeviceFingerprint()
print(“Model: fingerprint.hardwareSignals“screenResolution” ?? “N/A”)”)
 print(“Free disk: fingerprint.behaviourSignals“networkType” ?? “N/A”)”)
print(“VPN: fingerprint.behaviourSignals“isAdvertisingTrackingEnabled” as? Bool ?? false)”)
```

## Signals Collected

### Hardware (12 signals)
| Signal | Source |
|--------|--------|
| model | `utsname()` |
| systemVersion | `UIDevice` |
| screenResolution | `UIScreen` |
| batteryLevel/State | `UIDevice` |
| diskSpace (total/available) | `FileManager` |
| processorCount | `ProcessInfo` |
| physicalMemory | `ProcessInfo` |
| systemUptime | `ProcessInfo` |
| thermalState | `ProcessInfo` |
| lowPowerMode | `ProcessInfo` |

### Behavioral (13 signals)
| Signal | Source |
|--------|--------|
| timezone/locale | `TimeZone`/`Locale` |
| preferredLanguages | `Locale` |
| calendar | `Calendar` |
| keyboardLanguages | `UITextInputMode` |
| vendorID | `UIDevice` |
| trackingStatus | `ATTrackingManager` |
| networkType | `NWPathMonitor` |
| vpnConnected | `CFNetworkCopySystemProxySettings` |
| proxyConfigured | `CFNetworkCopySystemProxySettings` |

## API Reference

### Core API

- **`generateDeviceFingerprint() async → FingerprintInfo`**
  Single call returning cached/persistent device ID + all signals + risk score

### FingerprintInfo Structure
```swift
public struct FingerprintInfo {
   public let deviceID: String
  public let hardwareSignals: String: Any
  public let behaviourSignals: String: Any
  public let riskConfidenceLevel: Float // 0.0-1.0
}
```

## Security & Privacy

✅ **Persistent**: Survives app restarts (Keychain)  
✅ **Unique**: 98-99.5% entropy (25+ signals)  
✅ **Privacy-safe**: No network calls, local processing  
⚠️ **Risk scoring**: VPN(+0.3)/Proxy(+0.3)/Emulator(+0.4)  
🔒 **Actor-isolated**: Thread-safe execution  

## Performance
- Cold start:   120-180ms (Keychain + signals + SHA256)
- Cached hit:    8-12ms  (Keychain read only)
- Network wait: +50-100ms (NWPathMonitor)

## Limitations

- Simulator detectable (risk +0.4)
- VPN/Proxy increases risk score (+0.6 total)
- ATT denial reduces behavioral entropy
- Network timeout: 200ms max for `NWPathMonitor`

## License

MIT License © 2025 Javier Carrillo

<div align="center">

**Made for the iOS development community.**  
**Use responsibly and only for fraud prevention.**

[⬆ Back to Top](#iOSDeviceFingerprintGenerator)

</div>



