//
//  FingerprintInfo.swift
//  iOSDeviceFingerprintGenerator

import Foundation

/// A value type that encapsulates the full result of a device fingerprint evaluation.
///
/// `FingerprintInfo` groups three main aspects:
/// - A stable, hashed `deviceID` used to identify the device across app launches.
/// - Raw `hardwareSignals` describing the physical and system characteristics of the device.
/// - Raw `behaviourSignals` describing locale, network, and user-preference related context.
/// - A normalized `riskConfidenceLevel` indicating how suspicious the current environment is.
///
/// The struct is typically produced by ``iOSDeviceFingerprintGenerator`` with ``iOSDeviceFingerprintGenerator/generateDeviceFingerprint()`` method.
/// and is intended to be consumed by higher-level security, fraud detection, or analytics
/// components.
///
/// Usage recommendations:
/// - Treat `deviceID` as an opaque identifier; do not attempt to reverse or interpret it.
/// - Use `hardwareSignals` and `behaviourSignals` for debugging, audit logs, or feature flags,
///   not as primary keys.
/// - Use `riskConfidenceLevel` as an input to your own risk engine (e.g. thresholds, step‑up auth).
public struct FingerprintInfo {
    /// Stable, hashed identifier for this device fingerprint.
    ///
    /// This value is derived from a SHA‑256 hash over a deterministic combination
    /// of hardware and behavioral signals. It is:
    /// - Stable across app launches on the same device (while the Keychain entry exists).
    /// - Different across devices and significantly different environments.
    /// - Safe to store on your backend as a device identifier.
    public let deviceID: String
    
    /// Collection of hardware‑related signals captured at the time of fingerprint generation.
    ///
    /// Typical keys include (but are not limited to):
    /// - `"model"`: Low‑level device model identifier (e.g. `"iPhone14,5"`).
    /// - `"systemVersion"`: iOS version string.
    /// - `"screenResolution"`: Physical screen resolution in pixels (e.g. `"1170x2532"`).
    /// - `"totalDiskSpace"` / `"availableDiskSpace"`: Disk sizes in bytes.
    /// - `"batteryLevel"` / `"batteryState"`: Battery status information.
    /// - `"processorCount"`, `"physicalMemory"`, `"systemUptime"`, `"thermalState"`,
    ///   `"lowPowerModeEnabled"`.
    ///
    /// Values are intentionally typed as `Any` to allow heterogeneous signal types
    /// (e.g. `String`, `Int`, `Bool`, `Double`).
    public let hardwareSignals: [String: Any]
    
    /// Collection of behavior‑ and context‑related signals captured at the time of fingerprint generation.
    ///
    /// Typical keys include (but are not limited to):
    /// - `"timezone"`: Current system time zone identifier.
    /// - `"locale"`: Current locale identifier.
    /// - `"preferredLanguages"`: List of preferred language identifiers.
    /// - `"calendar"`: Current calendar identifier.
    /// - `"keyboardLanguages"`: Active keyboard language identifiers.
    /// - `"isAdvertisingTrackingEnabled"`: Whether advertising tracking is authorized.
    /// - `"vendorID"`: The app vendor identifier (if available).
    /// - `"networkType"`: Current network type snapshot (e.g. `"WiFi"`, `"Cellular"`).
    /// - `"vpnConnected"` / `"proxyConfigured"`: Network environment flags.
    ///
    /// As with `hardwareSignals`, values are stored as `Any` to support mixed types.
    public let behaviourSignals: [String: Any]
    
    /// Normalized risk score in the range `0.0...1.0` describing how suspicious the environment appears.
    ///
    /// Higher values indicate a higher confidence that the current device or environment
    /// might be risky (e.g. emulator, VPN, proxy usage). The exact weighting is defined
    /// by the generator implementation but generally follows:
    /// - `0.0`: Low/normal risk.
    /// - `0.5`: Medium risk (some suspicious signals present).
    /// - `1.0`: High risk (multiple strong indicators, such as VPN + proxy + emulator).
    ///
    /// This value is designed to be consumed by your own risk or fraud‑detection logic,
    /// for example to trigger step‑up authentication or additional validation.
    public let riskConfidenceLevel: Float
}
