import Foundation

/// The owner's trackpad, mouse and keyboard settings. The pointer and keyboard are shared by every
/// signed-in account, and macOS applies the settings of an account as it signs in, so an agent
/// account with factory defaults would switch off the owner's secondary click, change their mouse
/// speed or scrolling direction. Sparemac copies these into the agent account before each sign-in.
public enum InputSettings {
    /// Whole preference domains copied as they are.
    public static let domains = [
        "com.apple.AppleMultitouchTrackpad", "com.apple.driver.AppleBluetoothMultitouch.trackpad",
        "com.apple.AppleMultitouchMouse", "com.apple.driver.AppleBluetoothMultitouch.mouse",
    ]
    /// Global keys (any host and this host) copied when their name starts with one of these.
    public static let globalPrefixes = [
        "com.apple.mouse.", "com.apple.trackpad.", "com.apple.scrollwheel.", "com.apple.swipescrolldirection",
        "com.apple.keyboard.", "KeyRepeat", "InitialKeyRepeat", "ApplePressAndHoldEnabled",
    ]

    public static func allowedGlobal(_ key: String) -> Bool { globalPrefixes.contains { key.hasPrefix($0) } }

    /// Only simple values are copied (numbers, booleans, strings).
    static func simple(_ dict: [String: Any]) -> [String: Any] {
        dict.filter { $0.value is NSNumber || $0.value is String }
    }

    /// Whether two settings property lists hold the same values (their bytes can differ in key order).
    public static func same(_ a: Data, _ b: Data?) -> Bool {
        guard let b, let x = try? PropertyListSerialization.propertyList(from: a, format: nil) as? NSDictionary,
              let y = try? PropertyListSerialization.propertyList(from: b, format: nil) as? NSDictionary else { return false }
        return x.isEqual(y)
    }

    /// The current user's settings, as a property list: {domains, global, globalHost}.
    public static func current() -> Data? {
        var domainValues: [String: Any] = [:]
        for domain in domains {
            let values = CFPreferencesCopyMultiple(nil, domain as CFString, kCFPreferencesCurrentUser, kCFPreferencesAnyHost) as? [String: Any] ?? [:]
            let simpleValues = simple(values)
            if !simpleValues.isEmpty { domainValues[domain] = simpleValues }
        }
        func globals(_ host: CFString) -> [String: Any] {
            let all = CFPreferencesCopyMultiple(nil, kCFPreferencesAnyApplication, kCFPreferencesCurrentUser, host) as? [String: Any] ?? [:]
            return simple(all.filter { allowedGlobal($0.key) })
        }
        let plist: [String: Any] = ["domains": domainValues, "global": globals(kCFPreferencesAnyHost), "globalHost": globals(kCFPreferencesCurrentHost)]
        return try? PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0)
    }
}
