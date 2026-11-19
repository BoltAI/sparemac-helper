import Foundation

/// A saved setup for a session's screen, for clean screenshots and recordings: appearance, wallpaper, the Dock
/// around the app being shown, a clean desktop, no notifications, and that app's window in the middle. The
/// Sparemac app keeps them (Settings › Screen Setups); AI agents apply one with sparemac_preset and put it back after.
public struct Preset: Codable, Identifiable, Equatable, Sendable {
    public var id: String
    public var name: String
    /// "light", "dark", or "" to leave it as it is.
    public var appearance: String
    /// An image's full path, or "" to leave the wallpaper as it is. Sessions can't read your files, so images you
    /// choose are copied to `Preset.imagesFolder`.
    public var wallpaper: String
    /// The apps in the Dock after Finder, in order; `Preset.featuredApp` marks where the app being shown goes. Empty leaves the Dock as it is.
    public var dockApps: [String]
    /// No desktop icons or widgets.
    public var cleanDesktop: Bool
    /// Banners closed and Do Not Disturb on (macOS then shows its moon in the menu bar).
    public var quiet: Bool
    /// The featured app's window in the middle of the screen (its Window › Center).
    public var centerWindow: Bool
    /// Recordings zoom in on what the agent clicks and types: "auto" (fits the element), or "1.5", "2", "3";
    /// nil for none.
    public var zoom: String?

    public init(id: String = UUID().uuidString.lowercased(), name: String, appearance: String = "", wallpaper: String = "",
                dockApps: [String] = ["Mail", "Safari", "Notes"], cleanDesktop: Bool = true, quiet: Bool = true, centerWindow: Bool = true, zoom: String? = nil) {
        self.id = id; self.name = name; self.appearance = appearance; self.wallpaper = wallpaper
        self.dockApps = dockApps; self.cleanDesktop = cleanDesktop; self.quiet = quiet; self.centerWindow = centerWindow
        self.zoom = zoom
    }

    /// Stands in the Dock list for the app an AI agent shows, where the person put it; a preset may leave it out.
    public static let featuredApp = "{app}"

    /// The Dock's apps after Finder, in the person's order, with the app being shown in its place when the preset
    /// has one (and dropped without an app).
    public func dock(featuring app: String?) -> [String] {
        var seen = Set<String>()
        return dockApps.compactMap { $0 == Preset.featuredApp ? app : $0 }
            .filter { $0.caseInsensitiveCompare("Finder") != .orderedSame && seen.insert($0.lowercased()).inserted }
    }

    /// The two shortcuts that turn Do Not Disturb on and off in a session (macOS keeps Focus to Apple's own
    /// callers and Shortcuts). Sparemac adds them to a session the first time a preset needs them.
    public static let quietOn = "Sparemac Quiet On", quietOff = "Sparemac Quiet Off"
    /// Wallpapers people choose, where every session can read them (Sparemac's own folder there belongs to root).
    public static let imagesFolder = "/Users/Shared/Sparemac Presets"
}
