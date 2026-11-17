import Foundation

/// What the privileged helper does, over XPC. Every call answers with an error message or nil.
/// The helper never takes paths or user ids from the caller: it reads the caller's uid from the
/// connection and finds SparemacAgent inside its own app bundle.
@objc public protocol HelperProtocol {
    func version(reply: @escaping (String) -> Void)
    /// Creates a Standard agent account with its own group and no Setup Assistant.
    func createAccount(_ name: String, fullName: String, password: String, reply: @escaping (String?) -> Void)
    /// Signs an agent account out and removes its home folder and group. The app deletes the account
    /// record itself, because macOS lets only an app the user can answer delete a user.
    func deleteAccount(_ name: String, reply: @escaping (String?) -> Void)
    func signOut(_ name: String, reply: @escaping (String?) -> Void)
    /// Removes what's left of a deleted session's home folder. macOS protects a home's folders until its
    /// account is gone, so this runs after the app deletes the record; only for a folder whose owner no
    /// longer exists.
    func removeLeftoverHome(_ name: String, reply: @escaping (String?) -> Void)
    /// Copies SparemacAgent into place and starts it in signed-in agent accounts.
    func installAgent(reply: @escaping (String?) -> Void)
    /// Writes the owner's trackpad, mouse and keyboard settings (a property list made by InputSettings)
    /// into an agent account, so signing it in doesn't apply factory defaults to the shared devices.
    func applyInputSettings(_ name: String, settings: Data, reply: @escaping (String?) -> Void)
    /// Whether Screen Sharing is loaded now.
    func screenSharingState(reply: @escaping (Bool) -> Void)
    /// On: allowed only from this Mac (pf), then started. Off: stopped from the command line, which keeps
    /// the permission System Settings gave it (switching it off there removes it).
    func setScreenSharing(_ on: Bool, reply: @escaping (String?) -> Void)
    /// Replaces this helper with the one inside the calling app (checked to be signed by Sparemac)
    /// and restarts, so app updates need no new password.
    func updateHelper(reply: @escaping (String?) -> Void)
    /// Removes every agent account and everything the helper installed.
    func uninstall(reply: @escaping (String?) -> Void)
}
