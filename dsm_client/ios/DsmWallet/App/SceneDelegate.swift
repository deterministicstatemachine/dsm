// SPDX-License-Identifier: MIT OR Apache-2.0

import UIKit

/// The one window and its screen; the lifecycle transitions the screen
/// relays to Rust as hardware facts; and the connect links that open the
/// wallet (DSM Amendment A11), with the app the system names as sender.
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var wallet: WalletViewController?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        let wallet = WalletViewController()
        window.rootViewController = wallet
        window.makeKeyAndVisible()
        self.window = window
        self.wallet = wallet
        takeConnectLinks(connectionOptions.urlContexts)
    }

    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        takeConnectLinks(URLContexts)
    }

    /// The links that opened the wallet, each with the bundle id the system
    /// recorded as the opener (none when it recorded none): the opener's own
    /// words about itself are not consulted.
    private func takeConnectLinks(_ contexts: Set<UIOpenURLContext>) {
        for context in contexts {
            wallet?.takeConnectLink(context.url, sender: context.options.sourceApplication)
        }
    }

    func sceneDidBecomeActive(_ scene: UIScene) {
        wallet?.sceneDidBecomeActive(scene)
    }

    func sceneWillResignActive(_ scene: UIScene) {
        wallet?.sceneWillResignActive(scene)
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        wallet?.sceneDidEnterBackground()
    }
}
