// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import WebKit

/// The wallet's web view: the packaged page at the app's own origin, the
/// bridge object installed before the page's first script, and the one
/// message channel the page's requests and the host's events cross.
final class WalletWebView: WKWebView {
    private let messages: BridgeMessageHandler

    /// `wwwRoot` is the packaged React build; `bootstrap` the bridge script
    /// (`bridge_bootstrap.js`) installed at document start in every frame the
    /// navigation policy admits (the page allows itself no subframes).
    init(wwwRoot: URL, bootstrap: String) {
        let configuration = WKWebViewConfiguration()
        configuration.setURLSchemeHandler(BundleSchemeHandler(wwwRoot: wwwRoot), forURLScheme: WebNavigationPolicy.appScheme)
        configuration.websiteDataStore = .default()
        let messages = BridgeMessageHandler()
        self.messages = messages
        configuration.userContentController.addScriptMessageHandler(messages, contentWorld: .page, name: "dsm")
        configuration.userContentController.addUserScript(
            WKUserScript(source: bootstrap, injectionTime: .atDocumentStart, forMainFrameOnly: false)
        )
        super.init(frame: .zero, configuration: configuration)
        backgroundColor = .black
        scrollView.backgroundColor = .black
        scrollView.contentInsetAdjustmentBehavior = .never
    }

    required init?(coder: NSCoder) {
        nil
    }

    /// Hands one event to the page. Answers whether the page can take events
    /// now (the handler's call is queued on the page's thread); a page that
    /// is gone answers no, and the relay keeps the event.
    func deliver(_ event: EventRelay.Event) -> Bool {
        let script: String
        switch event {
        case .topic(let topic, let payload):
            guard let safeTopic = WalletWebView.safeTopic(topic) else {
                DsmLog.warn("WalletWebView", "an event topic has characters no topic may: dropped")
                return isDeliverable
            }
            script = "window.__dsmHostEvent(\"\(safeTopic)\", \"\(Base32Crockford.encode(payload))\")"
        case .nativeHost(let bytes):
            script = "window.__dsmNativeHostEvent(\"\(Base32Crockford.encode(bytes))\")"
        }
        guard isDeliverable else { return isDeliverable }
        DispatchQueue.main.async { [weak self] in
            self?.evaluateJavaScript(script) { _, error in
                if let error { DsmLog.warn("WalletWebView", "the page did not take an event: \(error)") }
            }
        }
        return isDeliverable
    }

    /// The page can take events once it has a window and loaded a document.
    private var isDeliverable: Bool {
        window != nil && url != nil
    }

    /// A topic as `MainActivity.sanitizeEventName` admits one: letters,
    /// digits, dash, dot and underscore. Anything else is no topic.
    static func safeTopic(_ topic: String) -> String? {
        let allowed = topic.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." || $0 == "_" }
        return allowed && !topic.isEmpty ? topic : nil
    }
}

/// The page's requests, as the bootstrap script posts them: a dictionary with
/// `kind` `bin` (one `BridgeRpcRequest`, answered with the `BridgeRpcResponse`)
/// or `rpc` (a method and payload, answered with the success bytes or a
/// rejection carrying the error's message), bytes as Base32 Crockford.
final class BridgeMessageHandler: NSObject, WKScriptMessageHandlerWithReply {
    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage, replyHandler: @escaping (Any?, String?) -> Void) {
        guard let body = message.body as? [String: Any], let kind = body["kind"] as? String else {
            replyHandler(nil, "DSM bridge: a message with no kind")
            return
        }
        switch kind {
        case "bin":
            guard let requestText = body["request"] as? String else {
                replyHandler(nil, "DSM bridge: a bin message with no request")
                return
            }
            let request = Base32Crockford.decode(requestText)
            guard request.count <= 1024 * 1024 else {
                replyHandler(nil, "DSM bridge: request too large: \(request.count) bytes")
                return
            }
            guard let method = DsmSdk.bridgeRequestMethod(request) else {
                let why = DsmSdk.bridgeRequestRefusal(request) ?? "the request does not decode"
                let response = DsmSdk.bridgeError(code: BridgeFailure.invalidPayload(why).code, message: "Invalid bridge request: \(why)")
                replyHandler(Base32Crockford.encode(response), nil)
                return
            }
            let payload = DsmSdk.bridgeRequestPayload(request)
            BridgeDispatcher.shared.dispatch(method: method, payload: payload) { outcome in
                let response: Data
                switch outcome {
                case .success(let data): response = DsmSdk.bridgeSuccess(data)
                case .failure(let failure): response = DsmSdk.bridgeError(code: failure.code, message: failure.description)
                }
                DispatchQueue.main.async { replyHandler(Base32Crockford.encode(response), nil) }
            }
        case "rpc":
            guard let method = body["method"] as? String, let payloadText = body["payload"] as? String else {
                replyHandler(nil, "DSM bridge: an rpc message with no method or payload")
                return
            }
            BridgeDispatcher.shared.dispatch(method: method, payload: Base32Crockford.decode(payloadText)) { outcome in
                DispatchQueue.main.async {
                    switch outcome {
                    case .success(let data): replyHandler(Base32Crockford.encode(data), nil)
                    case .failure(let failure): replyHandler(nil, failure.description)
                    }
                }
            }
        default:
            replyHandler(nil, "DSM bridge: no message kind named \(kind)")
        }
    }
}
