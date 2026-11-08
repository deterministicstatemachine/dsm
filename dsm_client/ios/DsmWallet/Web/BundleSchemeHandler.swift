// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import WebKit

/// Serves the packaged React build (`www/` in the app bundle) under the
/// app's origin, `dsm-app://wallet/assets/…`, as Android's `WebViewAssetLoader`
/// serves it under its own. Only files inside `www/` are served; a path that
/// escapes it, or names no file, is answered 404 and nothing else.
final class BundleSchemeHandler: NSObject, WKURLSchemeHandler {
    private let wwwRoot: URL

    init(wwwRoot: URL) {
        self.wwwRoot = wwwRoot.standardizedFileURL
    }

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        guard let url = task.request.url else {
            task.didFailWithError(URLError(.badURL))
            return
        }
        guard WebNavigationPolicy.decide(url) == .app else {
            respond(task, url: url, status: 404, body: Data(), type: "text/plain")
            return
        }
        let relative = String(url.path.dropFirst(WebNavigationPolicy.appPathPrefix.count))
        let file = wwwRoot.appendingPathComponent(relative).standardizedFileURL
        // The file must stay under www/: `..` segments are resolved by
        // standardizing, and a result outside the root is not the app's.
        guard file.path.hasPrefix(wwwRoot.path + "/") else {
            DsmLog.warn("BundleSchemeHandler", "a request escaped www/: \(relative)")
            respond(task, url: url, status: 404, body: Data(), type: "text/plain")
            return
        }
        let body: Data
        do {
            body = try Data(contentsOf: file)
        } catch {
            // The bundle holds no such file: a 404, as the asset loader answers.
            DsmLog.info("BundleSchemeHandler", "\(relative) is not in the bundle: \(error)")
            respond(task, url: url, status: 404, body: Data(), type: "text/plain")
            return
        }
        respond(task, url: url, status: 200, body: body, type: mimeType(for: file.pathExtension))
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {
        // Every response is delivered whole in `start`; nothing is in flight to stop.
    }

    private func respond(_ task: WKURLSchemeTask, url: URL, status: Int, body: Data, type: String) {
        let headers = [
            "Content-Type": type,
            "Content-Length": String(body.count),
            "Cache-Control": "no-store",
        ]
        guard let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers) else {
            task.didFailWithError(URLError(.cannotParseResponse))
            return
        }
        task.didReceive(response)
        task.didReceive(body)
        task.didFinish()
    }

    private func mimeType(for ext: String) -> String {
        switch ext.lowercased() {
        case "html": return "text/html; charset=utf-8"
        case "js", "mjs": return "application/javascript; charset=utf-8"
        case "css": return "text/css; charset=utf-8"
        case "json": return "application/json"
        case "wasm": return "application/wasm"
        case "svg": return "image/svg+xml"
        case "png": return "image/png"
        case "jpg", "jpeg": return "image/jpeg"
        case "webp": return "image/webp"
        case "gif": return "image/gif"
        case "ico": return "image/x-icon"
        case "woff": return "font/woff"
        case "woff2": return "font/woff2"
        case "ttf": return "font/ttf"
        case "otf": return "font/otf"
        case "mp3": return "audio/mpeg"
        case "wav": return "audio/wav"
        case "ogg": return "audio/ogg"
        case "toml", "txt", "crt", "map": return "text/plain; charset=utf-8"
        default: return "application/octet-stream"
        }
    }
}
