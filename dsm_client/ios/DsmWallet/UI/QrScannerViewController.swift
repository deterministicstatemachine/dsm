// SPDX-License-Identifier: MIT OR Apache-2.0

import AVFoundation
import UIKit

/// The native QR scanner the page opens by its one link: the camera's QR
/// codes through `AVCaptureMetadataOutput`, the first one read handed back
/// as text, a cancelled scan handed back as none. No third-party decoder.
final class QrScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "com.dsm.wallet.qr-session")
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var finished: ((String?) -> Void)?
    private enum Outcome { case pending, delivered }
    private var outcome = Outcome.pending

    init(finished: @escaping (String?) -> Void) {
        self.finished = finished
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .fullScreen
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        let cancel = UIButton(type: .system)
        cancel.setTitle("Cancel", for: .normal)
        cancel.setTitleColor(.white, for: .normal)
        cancel.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)
        cancel.sizeToFit()
        view.addSubview(cancel)
        cancelButton = cancel
    }

    /// The camera is asked for once the scanner is on screen: a scan that ends
    /// here can dismiss it. From `viewDidLoad` the presentation is still under
    /// way, so the dismissal is dropped and the result already spent: a black
    /// screen whose Cancel does nothing (2026-11-04, the simulator).
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard cameraStep == .notAsked else { return }
        cameraStep = .asked
        configureCamera()
    }

    private enum CameraStep { case notAsked, asked }
    private var cameraStep = CameraStep.notAsked
    private var cancelButton: UIButton?

    private func configureCamera() {
        guard let camera = AVCaptureDevice.default(for: .video) else {
            DsmLog.warn("QrScanner", "this device has no camera; the scan is cancelled")
            finish(nil)
            return
        }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            start(camera)
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted { self?.start(camera) } else { self?.finish(nil) }
                }
            }
        default:
            DsmLog.warn("QrScanner", "the camera is not allowed; offering Settings")
            offerCameraSettings()
        }
    }

    /// The camera was refused earlier, and iOS will not ask again: only
    /// Settings can allow it now, so say so and go there on request.
    private func offerCameraSettings() {
        let alert = UIAlertController(title: "Camera access is off",
                                      message: "To scan a code, allow the camera for DSM in Settings. You can also enter the code by hand.",
                                      preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Not now", style: .cancel) { [weak self] _ in
            self?.finish(nil)
        })
        alert.addAction(UIAlertAction(title: "Open Settings", style: .default) { [weak self] _ in
            if let settings = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(settings)
            }
            self?.finish(nil)
        })
        present(alert, animated: isViewLoaded)
    }

    private func start(_ camera: AVCaptureDevice) {
        do {
            let input = try AVCaptureDeviceInput(device: camera)
            guard session.canAddInput(input) else { throw AVError(.deviceNotConnected) }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { throw AVError(.deviceNotConnected) }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            guard output.availableMetadataObjectTypes.contains(.qr) else { throw AVError(.deviceNotConnected) }
            output.metadataObjectTypes = [.qr]
        } catch {
            DsmLog.error("QrScanner", "the camera session was not configured: \(error)")
            finish(nil)
            return
        }
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.insertSublayer(preview, at: 0)
        previewLayer = preview
        sessionQueue.async { [session] in session.startRunning() }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
        // The cancel button sits under the status bar, at the leading edge.
        let insets = view.safeAreaInsets
        cancelButton?.frame.origin = CGPoint(x: insets.left + 16, y: insets.top + 12)
        if let cancelButton { view.bringSubviewToFront(cancelButton) }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard let code = metadataObjects.compactMap({ $0 as? AVMetadataMachineReadableCodeObject }).first,
              code.type == .qr, let text = code.stringValue, !text.isEmpty else { return }
        finish(text)
    }

    @objc private func cancelTapped() {
        finish(nil)
    }

    /// Hands the result over once; later reads are not results.
    private func finish(_ text: String?) {
        guard outcome == .pending else { return }
        outcome = .delivered
        sessionQueue.async { [session] in
            if session.isRunning { session.stopRunning() }
        }
        let callback = finished
        finished = nil
        if presentingViewController != nil {
            dismiss(animated: isViewLoaded) { callback?(text) }
        } else {
            callback?(text)
        }
    }
}
