// SPDX-License-Identifier: MIT OR Apache-2.0

import Contacts
import ContactsUI
import Foundation

/// The one phone contact the user picks to link to a DSM contact (DSM
/// Amendment A17): its name, first phone number, first email and identifier,
/// handed to the page as a `ContactProfileV1` the Rust codec frames. Nothing
/// else of the phonebook is read, and nothing is stored here. The photo is
/// read on demand by identifier, for display only.
final class PhoneContacts: NSObject, CNContactPickerDelegate {
    private static let maxName = 64
    private static let maxEmail = 254
    private static let maxPhone = 32
    private static let maxPhotoBytes = 256 * 1024

    private let picked: (Data) -> Void

    init(picked: @escaping (Data) -> Void) {
        self.picked = picked
    }

    /// Opens the system picker; the picked contact's event, or the event
    /// carrying no bytes when the user picked none, reaches `picked`.
    func present(from controller: UIViewController) {
        let picker = CNContactPickerViewController()
        picker.delegate = self
        controller.present(picker, animated: controller.isViewLoaded)
    }

    func contactPickerDidCancel(_ picker: CNContactPickerViewController) {
        picked(DsmSdk.phoneContactPickedEvent(displayName: nil, email: nil, phone: nil, lookupKey: nil))
    }

    func contactPicker(_ picker: CNContactPickerViewController, didSelect contact: CNContact) {
        let name = String(CNContactFormatter.string(from: contact, style: .fullName)?.prefix(PhoneContacts.maxName) ?? "")
        let email = contact.emailAddresses.first.map { String($0.value) }?.trimmingCharacters(in: .whitespaces) ?? ""
        let phoneRaw = contact.phoneNumbers.first?.value.stringValue ?? ""
        let phone = String(phoneRaw.filter { $0.isNumber || "+ -().".contains($0) }.prefix(PhoneContacts.maxPhone))
        picked(DsmSdk.phoneContactPickedEvent(
            displayName: name,
            email: email.count <= PhoneContacts.maxEmail ? email : "",
            phone: phone,
            lookupKey: contact.identifier
        ))
    }

    /// The linked contact's thumbnail, JPEG or PNG as the phone stores it;
    /// no bytes when the contact has none, is gone, or the read is not
    /// allowed.
    static func photo(identifier: String) -> Data {
        guard !identifier.isEmpty, CNContactStore.authorizationStatus(for: .contacts) == .authorized else {
            return Data()
        }
        let store = CNContactStore()
        let keys = [CNContactThumbnailImageDataKey as CNKeyDescriptor]
        do {
            let contact = try store.unifiedContact(withIdentifier: identifier, keysToFetch: keys)
            guard let bytes = contact.thumbnailImageData, bytes.count <= maxPhotoBytes else { return Data() }
            return bytes
        } catch {
            // The contact is gone, or the read was not allowed: no photo.
            DsmLog.info("PhoneContacts", "no photo for the linked contact: \(error)")
            return Data()
        }
    }
}
