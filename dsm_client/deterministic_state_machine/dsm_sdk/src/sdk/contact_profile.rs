// SPDX-License-Identifier: MIT OR Apache-2.0
//! A person's details as the wallet shows them (DSM Amendment A17): a
//! contact's (what their card shared, or what the owner linked from the
//! phone's contacts or typed) and the owner's own card.
//!
//! Display only. No validity check reads a profile, no step carries one, and
//! nothing here leaves the device except the fields of the owner's card that
//! the owner chose to share, which ride on the contact code. A contact's
//! profile is kept in its row's `metadata` under [`PROFILE_KEY`]; the owner's
//! in the `settings` table under [`OWN_PROFILE_SETTING`], Base32 Crockford of
//! its protobuf bytes.

use prost::Message;

use dsm::types::proto as pb;

use crate::storage::client_db;

/// Where a contact row's metadata holds its profile.
pub const PROFILE_KEY: &str = "profile";
/// Where the settings table holds the owner's own card.
pub const OWN_PROFILE_SETTING: &str = "own_profile";

const MAX_NAME: usize = 64;
const MAX_EMAIL: usize = 254;
const MAX_PHONE: usize = 32;
const MAX_LOOKUP_KEY: usize = 256;

/// Why a profile is refused: a field too long, an email with no `@` between
/// two parts, or a phone with characters a phone number does not have.
pub fn validate(profile: &pb::ContactProfileV1) -> Result<(), String> {
    for (field, value, max) in [
        ("name", &profile.display_name, MAX_NAME),
        ("email", &profile.email, MAX_EMAIL),
        ("phone", &profile.phone, MAX_PHONE),
        (
            "phone contact key",
            &profile.phone_lookup_key,
            MAX_LOOKUP_KEY,
        ),
    ] {
        if value.chars().count() > max {
            return Err(format!("the {field} is longer than {max} characters"));
        }
        if value.chars().any(char::is_control) {
            return Err(format!("the {field} holds a control character"));
        }
    }
    if !profile.email.is_empty() {
        let Some((local, domain)) = profile.email.split_once('@') else {
            return Err("the email has no @".into());
        };
        if local.is_empty() || !domain.contains('.') || domain.contains('@') {
            return Err(format!("{} is not an email address", profile.email));
        }
    }
    if !profile
        .phone
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | ' ' | '-' | '(' | ')' | '.'))
    {
        return Err(format!("{} is not a phone number", profile.phone));
    }
    Ok(())
}

/// A profile with every field trimmed: what is stored and shown.
pub fn trimmed(profile: pb::ContactProfileV1) -> pb::ContactProfileV1 {
    pb::ContactProfileV1 {
        display_name: profile.display_name.trim().to_string(),
        email: profile.email.trim().to_string(),
        phone: profile.phone.trim().to_string(),
        phone_lookup_key: profile.phone_lookup_key.trim().to_string(),
    }
}

/// The profile a contact row holds; `None` when none was set.
pub fn profile_of(
    record: &client_db::ContactRecord,
) -> Result<Option<pb::ContactProfileV1>, String> {
    match record.metadata.get(PROFILE_KEY) {
        Some(bytes) => pb::ContactProfileV1::decode(bytes.as_slice())
            .map(Some)
            .map_err(|e| format!("the contact's stored profile does not decode: {e}")),
        None => Ok(None),
    }
}

/// Replaces a contact's profile and answers the stored one. The contact must
/// already be held: a profile never adds a contact.
pub fn set_contact_profile(
    device_id: &[u8],
    profile: pb::ContactProfileV1,
) -> Result<pb::ContactProfileV1, String> {
    let profile = trimmed(profile);
    validate(&profile)?;
    let mut record = client_db::get_contact_by_device_id(device_id)
        .map_err(|e| format!("the contact was not read: {e}"))?
        .ok_or_else(|| "no contact has that device id".to_string())?;
    record
        .metadata
        .insert(PROFILE_KEY.to_string(), profile.encode_to_vec());
    client_db::store_contact(&record).map_err(|e| format!("the contact was not stored: {e}"))?;
    Ok(profile)
}

/// The owner's own card; `None` until the owner made one.
pub fn own_profile() -> Result<Option<pb::ContactProfileV1>, String> {
    let Some(text) = client_db::get_setting(OWN_PROFILE_SETTING)
        .map_err(|e| format!("the own card was not read: {e}"))?
    else {
        return Ok(None);
    };
    let bytes = crate::util::text_id::decode_base32_crockford(&text)
        .ok_or_else(|| "the stored own card is not Base32 Crockford".to_string())?;
    pb::ContactProfileV1::decode(bytes.as_slice())
        .map(Some)
        .map_err(|e| format!("the stored own card does not decode: {e}"))
}

/// Replaces the owner's own card and answers the stored one. A phone
/// contact's lookup key has no place on it.
pub fn set_own_profile(profile: pb::ContactProfileV1) -> Result<pb::ContactProfileV1, String> {
    let profile = pb::ContactProfileV1 {
        phone_lookup_key: String::new(),
        ..trimmed(profile)
    };
    validate(&profile)?;
    let text = crate::util::text_id::encode_base32_crockford(&profile.encode_to_vec());
    client_db::set_setting(OWN_PROFILE_SETTING, &text)
        .map_err(|e| format!("the own card was not stored: {e}"))?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, email: &str, phone: &str) -> pb::ContactProfileV1 {
        pb::ContactProfileV1 {
            display_name: name.into(),
            email: email.into(),
            phone: phone.into(),
            phone_lookup_key: String::new(),
        }
    }

    #[test]
    fn a_profile_with_a_name_an_email_and_a_phone_is_accepted() {
        assert_eq!(
            validate(&profile(
                "Jane Miller",
                "jane@example.com",
                "+1 (555) 010-2233"
            )),
            Ok(())
        );
        assert_eq!(validate(&profile("", "", "")), Ok(()));
    }

    #[test]
    fn an_email_that_is_not_an_address_is_refused() {
        assert_eq!(
            validate(&profile("Jane", "jane", "")),
            Err("the email has no @".into())
        );
        for email in ["@example.com", "jane@example", "jane@ex@ample.com"] {
            assert_eq!(
                validate(&profile("Jane", email, "")),
                Err(format!("{email} is not an email address")),
            );
        }
    }

    #[test]
    fn a_phone_with_letters_or_an_overlong_name_is_refused() {
        assert_eq!(
            validate(&profile("Jane", "", "555-CALL")),
            Err("555-CALL is not a phone number".into()),
        );
        assert_eq!(
            validate(&profile(&"x".repeat(MAX_NAME + 1), "", "")),
            Err(format!("the name is longer than {MAX_NAME} characters")),
        );
        assert_eq!(
            validate(&profile("Jane\u{7}", "", "")),
            Err("the name holds a control character".into()),
        );
    }

    fn fresh_db() {
        crate::economic_fixtures::use_test_storage_dir();
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");
    }

    /// A contact's details are its row's: set, read back with the contact,
    /// and replaced by the next set. The row's keys and tip are untouched.
    #[test]
    #[serial_test::serial]
    fn a_contacts_details_are_kept_with_its_row_and_replaced_whole() {
        fresh_db();
        let device_id = [0x31u8; 32];
        client_db::store_contact_record_for_tests(device_id, "jm");
        let before = client_db::get_contact_by_device_id(&device_id)
            .expect("read")
            .expect("held");
        assert_eq!(profile_of(&before), Ok(None));

        let first = pb::ContactProfileV1 {
            phone_lookup_key: "0r7-2A".into(),
            ..profile(" Jane Miller ", "jane@example.com", "+1 555 0100")
        };
        let stored = set_contact_profile(&device_id, first).expect("stored");
        assert_eq!(stored.display_name, "Jane Miller");
        let after = client_db::get_contact_by_device_id(&device_id)
            .expect("read")
            .expect("held");
        assert_eq!(profile_of(&after), Ok(Some(stored)));
        assert_eq!(
            (after.public_key, after.current_chain_tip),
            (before.public_key, before.current_chain_tip)
        );

        let replaced = set_contact_profile(&device_id, profile("Jane", "", "")).expect("replaced");
        let read = client_db::get_contact_by_device_id(&device_id)
            .expect("read")
            .expect("held");
        assert_eq!(profile_of(&read), Ok(Some(replaced)));
    }

    /// Details never add a contact, and a refused profile changes nothing.
    #[test]
    #[serial_test::serial]
    fn details_for_no_contact_or_a_bad_email_are_refused() {
        fresh_db();
        assert_eq!(
            set_contact_profile(&[0x32u8; 32], profile("Ann", "", "")),
            Err("no contact has that device id".into()),
        );
        let device_id = [0x33u8; 32];
        client_db::store_contact_record_for_tests(device_id, "ann");
        assert_eq!(
            set_contact_profile(&device_id, profile("Ann", "ann", "")),
            Err("the email has no @".into()),
        );
        let row = client_db::get_contact_by_device_id(&device_id)
            .expect("read")
            .expect("held");
        assert_eq!(profile_of(&row), Ok(None));
    }

    /// The owner's card holds no phone contact's key, and reads back as stored.
    #[test]
    #[serial_test::serial]
    fn the_owners_card_reads_back_without_a_phone_contacts_key() {
        fresh_db();
        assert_eq!(own_profile(), Ok(None));
        let stored = set_own_profile(pb::ContactProfileV1 {
            phone_lookup_key: "0r9-77".into(),
            ..profile("Dana", "dana@example.com", "")
        })
        .expect("stored");
        assert_eq!(stored.phone_lookup_key, "");
        assert_eq!(own_profile(), Ok(Some(stored)));
    }

    #[test]
    fn a_stored_profile_is_trimmed() {
        let t = trimmed(profile("  Jane ", " jane@example.com ", " 555 "));
        assert_eq!(t, profile("Jane", "jane@example.com", "555"));
    }
}
