// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.ui

import android.content.ContentResolver
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.ContactsContract
import androidx.core.content.ContextCompat
import dsm.types.proto.ContactProfileV1

/**
 * The one phone contact the user picked to link to a DSM contact (DSM
 * Amendment A17): its name, first phone number, first email and lookup key,
 * as a ContactProfileV1. Nothing else of the phonebook is read, and nothing
 * is stored here: the page keeps what the user chose to keep through the
 * SDK. The photo is read on demand by lookup key, for display only.
 */
internal object PhoneContacts {
    private const val MAX_NAME = 64
    private const val MAX_EMAIL = 254
    private const val MAX_PHONE = 32
    private const val MAX_PHOTO_BYTES = 256 * 1024

    fun readAllowed(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, android.Manifest.permission.READ_CONTACTS) ==
            PackageManager.PERMISSION_GRANTED

    /** The picked contact as a ContactProfileV1's bytes; no bytes when it cannot be read. */
    fun read(resolver: ContentResolver, contactUri: Uri): ByteArray {
        val projection = arrayOf(
            ContactsContract.Contacts._ID,
            ContactsContract.Contacts.DISPLAY_NAME_PRIMARY,
            ContactsContract.Contacts.LOOKUP_KEY,
        )
        val (id, name, lookupKey) = resolver.query(contactUri, projection, null, null, null)?.use { c ->
            if (!c.moveToFirst()) return ByteArray(0)
            Triple(c.getLong(0), c.getString(1).orEmpty(), c.getString(2).orEmpty())
        } ?: return ByteArray(0)
        val phone = firstOf(
            resolver,
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            ContactsContract.CommonDataKinds.Phone.NUMBER,
            ContactsContract.CommonDataKinds.Phone.CONTACT_ID,
            id,
        )
        val email = firstOf(
            resolver,
            ContactsContract.CommonDataKinds.Email.CONTENT_URI,
            ContactsContract.CommonDataKinds.Email.ADDRESS,
            ContactsContract.CommonDataKinds.Email.CONTACT_ID,
            id,
        )
        return ContactProfileV1.newBuilder()
            .setDisplayName(name.take(MAX_NAME))
            .setEmail(if (email.length <= MAX_EMAIL) email else "")
            .setPhone(phone.filter { it.isDigit() || it in "+ -()." }.take(MAX_PHONE))
            .setPhoneLookupKey(lookupKey)
            .build()
            .toByteArray()
    }

    /** The first value of `column` among the contact's rows of one data kind, or "" when it has none. */
    private fun firstOf(resolver: ContentResolver, table: Uri, column: String, contactIdColumn: String, id: Long): String =
        resolver.query(table, arrayOf(column), "$contactIdColumn = ?", arrayOf(id.toString()), null)?.use { c ->
            if (c.moveToFirst()) c.getString(0).orEmpty().trim() else ""
        } ?: ""

    /**
     * The linked contact's photo thumbnail, JPEG or PNG as the phone stores
     * it; no bytes when the contact has none, is gone, or the read is not
     * allowed.
     */
    fun photo(context: Context, lookupKey: String): ByteArray {
        if (lookupKey.isEmpty() || !readAllowed(context)) return ByteArray(0)
        val resolver = context.contentResolver
        val lookupUri = Uri.withAppendedPath(ContactsContract.Contacts.CONTENT_LOOKUP_URI, lookupKey)
        val contactUri = ContactsContract.Contacts.lookupContact(resolver, lookupUri) ?: return ByteArray(0)
        val stream = ContactsContract.Contacts.openContactPhotoInputStream(resolver, contactUri) ?: return ByteArray(0)
        return stream.use { s ->
            val bytes = s.readBytes()
            if (bytes.size <= MAX_PHOTO_BYTES) bytes else ByteArray(0)
        }
    }
}
