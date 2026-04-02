package com.dsm.wallet.security

import org.junit.Assert.assertEquals
import org.junit.Test

class AccessLevelTest {

    @Test
    fun minOf_returnsLowerOrdinal_lessRestrictiveFirstInEnum() {
        // Enum order: FULL_ACCESS, PIN_REQUIRED, READ_ONLY, BLOCKED — minOf picks smaller ordinal.
        assertEquals(AccessLevel.FULL_ACCESS, AccessLevel.minOf(AccessLevel.FULL_ACCESS, AccessLevel.READ_ONLY))
        assertEquals(AccessLevel.READ_ONLY, AccessLevel.minOf(AccessLevel.READ_ONLY, AccessLevel.BLOCKED))
        assertEquals(AccessLevel.FULL_ACCESS, AccessLevel.minOf(AccessLevel.PIN_REQUIRED, AccessLevel.FULL_ACCESS))
    }

    @Test
    fun minOf_same_returnsSame() {
        assertEquals(AccessLevel.FULL_ACCESS, AccessLevel.minOf(AccessLevel.FULL_ACCESS, AccessLevel.FULL_ACCESS))
    }

    @Test
    fun ordinal_ordering_matches_declaration_order() {
        assert(AccessLevel.FULL_ACCESS.ordinal < AccessLevel.PIN_REQUIRED.ordinal)
        assert(AccessLevel.PIN_REQUIRED.ordinal < AccessLevel.READ_ONLY.ordinal)
        assert(AccessLevel.READ_ONLY.ordinal < AccessLevel.BLOCKED.ordinal)
    }
}
