#!/bin/bash
# Modify build.gradle.kts to include Nordic BLE
sed -i '' '/implementation("androidx.work:work-runtime-ktx:2.9.0")/a\
    implementation("no.nordicsemi.android:ble:2.7.1")\
    implementation("no.nordicsemi.android:ble-ktx:2.7.1")' dsm_client/android/app/build.gradle.kts

# Apply GATT 133 error handling in GattServerHost.kt (stub sed, replace later)
