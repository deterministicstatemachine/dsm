#!/bin/bash
# Adding a stub to Kotlin for handling the GATT 133 explicitly and delay 1.5s
sed -i '' '/is BleSessionEvent.ErrorOccurred -> {/a\
                        if (event.status == 133) {\
                            Log.w("BleCoordinator", "GATT 133 observed. Scheduling delay recovery...")\
                            kotlinx.coroutines.GlobalScope.launch {\
                                kotlinx.coroutines.delay(1500)\
                                getOrCreateSession(event.deviceAddress).connect()\
                            }\
                        }\
' dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleCoordinator.kt
