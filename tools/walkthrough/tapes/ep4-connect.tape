# Episode 4: make an offer, connect a wallet (here the terminal wallet; the
# phones' half of the episode is recorded from scrcpy and the iOS Simulator).
Output docs/walkthrough/clips/ep4-connect.mp4
Source tools/walkthrough/tapes/_settings.tape

Type "make dev-wallet"
Enter
Wait
Sleep 3s
Type `CODE=$(make -s app ARGS="offer 'My Game' ERA 0.10 1.00")`
Enter
Wait
Sleep 2s
Type "echo $CODE"
Enter
Wait
Sleep 3s
Type `make dev-wallet-connect CODE="$CODE"`
Enter
Wait
Sleep 3s
Hide
Type "sleep 3"
Enter
Wait
Show
Type "make app ARGS=connections"
Enter
Wait
Sleep 5s
