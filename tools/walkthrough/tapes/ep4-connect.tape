# Episode 4: make an offer, connect a wallet (here the terminal wallet; the
# phones' half of the episode is recorded from scrcpy and the iOS Simulator).
Output ep4-connect.mp4
Source tools/walkthrough/tapes/_settings.tape

Type "make dev-wallet"
Enter
Sleep 30s
Type `CODE=$(make -s app ARGS="offer 'My Game' ERA 10 100")`
Enter
Sleep 3s
Type "echo $CODE"
Enter
Sleep 3s
Type `make dev-wallet-connect CODE="$CODE"`
Enter
Sleep 5s
Hide
Type "sleep 3"
Enter
Show
Type "make app ARGS=sessions"
Enter
Sleep 4s
