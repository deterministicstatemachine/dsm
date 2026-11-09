# Episode 5: ask the wallet for things. Inside the grant, over the cap,
# holdings, and a disconnect. Facts, not answers, are the evidence.
Output ep5-requests.mp4
Source tools/walkthrough/tapes/_settings.tape

Type `S=$(make -s app ARGS=sessions | awk '$NF=="CONNECTED"{print $2}' | tail -1)`
Enter
Sleep 2s
Type `make app ARGS="pay $S ERA 5"`
Enter
Sleep 2s
Hide
Type "sleep 4"
Enter
Show
Type `make app ARGS="status $S 1"`
Enter
Sleep 5s
Type `make app ARGS="pay $S ERA 20"`
Enter
Sleep 2s
Hide
Type "sleep 4"
Enter
Show
Type "make dev-wallet-pending"
Enter
Sleep 5s
Type `make wallet ARGS="approve $S 2"`
Enter
Sleep 3s
Hide
Type "sleep 4"
Enter
Show
Type `make app ARGS="status $S 2"`
Enter
Sleep 5s
Type `make app ARGS="holdings $S ERA"`
Enter
Hide
Type "sleep 4"
Enter
Show
Type `make app ARGS="status $S 3"`
Enter
Sleep 5s
Type `make wallet ARGS="disconnect $S"`
Enter
Sleep 4s
