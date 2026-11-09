# Episode 5: ask the wallet for things. Inside the grant, over the cap,
# what it owns, a sign-in, an item issued and given, and a disconnect. Facts, not answers, are the evidence.
Output ep5-requests.mp4
Source tools/walkthrough/tapes/_settings.tape

Type `S=$(make -s app ARGS=connections | awk '$NF=="CONNECTED"{print $2}' | tail -1)`
Enter
Sleep 2s
Type `make app ARGS="send $S ERA 0.05"`
Enter
Sleep 2s
Hide
Type "sleep 4"
Enter
Show
Type `make app ARGS="result $S 1"`
Enter
Sleep 5s
Type `make app ARGS="send $S ERA 0.20"`
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
Type `make app ARGS="result $S 2"`
Enter
Sleep 5s
Type `make app ARGS="owns $S ERA"`
Enter
Hide
Type "sleep 4"
Enter
Show
Type `make app ARGS="result $S 3"`
Enter
Sleep 5s
Type `make app ARGS="login $S"`
Enter
Sleep 2s
Hide
Type "sleep 4"
Enter
Show
Type "make dev-wallet-pending"
Enter
Sleep 5s
Type `make wallet ARGS="approve $S 4"`
Enter
Sleep 3s
Hide
Type "sleep 4"
Enter
Show
Type `make app ARGS="result $S 4"`
Enter
Sleep 5s
Type `make app ARGS="issue SHIELD shield 1"`
Enter
Sleep 8s
Type `make app ARGS="accept $S SHIELD"`
Enter
Hide
Type "sleep 6"
Enter
Show
Type `make app ARGS="give $(make -s wallet ARGS=id) SHIELD 1"`
Enter
Sleep 8s
Type "make wallet ARGS=owned"
Enter
Sleep 5s
Type `make wallet ARGS="disconnect $S"`
Enter
Sleep 4s
