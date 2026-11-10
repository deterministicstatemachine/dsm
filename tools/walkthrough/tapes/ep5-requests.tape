# Episode 5: ask the wallet for things. Inside the grant, over the cap,
# what it owns, a sign-in, an item issued and given, and a disconnect. Facts, not answers, are the evidence.
Output docs/walkthrough/clips/ep5-requests.mp4
Source tools/walkthrough/tapes/_settings.tape

Type `S=$(make -s app ARGS=connections | awk -v w="$(make -s wallet ARGS=id)" '$4==w && $NF=="CONNECTED"{print $2}')`
Enter
Wait
Sleep 2s
Type `make app ARGS="send $S ERA 0.05"`
Enter
Wait
Sleep 2s
Hide
Type "sleep 4"
Enter
Wait
Show
Type `make app ARGS="result $S 1"`
Enter
Wait
Sleep 5s
Type `make app ARGS="send $S ERA 0.20"`
Enter
Wait
Sleep 2s
Hide
Type "sleep 4"
Enter
Wait
Show
Type "make dev-wallet-pending"
Enter
Wait
Sleep 5s
Type `make wallet ARGS="approve $S 2"`
Enter
Wait
Sleep 3s
Hide
Type "sleep 4"
Enter
Wait
Show
Type `make app ARGS="result $S 2"`
Enter
Wait
Sleep 5s
Type `make app ARGS="owns $S ERA"`
Enter
Wait
Hide
Type "sleep 4"
Enter
Wait
Show
Type `make app ARGS="result $S 3"`
Enter
Wait
Sleep 5s
Type `make app ARGS="login $S"`
Enter
Wait
Sleep 2s
Hide
Type "sleep 4"
Enter
Wait
Show
Type "make dev-wallet-pending"
Enter
Wait
Sleep 5s
Type `make wallet ARGS="approve $S 4"`
Enter
Wait
Sleep 3s
Hide
Type "sleep 4"
Enter
Wait
Show
Type `make app ARGS="result $S 4"`
Enter
Wait
Sleep 5s
Type `make app ARGS="issue SHIELD shield 1"`
Enter
Wait
Sleep 4s
Type `make app ARGS="accept $S SHIELD"`
Enter
Wait
Hide
Type "sleep 6"
Enter
Wait
Show
Type `make app ARGS="give $(make -s wallet ARGS=id) SHIELD 1"`
Enter
Wait
Sleep 4s
Type "make wallet ARGS=owned"
Enter
Wait
Sleep 5s
Type `make wallet ARGS="disconnect $S"`
Enter
Wait
Sleep 4s
