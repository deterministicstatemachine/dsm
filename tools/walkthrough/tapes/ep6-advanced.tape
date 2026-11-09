# Episode 6 (advanced): a shop of your own (a vault that sells your coin), a
# trade through it, a match your app referees between two wallets, and a
# wallet's contacts. Needs make app-dev and make dev-wallet from the earlier
# episodes; the wallet disconnected at the end of episode 5, so it connects again
# with an offer that carries the trade and match grants.
Output docs/walkthrough/clips/ep6-advanced.mp4
Source tools/walkthrough/tapes/_settings.tape

Type `make app ARGS="issue GOLD 'Starter gold' 1000000 2"`
Enter
Wait
Sleep 4s
Type `make app ARGS="vault GOLD 1000 ERA 10"`
Enter
Wait
Sleep 4s
Type "make app ARGS=vaults"
Enter
Wait
Sleep 4s
Type `CODE=$(make -s app ARGS="offer 'My Game' ERA 0.10 1.00 GOLD")`
Enter
Wait
Type `make dev-wallet-connect CODE="$CODE"`
Enter
Wait
Sleep 5s
Type `S=$(make -s app ARGS=connections | awk '$NF=="CONNECTED"{print $2}' | tail -1)`
Enter
Wait
Type `make app ARGS="price $S ERA GOLD 0.50"`
Enter
Wait
Hide
Type "sleep 4"
Enter
Wait
Show
Type `make app ARGS="result $S 1"`
Enter
Wait
Sleep 5s
Type `make app ARGS="trade $S ERA GOLD 0.50 95"`
Enter
Wait
Sleep 3s
Hide
Type "sleep 6"
Enter
Wait
Show
Type `make app ARGS="result $S 4"`
Enter
Wait
Sleep 5s
Type "make wallet ARGS=owned"
Enter
Wait
Sleep 5s
Type "make app ARGS=vaults"
Enter
Wait
Sleep 4s
Type "make dev-wallet2"
Enter
Wait
Sleep 3s
Type `CODE2=$(make -s app ARGS="offer 'My Game' ERA 0.10 1.00 GOLD")`
Enter
Wait
Type `make wallet2 ARGS="connect $CODE2"`
Enter
Wait
Sleep 4s
Type `S2=$(make -s app ARGS=connections | awk '$NF=="CONNECTED"{print $2}' | tail -1)`
Enter
Wait
Type `make app ARGS="stake $S $S2 'match 1' ERA 1.00 A"`
Enter
Wait
Hide
Type "sleep 6"
Enter
Wait
Show
Type `make app ARGS="result $S 5"`
Enter
Wait
Sleep 5s
Type `A=$(make -s app ARGS="result $S 5" | awk '/^  stake /{print $2; exit}')`
Enter
Wait
Type `make app ARGS="stake $S2 $S 'match 1' ERA 1.00 B $A"`
Enter
Wait
Hide
Type "sleep 6"
Enter
Wait
Show
Type `make app ARGS="result $S2 1"`
Enter
Wait
Sleep 5s
Type `B=$(make -s app ARGS="result $S2 1" | awk '/^  stake /{print $2; exit}')`
Enter
Wait
Type `make app ARGS="decide $A A"`
Enter
Wait
Sleep 4s
Type `make app ARGS="collect $S $A $B"`
Enter
Wait
Hide
Type "sleep 6"
Enter
Wait
Show
Type `make app ARGS="result $S 6"`
Enter
Wait
Sleep 5s
Type "make wallet ARGS=owned"
Enter
Wait
Sleep 5s
Type `make app ARGS="contacts $S"`
Enter
Wait
Hide
Type "sleep 4"
Enter
Wait
Show
Type `make app ARGS="result $S 7"`
Enter
Wait
Sleep 6s
