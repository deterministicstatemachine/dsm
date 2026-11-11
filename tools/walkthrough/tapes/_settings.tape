# Shared look for every walkthrough episode (Source'd by each tape).
Set Shell "bash"
Set FontSize 20
Set Width 1600
Set Height 900
Set Padding 32
Set TypingSpeed 45ms
Set Theme "Builtin Dark"
# A long command (a build, the nodes coming up, an account's first run) is
# waited for, not slept through: `Wait` holds until the prompt is back.
Set WaitTimeout 600s
# The shell VHS opens is not a login shell: rustup's cargo (the pinned
# toolchain) comes first, as it does in a developer's own terminal.
Hide
Type `export PATH="$HOME/.cargo/bin:$PATH"; clear`
Enter
Wait
Show
