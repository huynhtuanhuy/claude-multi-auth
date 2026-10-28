# Terminal demo for the README. Fake data only: seed.sh builds a debug `cma`
# with the test backend and a throwaway world under $TMPDIR.
#
# Run from the repository root:
#   vhs docs/assets/demo/demo.tape

Output docs/assets/demo.gif

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontFamily "Menlo"
Set FontSize 16
Set Columns 122
Set Rows 26
Set Padding 24
Set Framerate 20
Set TypingSpeed 55ms
Set WaitTimeout 300s

# Point the shell at the fake world (the first run also builds the binary).
Hide
Type `eval "$(docs/assets/demo/seed.sh)" && export PS1='$ ' HISTFILE=/dev/null && clear`
Enter
Wait /^\$$/
Show

Sleep 600ms
Type "cma list"
Sleep 300ms
Enter
Sleep 3s

Type "cma usage"
Sleep 300ms
Enter
Sleep 3s

Type "cma switch personal"
Sleep 300ms
Enter
Sleep 1.2s
# The confirmation reads a single key; no Enter.
Type "y"
Sleep 2.5s

Type "cma status"
Sleep 300ms
Enter
Sleep 1s
# The still for listings: the whole session on one screen.
Screenshot docs/assets/demo.png
Sleep 2.5s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type "cma list"
Sleep 300ms
Enter
Sleep 3.5s

# Remove the fake world.
Hide
Type `rm -rf "$CMA_DEMO_WORLD"`
Enter
Sleep 500ms
