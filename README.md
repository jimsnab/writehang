# About

This project reproduces a go networking issue. There is some combination of accumulated buffered data that
leads to a hung Write() call.

To reproduce:

1. `go install .`
2. Open up two terminals, one for the server, the other for the client
3. On the server terminal, run `writehang server`
4. On the client terminal, run `writehang client`
5. Wait for a few minutes

The repro seen should look like this on the server terminal:

```
...
sent 78282
sent 78283
received: processed 19657
sent 78284
sent 78285
sent 78286
sent 78287
received: processed 19658
sent 78288
received: processed 19659
received: processed 19660
received: processed 19661
received: processed 19662
received: processed 19663
received: processed 19664
...
```

The `sent` lines should continue endlessly, but they stop at some point. (Guess: socket buffers full?)
At this point the code is stuck in `waitWrite()` in the go runtime.

Remove this line from `sender.go` and the wedge will happen almost immediately.

`time.Sleep(time.Millisecond)		// slow things for easier observation`

This program was extracted from production software that is encountering occassional lockups. It's not
clear if TLS is required for the repo and it probably isn't.

There is some test code included also for digging into the implementation.