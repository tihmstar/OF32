# offsetfinder
A simple tool to find offsets needed in 32bit jailbreaks. Feel free to contribute.

### How to use
```
./offsetfinder [iOS BuildID] (device1 device2 device3 ...)
```

### Notes
Only works on 32bit kernelcaches (obviously). Didn't do a lot of testing, so stuff may happen. Also not sure all offsets needed are included.
Pull requests are appreciated!

*Important:* will not work on dumps/runtime kernel as it is, since it relies on symbols that get stripped at runtime.
