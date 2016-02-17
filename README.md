# rlm_gauth

**rlm_gauth** is a module to the freeradius server that authorizes clients using theirs google account credentials.

The module is so easy as grab the username and password from the radius packet and just validate it using a smtp connection with google.
This is one of recommended ways to validate if users exists and their credentials are valid.

## How to use

### Compile

**First** you need to clone or download the freeRADIUS source code from the repo. [Github](https://github.com/FreeRADIUS/freeradius-server).

The best way to do it, is to download instead of clone it, but if you prefer clone, delete the .git folder from the project. There are some validations on the *VERSION* and *commit hash* so they need to be the same as the one on your freeradius instalation.
If you install freeradius using your system package manager, this values should be 0.

**Second**, you need to include this module in the `src/modules` folder of the freeradius server source code. You can add it as a `git submodule` or just by downloading this code and including it on the folder mentioned before.

As a submodule, you just need to change directory to `src/modules` and run `git submodule add https://github.com/portellaa/rlm_gauth.git` and it's ready to go.

**Third**, just go back to your freeradius source code folder, run `./configure && make`. If you are running your own version of freeradius, instead of one from your system package manager, you can run `make install` too.

### Installation

If you didn't run `make install` mentioned in the section above, you need to copy the compiled module to the lib folder of the version installed on your system.

You can find the compiled modules in `build/lib/.libs/`

The modules should be in the `/usr/lib/freeradius/` but this can change with your system version. The best way to know is querying your package manager for the files installed with the freeradius packet.

### Configuration

The users account should be verified against any domain, even if that one is __*gmail.com*__

The modules configuration are under `/etc/raddb/mods-availabe/`. So, you should just create a file called `gauth` with the configuration:

```
gauth {
	domain = gmail.com
}
```

## Roadmap

* [X] Support simple username and cleartext passwords.
* [ ] Support configuration for smtp connection.

## Credits

[Mindera People](www.mindera.com)

## License

MIT