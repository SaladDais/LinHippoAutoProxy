# What

[WinHippoAutoProxy](https://github.com/SaladDais/WinHippoAutoProxy), but for Linux.
This is a wrapper program to proxy a Second Life viewer through Hippolyzer, even if the viewer has no SOCKS5 support.
Any viewer that supports the `http_proxy` env vars and uses the typical UDP networking functions should be wrappable.

# Why

To help developers who don't want to write SOCKS 5 code to test their viewers or bots with Hippolyzer.

# Where

https://github.com/SaladDais/LinHippoAutoProxy

# How

It intercepts the relevant POSIX functions for sending and receiving UDP messages using `LD_PRELOAD`.

You can build it on Debian derivatives with:

```shell
sudo apt-get install build-essential g++
make
```

Then you can run the program you want to wrap like `./hippoautoproxy.sh ~/firestorm_dir/firestorm`
or `./hippoautoproxy.sh node some_bot.js` or whatever.

If you have issues with HTTP connections, either: 
* Your HTTP library doesn't support the `http_proxy` environment variable and needs manual proxying
* Your HTTP library doesn't trust the proxy's HTTPS cert. Disable SSL verification or trust the proxy's CA cert (it's in `~/.mitmproxy/mitmproxy-ca-cert.pem`)

# ?

I only implemented enough to get Hippolyzer working because neither tsocks nor proxychains-ng supported
SOCKS 5 UDP. It probably won't work well for anything other than Hippolyzer without more work.
