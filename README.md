# xdccget
This is a project that allows you to download files from IRC with XDCC with an easy and simple to use command line tool
like wget or curl. It supports at the moment Linux, Windows (with cygwin) and BSD-variants. Also OSX with some installed
ports works.

## Using xdccget
In order to use xdccget properly i will provide some simple examples. You should be able to extract 
the options for your personal usage quite quickly, i guess:

For example, let's assume that you want to download the package *34* from the bot *super-duper-bot*
at the channel *best-channel* from the irc-server
*irc.sampel.net* without ssl and from the standard-irc-port *6667*. 
Then the command line argument for xdccget would be:

``` 
xdccget -i "irc.sampel.net" "#best-channel" "super-duper-bot xdcc send #34"
``` 

This would download the package *34* from *super-duper-bot* without using ssl. You can also specifiy a 
special port, so lets assume that the *irc.sampel.net* server would use the port 1337. Then our xdcc-get-call would
be like this:

``` 
xdccget -i -p 1337 "irc.sampel.net" "#best-channel" "super-duper-bot xdcc send #34"
``` 

If your irc-network supports ssl you can even use an secure ssl-connection with xdccget. So lets imagine that 
*irc.sampel.net* uses ssl on port 1338. Then we would call xdccget like this to use ssl:

``` 
xdccget -i -p 1338 "#irc.sampel.net" "#best-channel" "super-duper-bot xdcc send #34"
``` 

If the bot even supports ssl than you can use the ssend-command to use an ssl-encrypted connection with the bot.
So for example if the *super-duper-bot* would support ssl-connection, then we could call xdccget like:

``` 
xdccget -i -p 1338 "#irc.sampel.net" "#best-channel" "super-duper-bot xdcc ssend #34"
``` 

Notice the *xdcc ssend* command instead of *xdcc send*. This tells the bot that we want connect to him with ssl 
enabled.

This is the basic usage of xdccget. You can call xdccget --help to understand all currently supported arguments.
xdccget also uses a config file, which will be placed at your homefolder in .xdccget/config. You can modify
the default parameters to your matters quickly.

## Compiling xdccget
Compiling xdccget is just running make from the root folder of the repository. Please make sure, that you have installed
the depended libraries (OpenSSL and for some systems argp-library) and use the correct Makefile for your system.

### Ubuntu and derivants
To compile xdccget under Ubuntu and other distros like Linux Mint you have to install the package libssl-dev with apt-get.
You also need the build-essential package. 

```
sudo apt-get install libssl-dev build-essential
```

### other linux distros
You need to make sure, that you have the openssl-development packages for you favorite distribution installed.

### OSX and BSD
For osx and bsd systems you need to also install the development files for openssl. You need to install
the library argp, which is used to parse command line arguments. Please make sure, that you rename the Makefile.FreeBSD
for example to Makefile if you want to compile for FreeBSD.

If you use pkg on FreeBSD for package-management you can issue the following command to install the required libs:

```
sudo pkg install gcc argp-standalone openssl
```

On OSX and other BSD variants you have to use an alternative way to install the packages.

### Windows
For windows you first need to install cygwin. Please make sure that you install gcc-core, libargp and openssl-devel with
cygwin. If you have installed all depedent libraries then you can compile xdccget with cygwin by using the Makefile.cygwin.
Please rename Makefile.cygwin to Makefile and then run make from the cygwin terminal.

## Configure xdccget
You can configure some options with the config file. It is placed in the folder .xdccget in your home directory of your operating system. The following options are currently supported:

``` 
downloadDir - this defines the default directory used to store the downloaded files
logLevel - this defines the default logging level. valid options are info, warn and error
allowAllCerts - this options will allow silently all self signed certificates if set to true
```
