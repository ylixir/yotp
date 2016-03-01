# yotp
One time password generator (think google authenticator, two factor authentication)

Works with mono and dotnetcore. I would assume it works with windows, but I haven't tried it.

# usage
First you need your secret key. A three second google search gave me this:
https://dpron.com/3-ways-to-move-google-authenticator/

Which should give you some ideas on how to retrieve that. then simply run yotp, passing your key as a command line argument:

    $ ./yotp.exe JBSWY3DPEHPK3PXP

That line should give you the code currently displayed at http://blog.tinisles.com/2011/10/google-authenticator-one-time-password-algorithm-in-javascript/ if you wish to test things out.

## the future
* ~~reorganize to be more object oriented~~
* clean up all the magic numbers and replace with constants and tuneables
* embed lua to one shot configuration files and extensability/plugins
* make a steam and battle.net plugin
