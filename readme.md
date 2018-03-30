# CLI Deauther for macOS

This project is very much an experiment, a proof of concept made entirely
for educational purposes. It should not be considered stable or
user friendly.

<img width="800" alt="deauther CLI" src="https://user-images.githubusercontent.com/246651/38156175-f94137c4-3473-11e8-997b-9e2a34177f31.png">

## About this project

The 802.11 WiFi standard which prescribes almost all of our communications
these days has its flaws. I recently found out about these flaws and wanted to
learn more about them.

In particular, every client connected to a WiFi access point is vulnerable to
a [deauthentication attack](https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack).
Through this project I've learned many things, including the fact that this
attack does work. I talk about my findings in the next section.

I've had just about as much fun getting the deauth attack working as scanning
the air waves for packets from various devices. It surprised me just how much
you can learn by doing so.

## Deauth attack effectiveness

Note that this assumes that my implementation doesn't have any defects, it's
possible there is an opportunity to make it more effective.

My tests were also rather rudimentary. I so far only tested this tool on an
open WiFi network. I deauthed two devices, an Android smartphone and a
PlayStation 4 console. Both devices were compromised.

The deauth attack carried out by this tool caused both devices to intermittently
lose connection to the WiFi network. This had multiple practical consequences
depending on the application used on the device.

On my Android device I ran a simple `ping` command. During the deauth attack
packets were still being returned, but intermittent disconnections caused
errors for approximately 5 seconds before a connection was restored with another
access point. The deauth attack wasn't able to completely disconnect the device
from the internet. This could have been due to the plethora of access points
available on my home network.

On my PS4 I played two games while the deauth attack was being carried out.
Fortnite and Gwent, in both cases the games were able to remain connected to
the server, but the intermittent disconnections caused very great lag which made
them largely unplayable.

In Fortnite's case I was able to observe some pretty
clever client-side prediction when spectating other players, but controlling
my own character caused the character to simply stop and then teleport in the
direction I was initially walking after reconnection.

As for Gwent, the consistent disconnections caused it to pop up a dialog box
with a "Connection lost... reconnecting..." message every couple of seconds.
This made the game really annoying to play.

## Disclaimer

I repeat: this project was made entirely for educational purposes. Use it only
against your own networks and devices.
Check the legal regulations in your country before using it. I don't take
any responsibility for what you do with this program.