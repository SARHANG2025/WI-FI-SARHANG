#!/usr/bin/python

# -*- coding: utf-8 -*-

"""
    wifite

    author: derv82 at gmail
    author: bwall @SARHANG_HRX (@SARHANG_HRX)
    author: drone @SARHANG_HRX (@SARHANG_HRX)

    Thanks to everyone that contributed to this project.
    If you helped in the past and want your name here, shoot me an email

    Licensed under the GNU General Public License Version 2 (GNU GPL v2),
        available at: http://www.gnu.org/licenses/gpl-2.0.txt

    (C) 2011 Derv Merkler

    Ballast Security additions
    -----------------
     - No longer requires to be root to run -cracked
     - cracked.txt changed to cracked.csv and stored in csv format(easier to read, no \x00s)
         - Backwards compatibility
     - Made a run configuration class to handle globals
     - Added -recrack (shows already cracked APs in the possible targets, otherwise hides them)
     - Changed the updater to grab files from GitHub and not Google Code
     - Use argparse to parse command-line arguments
     - -wepca flag now properly initialized if passed through CLI
     - parse_csv uses python csv library
    -----------------


    TODO:

    Restore same command-line switch names from v1

    If device already in monitor mode, check for and, if applicable, use macchanger

     WPS
     * Mention reaver automatically resumes sessions
     * Warning about length of time required for WPS attack (*hours*)
     * Show time since last successful attempt
     * Percentage of tries/attempts ?
     * Update code to work with reaver 1.4 ("x" sec/att)

     WEP:
     * ability to pause/skip/continue    (done, not tested)
     * Option to capture only IVS packets (uses --output-format ivs,csv)
       - not compatible on older aircrack-ng's.
           - Just run "airodump-ng --output-format ivs,csv", "No interface specified" = works
         - would cut down on size of saved .caps

     reaver:
          MONITOR ACTIVITY!
          - Enter ESSID when executing (?)
       - Ensure WPS key attempts have begun.
       - If no attempts can be made, stop attack

       - During attack, if no attempts are made within X minutes, stop attack & Print

       - Reaver's output when unable to associate:
         [!] WARNING: Failed to associate with AA:BB:CC:DD:EE:FF (ESSID: ABCDEF)
       - If failed to associate for x minutes, stop attack (same as no attempts?)

    MIGHTDO:
      * WPA - crack (pyrit/cowpatty) (not really important)
      * Test injection at startup? (skippable via command-line switch)

"""

# ############
# LIBRARIES #
#############

import csv  # Exporting and importing cracked aps
import os  # File management
import time  # Measuring attack intervals
import random  # Generating a random MAC address.
import errno  # Error numbers

from sys import argv  # Command-line arguments
from sys import stdout  # Flushing

from shutil import copy  # Copying .cap files

# Executing, communicating with, killing processes
from subprocess import Popen, call, PIPE
from signal import SIGINT, SIGTERM

import re  # RegEx, Converting SSID to filename
import argparse  # arg parsing
import urllib  # Check for new versions from the repo
import abc  # abstract base class libraries for attack templates


################################
# GLOBAL VARIABLES IN ALL CAPS #
################################

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray

# /dev/null, send output from programs so they don't print to screen.
DN = open(os.devnull, 'w')
ERRLOG = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')

###################
# DATA STRUCTURES #
###################


class CapFile:
    """
        Holds data about an access point's .cap file, including AP's ESSID & BSSID.
    """

    def __init__(self, filename, ssid, bssid):
        self.filename = filename
        self.ssid = ssid
        self.bssid = bssid


class Target:
    """
        Holds data for a Target (aka Access Point aka Router)
    """

    def __init__(self, bssid, power, data, channel, encryption, ssid):
        self.bssid = bssid
        self.power = power
        self.data = data
        self.channel = channel
        self.encryption = encryption
        self.ssid = ssid
        self.wps = False  # Default to non-WPS-enabled router.
        self.key = ''


class Client:
    """
        Holds data for a Client (device connected to Access Point/Router)
    """

    def __init__(self, bssid, station, power):
        self.bssid = bssid
        self.station = station
        self.power = power


class RunConfiguration:
    """
        Configuration for this rounds of attacks
    """

    def __init__(self):
        self.REVISION = 89;
        self.PRINTED_SCANNING = False

        self.TX_POWER = 0  # Transmit power for wireless interface, 0 uses default power

        # WPA variables
        self.WPA_DISABLE = False  # Flag to skip WPA handshake capture
        self.WPA_STRIP_HANDSHAKE = True  # Use pyrit or tshark (if applicable) to strip handshake
        self.WPA_DEAUTH_COUNT = 1  # Count to send deauthentication packets
        self.WPA_DEAUTH_TIMEOUT = 10  # Time to wait between deauthentication bursts (in seconds)
        self.WPA_ATTACK_TIMEOUT = 500  # Total time to allow for a handshake attack (in seconds)
        self.WPA_HANDSHAKE_DIR = 'hs'  # Directory in which handshakes .cap files are stored
        # Strip file path separator if needed
        if self.WPA_HANDSHAKE_DIR != '' and self.WPA_HANDSHAKE_DIR[-1] == os.sep:
            self.WPA_HANDSHAKE_DIR = self.WPA_HANDSHAKE_DIR[:-1]

        self.WPA_FINDINGS = []  # List of strings containing info on successful WPA attacks
        self.WPA_DONT_CRACK = False  # Flag to skip cracking of handshakes
        if os.path.exists('/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'):
            self.WPA_DICTIONARY = '/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
        elif os.path.exists('/usr/share/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'):
            self.WPA_DICTIONARY = '/usr/share/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
        elif os.path.exists('/usr/share/wordlists/fern-wifi/common.txt'):
            self.WPA_DICTIONARY = '/usr/share/wordlists/fern-wifi/common.txt'
        else:
            self.WPA_DICTIONARY = ''

        # Various programs to use when checking for a four-way handshake.
        # True means the program must find a valid handshake in order for wifite to recognize a handshake.
        # Not finding handshake short circuits result (ALL 'True' programs must find handshake)
        self.WPA_HANDSHAKE_TSHARK = True  # Checks for sequential 1,2,3 EAPOL msg packets (ignores 4th)
        self.WPA_HANDSHAKE_PYRIT = False  # Sometimes crashes on incomplete dumps, but accurate.
        self.WPA_HANDSHAKE_AIRCRACK = True  # Not 100% accurate, but fast.
        self.WPA_HANDSHAKE_COWPATTY = False  # Uses more lenient "nonstrict mode" (-2)

        # WEP variables
        self.WEP_DISABLE = False  # Flag for ignoring WEP networks
        self.WEP_PPS = 600  # packets per second (Tx rate)
        self.WEP_TIMEOUT = 600  # Amount of time to give each attack
        self.WEP_ARP_REPLAY = True  # Various WEP-based attacks via aireplay-ng
        self.WEP_CHOPCHOP = True  #
        self.WEP_FRAGMENT = True  #
        self.WEP_CAFFELATTE = True  #
        self.WEP_P0841 = True
        self.WEP_HIRTE = True
        self.WEP_CRACK_AT_IVS = 10000  # Number of IVS at which we start cracking
        self.WEP_IGNORE_FAKEAUTH = True  # When True, continues attack despite fake authentication failure
        self.WEP_FINDINGS = []  # List of strings containing info on successful WEP attacks.
        self.WEP_SAVE = False  # Save packets.

        # WPS variables
        self.WPS_DISABLE = False  # Flag to skip WPS scan and attacks
        self.PIXIE = False
        self.WPS_FINDINGS = []  # List of (successful) results of WPS attacks
        self.WPS_TIMEOUT = 660  # Time to wait (in seconds) for successful PIN attempt
        self.WPS_RATIO_THRESHOLD = 0.01  # Lowest percentage of tries/attempts allowed (where tries > 0)
        self.WPS_MAX_RETRIES = 0  # Number of times to re-try the same pin before giving up completely.


        # Program variables
        self.SHOW_ALREADY_CRACKED = False  # Says whether to show already cracked APs as options to crack
        self.WIRELESS_IFACE = ''  # User-defined interface
        self.MONITOR_IFACE = ''  # User-defined interface already in monitor mode
        self.TARGET_CHANNEL = 0  # User-defined channel to scan on
        self.TARGET_ESSID = ''  # User-defined ESSID of specific target to attack
        self.TARGET_BSSID = ''  # User-defined BSSID of specific target to attack
        self.IFACE_TO_TAKE_DOWN = ''  # Interface that wifite puts into monitor mode
        # It's our job to put it out of monitor mode after the attacks
        self.ORIGINAL_IFACE_MAC = ('', '')  # Original interface name[0] and MAC address[1] (before spoofing)
        self.DO_NOT_CHANGE_MAC = True  # Flag for disabling MAC anonymizer
        self.SEND_DEAUTHS = True # Flag for deauthing clients while scanning for acces points
        self.TARGETS_REMAINING = 0  # Number of access points remaining to attack
        self.WPA_CAPS_TO_CRACK = []  # list of .cap files to crack (full of CapFile objects)
        self.THIS_MAC = ''  # The interfaces current MAC address.
        self.SHOW_MAC_IN_SCAN = False  # Display MACs of the SSIDs in the list of targets
        self.CRACKED_TARGETS = []  # List of targets we have already cracked
        self.ATTACK_ALL_TARGETS = False  # Flag for when we want to attack *everyone*
        self.ATTACK_MIN_POWER = 0  # Minimum power (dB) for access point to be considered a target
        self.VERBOSE_APS = True  # Print access points as they appear
        self.CRACKED_TARGETS = self.load_cracked()
        old_cracked = self.load_old_cracked()
        if len(old_cracked) > 0:
            # Merge the results
            for OC in old_cracked:
                new = True
                for NC in self.CRACKED_TARGETS:
                    if OC.bssid == NC.bssid:
                        new = False
                        break
                # If Target isn't in the other list
                # Add and save to disk
                if new:
                    self.save_cracked(OC)

    def ConfirmRunningAsRoot(self):
        if os.getuid() != 0:
            print R + ' [!]' + O + ' ERROR:' + G + ' wifite' + O + ' must be run as ' + R + 'root' + W
            print R + ' [!]' + O + ' login as root (' + W + 'su root' + O + ') or try ' + W + 'sudo ./wifite.py' + W
            exit(1)

    def ConfirmCorrectPlatform(self):
        if not os.uname()[0].startswith("Linux") and not 'Darwin' in os.uname()[0]:  # OSX support, 'cause why not?
            print O + ' [!]' + R + ' WARNING:' + G + ' wifite' + W + ' must be run on ' + O + 'linux' + W
            exit(1)

    def CreateTempFolder(self):
        from tempfile import mkdtemp

        self.temp = mkdtemp(prefix='wifite')
        if not self.temp.endswith(os.sep):
            self.temp += os.sep

    def save_cracked(self, target):
        """
            Saves cracked access point key and info to a file.
        """
        self.CRACKED_TARGETS.append(target)
        with open('cracked.csv', 'wb') as csvfile:
            targetwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            for target in self.CRACKED_TARGETS:
                targetwriter.writerow([target.bssid, target.encryption, target.ssid, target.key, target.wps])

    def load_cracked(self):
        """
            Loads info about cracked access points into list, returns list.
        """
        result = []
        if not os.path.exists('cracked.csv'): return result
        with open('cracked.csv', 'rb') as csvfile:
            targetreader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for row in targetreader:
                t = Target(row[0], 0, 0, 0, row[1], row[2])
                t.key = row[3]
                t.wps = row[4]
                result.append(t)
        return result

    def load_old_cracked(self):
        """
                Loads info about cracked access points into list, returns list.
        """
        result = []
        if not os.path.exists('cracked.txt'):
            return result
        fin = open('cracked.txt', 'r')
        lines = fin.read().split('\n')
        fin.close()

        for line in lines:
            fields = line.split(chr(0))
            if len(fields) <= 3:
                continue
            tar = Target(fields[0], '', '', '', fields[3], fields[1])
            tar.key = fields[2]
            result.append(tar)
        return result

    def exit_gracefully(self, code=0):
        """
            We may exit the program at any time.
            We want to remove the temp folder and any files contained within it.
            Removes the temp files/folder and exists with error code "code".
        """
        # Remove temp files and folder
        if os.path.exists(self.temp):
            for f in os.listdir(self.temp):
                os.remove(os.path.join(self.temp, f))
            os.rmdir(self.temp)
        # Disable monitor mode if enabled by us
        self.RUN_ENGINE.disable_monitor_mode()
        # Change MAC address back if spoofed
        mac_change_back()
        print GR + " [+]" + W + " quitting"  # wifite will now exit"
        print ''
        # GTFO
        exit(code)

    def handle_args(self):
        """
            Handles command-line arguments, sets global variables.
        """
        set_encrypt = False
        set_hscheck = False
        set_wep = False
        capfile = ''  # Filename of .cap file to analyze for handshakes

        opt_parser = self.build_opt_parser()
        options = opt_parser.parse_args()

        try:
            if not set_encrypt and (options.wpa or options.wep or options.wps):
                self.WPS_DISABLE = True
                self.WPA_DISABLE = True
                self.WEP_DISABLE = True
                set_encrypt = True
            if options.recrack:
                self.SHOW_ALREADY_CRACKED = True
                print GR + ' [+]' + W + ' including already cracked networks in targets.'
            if options.wpa:
                if options.wps:
                    print GR + ' [+]' + W + ' targeting ' + G + 'WPA' + W + ' encrypted networks.'
                else:
                    print GR + ' [+]' + W + ' targeting ' + G + 'WPA' + W + ' encrypted networks (use ' + G + '-wps' + W + ' for WPS scan)'
                self.WPA_DISABLE = False
            if options.wep:
                print GR + ' [+]' + W + ' targeting ' + G + 'WEP' + W + ' encrypted networks'
                self.WEP_DISABLE = False
            if options.wps:
                print GR + ' [+]' + W + ' targeting ' + G + 'WPS-enabled' + W + ' networks.'
                self.WPS_DISABLE = False
            if options.pixie:
                print GR + ' [+]' + W + ' targeting ' + G + 'WPS-enabled' + W + ' networks.'
                print GR + ' [+]' + W + ' using only ' + G + 'WPS Pixie-Dust' + W + ' attack.'
                self.WPS_DISABLE = False
                self.WEP_DISABLE = True
                self.PIXIE = True
            if options.channel:
                try:
                    self.TARGET_CHANNEL = int(options.channel)
                except ValueError:
                    print O + ' [!]' + R + ' invalid channel: ' + O + options.channel + W
                except IndexError:
                    print O + ' [!]' + R + ' no channel given!' + W
                else:
                    print GR + ' [+]' + W + ' channel set to %s' % (G + str(self.TARGET_CHANNEL) + W)
            if options.mac_anon:
                print GR + ' [+]' + W + ' mac address anonymizing ' + G + 'enabled' + W
                print O + '      not: only works if device is not already in monitor mode!' + W
                self.DO_NOT_CHANGE_MAC = False
            if options.interface:
                self.WIRELESS_IFACE = options.interface
                print GR + ' [+]' + W + ' set interface :%s' % (G + self.WIRELESS_IFACE + W)
            if options.monitor_interface:
                self.MONITOR_IFACE = options.monitor_interface
                print GR + ' [+]' + W + ' set interface already in monitor mode :%s' % (G + self.MONITOR_IFACE + W)
            if options.nodeauth:
                self.SEND_DEAUTHS = False
                print GR + ' [+]' + W + ' will not deauthenticate clients while scanning%s' % W
            if options.essid:
                try:
                    self.TARGET_ESSID = options.essid
                except ValueError:
                    print R + ' [!]' + O + ' no ESSID given!' + W
                else:
                    print GR + ' [+]' + W + ' targeting ESSID "%s"' % (G + self.TARGET_ESSID + W)
            if options.bssid:
                try:
                    self.TARGET_BSSID = options.bssid
                except ValueError:
                    print R + ' [!]' + O + ' no BSSID given!' + W
                else:
                    print GR + ' [+]' + W + ' targeting BSSID "%s"' % (G + self.TARGET_BSSID + W)
            if options.showb:
                self.SHOW_MAC_IN_SCAN = True
                print GR + ' [+]' + W + ' target MAC address viewing ' + G + 'enabled' + W
            if options.all:
                self.ATTACK_ALL_TARGETS = True
                print GR + ' [+]' + W + ' targeting ' + G + 'all access points' + W
            if options.power:
                try:
                    self.ATTACK_MIN_POWER = int(options.power)
                except ValueError:
                    print R + ' [!]' + O + ' invalid power level: %s' % (R + options.power + W)
                except IndexError:
                    print R + ' [!]' + O + ' no power level given!' + W
                else:
                    print GR + ' [+]' + W + ' minimum target power set to %s' % (G + str(self.ATTACK_MIN_POWER) + W)
            if options.tx:
                try:
                    self.TX_POWER = int(options.tx)
                except ValueError:
                    print R + ' [!]' + O + ' invalid TX power leve: %s' % ( R + options.tx + W)
                except IndexError:
                    print R + ' [!]' + O + ' no TX power level given!' + W
                else:
                    print GR + ' [+]' + W + ' TX power level set to %s' % (G + str(self.TX_POWER) + W)
            if options.quiet:
                self.VERBOSE_APS = False
                print GR + ' [+]' + W + ' list of APs during scan ' + O + 'disabled' + W
            if options.check:
                try:
                    capfile = options.check
                except IndexError:
                    print R + ' [!]' + O + ' unable to analyze capture file' + W
                    print R + ' [!]' + O + ' no cap file given!\n' + W
                    self.exit_gracefully(1)
                else:
                    if not os.path.exists(capfile):
                        print R + ' [!]' + O + ' unable to analyze capture file!' + W
                        print R + ' [!]' + O + ' file not found: ' + R + capfile + '\n' + W
                        self.exit_gracefully(1)
            if options.cracked:
                if len(self.CRACKED_TARGETS) == 0:
                    print R + ' [!]' + O + ' There are no cracked access points saved to ' + R + 'cracked.db\n' + W
                    self.exit_gracefully(1)
                print GR + ' [+]' + W + ' ' + W + 'previously cracked access points' + W + ':'
                for victim in self.CRACKED_TARGETS:
                    if victim.wps != False:
            
