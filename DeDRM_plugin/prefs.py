#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fileencoding=UTF-8:ts=4:sw=4:sta:et:sts=4:ai

__license__ = 'GPL v3'

# Standard Python modules.
import os, sys
import traceback
import time


#@@CALIBRE_COMPAT_CODE@@


try: 
    from calibre.utils.config import JSONConfig
except:
    from standalone.jsonconfig import JSONConfig

from __init__ import PLUGIN_NAME

class DeDRM_Prefs():
    def __init__(self, json_path=None):
        if json_path is None:
            JSON_PATH = os.path.join("plugins", PLUGIN_NAME.strip().lower().replace(' ', '_') + '.json')
        else:
            JSON_PATH = json_path

        # Calibre workers can initialize concurrently; retry transient Windows
        # sharing violations without overwriting the existing preference file.
        for attempt in range(6):
            try:
                self.dedrmprefs = JSONConfig(JSON_PATH)
                break
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.05 * (attempt + 1))

        self.dedrmprefs.defaults['configured'] = False
        self.dedrmprefs.defaults['deobfuscate_fonts'] = True
        self.dedrmprefs.defaults['remove_watermarks'] = True
        self.dedrmprefs.defaults['bandnkeys'] = {}
        self.dedrmprefs.defaults['adeptkeys'] = {}
        self.dedrmprefs.defaults['ereaderkeys'] = {}
        self.dedrmprefs.defaults['kindlekeys'] = {}
        self.dedrmprefs.defaults['androidkeys'] = {}
        self.dedrmprefs.defaults['pids'] = []
        self.dedrmprefs.defaults['serials'] = []
        self.dedrmprefs.defaults['lcp_passphrases'] = []
        self.dedrmprefs.defaults['adobe_pdf_passphrases'] = []
        self.dedrmprefs.defaults['adobewineprefix'] = ""
        self.dedrmprefs.defaults['kindlewineprefix'] = ""
        self.dedrmprefs.defaults['kindleextrakeyfile'] = ""

        # initialise
        # we must actually set the prefs that are dictionaries and lists
        # to empty dictionaries and lists, otherwise we are unable to add to them
        # as then it just adds to the (memory only) dedrmprefs.defaults versions!
        if self.dedrmprefs['bandnkeys'] == {}:
            dict.__setitem__(self.dedrmprefs, 'bandnkeys', {})
        if self.dedrmprefs['adeptkeys'] == {}:
            dict.__setitem__(self.dedrmprefs, 'adeptkeys', {})
        if self.dedrmprefs['ereaderkeys'] == {}:
            dict.__setitem__(self.dedrmprefs, 'ereaderkeys', {})
        if self.dedrmprefs['kindlekeys'] == {}:
            dict.__setitem__(self.dedrmprefs, 'kindlekeys', {})
        if self.dedrmprefs['androidkeys'] == {}:
            dict.__setitem__(self.dedrmprefs, 'androidkeys', {})
        if self.dedrmprefs['pids'] == []:
            dict.__setitem__(self.dedrmprefs, 'pids', [])
        if self.dedrmprefs['serials'] == []:
            dict.__setitem__(self.dedrmprefs, 'serials', [])
        if self.dedrmprefs['lcp_passphrases'] == []:
            dict.__setitem__(self.dedrmprefs, 'lcp_passphrases', [])
        if self.dedrmprefs['adobe_pdf_passphrases'] == []:
            dict.__setitem__(self.dedrmprefs, 'adobe_pdf_passphrases', [])

    def __getitem__(self,kind = None):
        if kind is not None:
            return self.dedrmprefs[kind]
        return self.dedrmprefs

    def set(self, kind, value):
        self.dedrmprefs[kind] = value

    def writeprefs(self,value = True):
        self.dedrmprefs['configured'] = value

    def addnamedvaluetoprefs(self, prefkind, keyname, keyvalue):
        try:
            if keyvalue not in self.dedrmprefs[prefkind].values():
                # ensure that the keyname is unique
                # by adding a number (starting with 2) to the name if it is not
                namecount = 1
                newname = keyname
                while newname in self.dedrmprefs[prefkind]:
                    namecount += 1
                    newname = "{0:s}_{1:d}".format(keyname,namecount)
                # add to the preferences
                self.dedrmprefs[prefkind][newname] = keyvalue
                return (True, newname)
        except:
            traceback.print_exc()
            pass
        return (False, keyname)

    def addvaluetoprefs(self, prefkind, prefsvalue):
        # ensure the keyvalue isn't already in the preferences
        try:
            if prefsvalue not in self.dedrmprefs[prefkind]:
                self.dedrmprefs[prefkind].append(prefsvalue)
                return True
        except:
            traceback.print_exc()
        return False
