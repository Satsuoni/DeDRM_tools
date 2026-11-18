#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
A wrapper script to generate zip files for GitHub releases.

This script tends to be compatible with both Python 2 and Python 3.
'''

from __future__ import print_function

import os
import shutil


DEDRM_SRC_DIR = 'DeDRM_plugin'
DEDRM_SRC_TMP_DIR = 'DeDRM_plugin_temp'
DEDRM_README= 'DeDRM_plugin_ReadMe.txt'
OBOK_SRC_DIR = 'Obok_plugin'
OBOK_SRC_TMP_DIR = 'Obok_plugin_temp'
OBOK_README = 'obok_plugin_ReadMe.txt'
KRFTool="Other_Tools/KRFKeyExtractor/KRFKeyExtractor.exe"
KRFTool28="Other_Tools/KRFKeyExtractor/KFXKeyExtractor28.exe"
KRFTool282="Other_Tools/KRFKeyExtractor/KFXKeyExtractor282.exe"
KFXArchiverTool291="Other_Tools/KRFKeyExtractor/KFXArchiver291.exe"
MSIXArchiverTool="Other_Tools/KRFKeyExtractor/MSIXKFXArchiver1_23620_final.exe"
MSIXArchiverTool64="Other_Tools/KRFKeyExtractor/MSIXKFXArchiver_x64_1_5634.exe"
KRFFrida="Other_Tools/KRFKeyExtractor/kindleFridaInstr.py"
KRFFridaDecr="Other_Tools/KRFKeyExtractor/kindleFridaDecrypt.py"
KRFFrida86="Other_Tools/KRFKeyExtractor/kindledecr_x84_64"
KRFFridaArm="Other_Tools/KRFKeyExtractor/kindledecr_arm64"
KRFFridaAgent="Other_Tools/KRFKeyExtractor/compiled_agent.js"



RELEASE_DIR = 'release'

# Never ship these from the working tree (caches, editor/OS droppings, patch leftovers).
EXCLUDED_DIRS = ('__pycache__', '.pytest_cache', '.mypy_cache')
EXCLUDED_FILE_SUFFIXES = ('.pyc', '.pyo', '.tmp', '.orig', '.rej', '.swp')
EXCLUDED_FILE_NAMES = ('.DS_Store', 'Thumbs.db')

def patch_file(filepath):
    f = open(filepath, "rb")
    fn = open(filepath + ".tmp", "wb")
    patch = open(os.path.join(DEDRM_SRC_DIR, "__calibre_compat_code.py"), "rb")
    patchdata = patch.read()
    patch.close()

    while True:
        line = f.readline()
        if len(line) == 0:
            break

        if line.strip().startswith(b"#@@CALIBRE_COMPAT_CODE@@"):
            fn.write(patchdata)
        else:
            fn.write(line)

    f.close()
    fn.close()
    shutil.move(filepath + ".tmp", filepath)



def _ignore_junk(directory, names):
    """shutil.copytree ignore callback: drop caches and stray files."""
    return [n for n in names
            if n in EXCLUDED_DIRS
            or n in EXCLUDED_FILE_NAMES
            or n.endswith(EXCLUDED_FILE_SUFFIXES)]


def make_plugin_zip(src_dir, tmp_dir, apply_compat_patch):
    """Build <src_dir>.zip from a cleaned temporary copy of src_dir.

    The source tree is never zipped directly, so caches or leftovers from a
    crashed run cannot end up in the release. Returns the zip file name.
    """
    shutil.rmtree(tmp_dir, ignore_errors=True)
    shutil.copytree(src_dir, tmp_dir, ignore=_ignore_junk)
    try:
        if apply_compat_patch:
            for root, dirs, files in os.walk(tmp_dir):
                for name in files:
                    if name.endswith(".py"):
                        patch_file(os.path.join(root, name))
        return shutil.make_archive(src_dir, 'zip', tmp_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def make_release(version):
    shutil.rmtree(RELEASE_DIR, ignore_errors=True)
    os.mkdir(RELEASE_DIR)

    # Package both plugins from cleaned temporary copies.
    make_plugin_zip(DEDRM_SRC_DIR, DEDRM_SRC_TMP_DIR, apply_compat_patch=True)
    make_plugin_zip(OBOK_SRC_DIR, OBOK_SRC_TMP_DIR, apply_compat_patch=False)
    shutil.move(DEDRM_SRC_DIR+'.zip', RELEASE_DIR)
    shutil.move(OBOK_SRC_DIR+'.zip', RELEASE_DIR)
    shutil.copy(DEDRM_README, RELEASE_DIR)
    shutil.copy(OBOK_README, RELEASE_DIR)
    try:
        shutil.copy(KRFTool, RELEASE_DIR)
    except:
        pass
    try:
        shutil.copy(KRFTool28, RELEASE_DIR)
    except:
        pass    
    try:
        shutil.copy(KRFTool282, RELEASE_DIR)
    except:
        pass    
    try:
        shutil.copy(MSIXArchiverTool, RELEASE_DIR)
    except:
        pass    
    try:
        shutil.copy(MSIXArchiverTool64, RELEASE_DIR)
    except:
        pass    
    try:
        shutil.copy(KFXArchiverTool291, RELEASE_DIR)
    except:
        pass
    try:
        shutil.copy(KRFFrida, RELEASE_DIR)
    except:
        pass
    try:
        shutil.copy(KRFFridaDecr, RELEASE_DIR)
    except:
        pass        
    try:
        shutil.copy(KRFFrida86, RELEASE_DIR)
    except:
        pass
    try:
        shutil.copy(KRFFridaArm, RELEASE_DIR)
    except:
        pass
    try:
        shutil.copy(KRFFridaAgent, RELEASE_DIR)
    except:
        pass

    shutil.copy("ReadMe_Overview.txt", RELEASE_DIR)

    if version is not None:
        release_name = 'DeDRM_tools_{}'.format(version)
    else:
        release_name = 'DeDRM_tools'
    result = shutil.make_archive(release_name, 'zip', RELEASE_DIR)
    shutil.rmtree(RELEASE_DIR, ignore_errors=True)
    return result


if __name__ == '__main__':
    import sys
    try:
        version = sys.argv[1]
    except IndexError:
        version = None

    print(make_release(version))
