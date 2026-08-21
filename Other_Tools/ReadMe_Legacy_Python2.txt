Legacy Python 2 scripts in Other_Tools
=======================================

The following standalone scripts were written for Python 2 and do not run
(or even compile) on Python 3. They are NOT part of the release zips and are
kept for reference only:

  DRM_Key_Scripts/Adobe_Digital_Editions/adobekey.pyw
  DRM_Key_Scripts/Barnes_and_Noble_ePubs/ignoblekey.pyw
  DRM_Key_Scripts/Barnes_and_Noble_ePubs/ignoblekeyfetch.pyw
  DRM_Key_Scripts/Barnes_and_Noble_ePubs/ignoblekeygen.pyw
  DRM_Key_Scripts/Kindle_for_Android/androidkindlekey.pyw
  DRM_Key_Scripts/Kindle_for_iOS/kindleiospidgen.pyw
  DRM_Key_Scripts/Kindle_for_Mac_and_PC/kindlekey.pyw
  Tetrachroma_FileOpen_ineptpdf/ineptpdf_fileopen.pyw

Maintained Python 3 versions of the key-retrieval scripts live inside the
DeDRM calibre plugin (DeDRM_plugin/), which can also be run standalone:

  python3 -m DeDRM_plugin --help

Kobo/obok.py (v3.2.4) is an older standalone copy of the Obok plugin's
obok.py; it compiles on Python 3 but the maintained version is
Obok_plugin/obok/obok.py.
