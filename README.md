# mgrep(1) - print lines that match patterns in mime\-encoded files

0.1, 2019-07-02

```
mgrep [\| -Q \||\| -X \|] [ GREP_OPTION .\|.\|.] PATTERN [ FILE .\|.\|.]
mgrep [\| -Q \||\| -X \|] [ GREP_OPTION .\|.\|.] -e PATTERNS .\|.\|. [ FILE .\|.\|.]
mgrep [\| -Q \||\| -X \|] [ GREP_OPTION .\|.\|.] -f PATTERN_FILE .\|.\|. [ FILE .\|.\|.]
```

# Description

*Mgrep*
ican be used to invoke the
*grep*
command on the
**decoded**
content of
*BASE64*
or
*quoted-printable*
mime-encoded files. Beside the options
**-Q**
and
**-X**
all options specified are passed directly to
*grep.*
If no file is specified, then the standard input is mime-decoded
and fed to grep.
Otherwise the given files are mime-decoded and fed to
*grep*.

As experimental feature: if the input files is in mbox format 
**mgrep**
may detect the boundaries used for the mime encoded messages
as well as attachments and fed the decoded content of those
(but not the header) to 
*grep*.

# Options


* **-h&nbsp;***,&nbsp;--help*  
  Displays this help (as well as the help of original
  *grep*)
  and exit.
* **-Q&nbsp;***\fr,&nbsp;\fb--quoted-printable*  
  Assume
  *quoted-printablei*
  encoding.
* **-X&nbsp;***\fr,&nbsp;\fb--base64*  
  Assume
  *base64*
  encoding (default).

# See Also

**grep**(1)

# Standards


## RFC\ 2045

Multipurpose Internet Mail Extensions, (**MIME**) Part One: Format of Internet Message Bodies

## RFC\ 4155

The **application/mbox** Media Type

# Licenses

*GNU GPL v2*  
*MIT*
-- mainly the
**MIME**
decoding part.

# Author

Werner Fink &lt;[werner@suse.de](mailto:werner@suse.de)&gt;
