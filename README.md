# ahcifixd.sys
DOS driver to allow Memory Managers (e.g. EMM386) to be used with Intel AHCI (SATA) controllers without corrupting EBDA

This sets out to solve the same problems as [`ahcifix.386`](https://github.com/PluMGMK/ahcifix.386) (detailed in that project's Readme), but under `EMM386` (or equivalent) as opposed to Windows 3.1.

## Building

Assemble it as a binary file using JWASM or similar, e.g. as done in the `DOSBUILD.BAT`.

## Usage

Load it as a device from `CONFIG.SYS`, **before** `EMM386` or any other Memory Manager. If you plan to run Windows 3.1 in Enhanced Mode, you can also specify the path to your copy of [`ahcifix.386`](https://github.com/PluMGMK/ahcifix.386). This can be omitted if it's in `C:\WINDOWS\SYSTEM` though.

For example, here's what I have in my `CONFIG.SYS`:
```
DEVICE=C:\AHCIFIXD\AHCIFIXD.SYS C:\WIN16DDK\386\AHCIFIX\AHCIFIX.386
DEVICE=C:\DOS\EMM386.EXE RAM I=B000-B7FF FRAME=D800
```

I have included my `EMM386.EXE` invocation to highlight that this driver is loaded before it.
