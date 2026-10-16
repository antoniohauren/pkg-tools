# DirectPackageInstaller payload

`payload.bin` is an unmodified copy from DirectPackageInstaller commit
`ca7bade66737fede3b0e7bad73b665e0a4d4ff39`,
SHA-256 `1ca35f9670c2b4ff55a769df52ecccbf534c5e349da85bc5af6da7b8520dcfb0`.

Copyright its contributors; licensed under GNU GPL v3. Source and build files:
https://github.com/marcussacana/DirectPackageInstaller/tree/ca7bade66737fede3b0e7bad73b665e0a4d4ff39/Payload

PKG Tools patches only the six-byte callback address marker in memory before
sending this separate payload to GoldHEN BinLoader.
