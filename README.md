ffsendr
========

This is yet another unofficial *Firefox Send* client,
written in Go.

It aims to be lean, easy to audit and hackable,
so it lacks fancy features.
For example, it doesn't bother fetching the metadata associated 
with the downloads, so your files will be named `[file-id].bin`.

Feel free to hack away on this client.
If you do find bugs, you can file an issue, or better yet, a pull request.

⚠️ This client has not been thoroughly tested, 
so please beware when using it for mission-critical tasks.

Installation
=============

You will need to install [Go](https://golang.org/).

To download and compile *ffsendr*, use `go get`:

    go get github.com/geekman/ffsendr

The `ffsendr` executable should now be in your `$GOPATH/bin` directory.


Usage
======

This client can upload and download files,
but provides some additional control over encryption.

Note that due to the behavior of Go's flag parsing library, 
all flags (options) must be placed in front before the action verb.


Upload
-------

    ffsendr upload <file>

When uploading, you can control the master key used to encrypt the file
by specifying the `-key` flag.


Download
---------

    ffsendr download https://send.firefox.com/download/00aabbccdd/#azkwH...

You can download the file either using the full link with the secret key
appended, or without:

    ffsendr -authkey ... download https://send.firefox.com/download/00aabbccdd/

If you do not specify the secret, you will need an *auth key* instead. 
See below on how it can be derived.

Subsequently, you will also need to manually decrypt the file with:

    ffsendr -key azkwH... decrypt <file>


Keys
-----

You can show the generated keys by using the `keys` subcommand:

    ffsendr -key azkwH... keys

Among the keys generated is the auth key, which you can use for 
downloading files.

While the keys generated are shown in hex, keys specified in flags must be in 
raw (no padding) URL-safe Base64.


License
========

**ffsendr is licensed under the 3-clause ("modified") BSD License.**

Copyright (C) 2019 Darell Tan

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

