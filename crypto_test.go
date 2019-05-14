// This file is part of ffsendr.
// Copyright 2019 Darell Tan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the README.

package main

import (
	"encoding/json"
	"testing"
)

func TestMetaDecrypt(t *testing.T) {
	k, err := NewKeychainFromB64("Jrbx6a-S-iZay7vuTKGicw")
	if err != nil {
		t.Error(err)
	}
	data, err := k.DecryptMetadata("0lTNudREKY9ZDM2v60vHU7cBQDMlZEv4ZQ7YxOWwRi1lkUYX2N5s9I3EMiL6e20Sern5RQZSoQ4zRD1xmHx3XXcIBLacMnCjg8gglyqJOpNITP06WaVaD-LZqOZLeooIRS71-kRkb0-kcMR7MwP2IFlcCg-yDPEdjUv8e6LGT1WoCs6zGFAvB7XOy_Y")
	if err != nil {
		t.Error(err)
	}

	t.Logf("dec metadata: %q", data)

	var j json.RawMessage
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		t.Error(err)
	}
}
