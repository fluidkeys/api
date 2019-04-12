// Copyright 2018 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

package pgpkey

import "github.com/fluidkeys/fluidkeys/fingerprint"

// LoaderInterface allows mocking Loader (not PgpKey) which itself wraps the package function
// pgpkey.LoadFromArmoredEncryptedPrivateKey
type LoaderInterface interface {
	LoadFromArmoredEncryptedPrivateKey(string, string) (*PgpKey, error)
}

// PgpKeyInterface allows mocking PgpKey
type PgpKeyInterface interface {
	Armor() (string, error)
	ArmorPrivate(string) (string, error)
	Fingerprint() fingerprint.Fingerprint
}
