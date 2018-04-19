package blocks

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"

	mh "gx/ipfs/QmZyZDi491cCNTLfAhwcaDii2Kg4pwKRkhqQzURGDvY6ua/go-multihash"
	cid "gx/ipfs/QmcZfnkapfECQGcLZaf9B79NRg7cRa9EnZh4LSbkCzwNvY/go-cid"
)

type CryptoBlock struct {
	cid    *cid.Cid
	data   []byte
	public []byte
}

// NewBlockWithPrefix creates a new block from data and a prefix.
// If the prefix is a version 4 prefix the data will be encrypted.
func NewBlockWithPrefix(data []byte, pref cid.Prefix) (Block, error) {
	if pref.Version != 4 {
		c, err := pref.Sum(data)
		if err != nil {
			return nil, err
		}
		return NewBlockWithCid(data, c)
	}

	if pref.KeyType != 1 {
		return nil, fmt.Errorf("keytype must be 1")
	}

	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	public := secretbox.Seal(nonce[:], data, &nonce, &key)

	cid1, err := cid.NewPrefixV1(cid.Raw, pref.MhType).Sum(public)
	if err != nil {
		return nil, err
	}

	cid4 := cid.NewCidV4(pref.Codec, pref.KeyType, key[:], cid1.Hash())

	return &CryptoBlock{
		cid:    cid4,
		data:   data,
		public: public,
	}, nil
}

// NewAutoDecryptedBlock creates a new block from encrypted data and a cid.
func NewAutoDecryptedBlock(public []byte, c *cid.Cid) (Block, error) {
	if c.Prefix().Version != 4 {
		return NewBlockWithCid(public, c)
	}

	if c.KeyType() != 1 {
		return nil, fmt.Errorf("keytype must be 1")
	}

	if len(c.SecretKey()) != 32 {
		return nil, errors.New("wrong key length")
	}

	if len(public) < 24+secretbox.Overhead {
		return nil, errors.New("ciphertext too short")
	}

	var key [32]byte
	copy(key[:], c.SecretKey())
	var nonce [24]byte
	copy(nonce[:], public[:24])
	data, ok := secretbox.Open(nil, public[24:], &nonce, &key)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return &CryptoBlock{
		cid:    c,
		data:   data,
		public: public,
	}, nil
}

// Multihash returns the hash contained in the block CID.
func (b *CryptoBlock) Multihash() mh.Multihash {
	return b.cid.Hash()
}

// RawData returns the block raw contents as a byte slice.
func (b *CryptoBlock) RawData() []byte {
	return b.data
}

// Cid returns the content identifier of the block.
func (b *CryptoBlock) Cid() *cid.Cid {
	return b.cid
}

// String provides a human-readable representation of the block CID.
func (b *CryptoBlock) String() string {
	return fmt.Sprintf("[CryptoBlock %s]", b.Cid())
}

// Loggable returns a go-log loggable item.
func (b *CryptoBlock) Loggable() map[string]interface{} {
	return map[string]interface{}{
		"cryptoBlock": b.Cid().String(),
	}
}

func (b *CryptoBlock) ToPublic() (Block, error) {
	return NewBlockWithCid(b.public, b.cid.ToPublic())
}
