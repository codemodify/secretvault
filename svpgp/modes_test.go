package svpgp

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	s = strings.Join(strings.Fields(s), "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// RFC 7253, appendix A: the 16 sample tuples for AES-128 with 128-bit tags.
func TestOCBMatchesRFC7253SampleResults(t *testing.T) {
	key := unhex(t, "000102030405060708090A0B0C0D0E0F")
	vectors := []struct{ n, a, p, c string }{
		{"BBAA99887766554433221100", "", "", "785407BFFFC8AD9EDCC5520AC9111EE6"},
		{"BBAA99887766554433221101", "0001020304050607", "0001020304050607", "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009"},
		{"BBAA99887766554433221102", "0001020304050607", "", "81017F8203F081277152FADE694A0A00"},
		{"BBAA99887766554433221103", "", "0001020304050607", "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9"},
		{"BBAA99887766554433221104", "000102030405060708090A0B0C0D0E0F", "000102030405060708090A0B0C0D0E0F", "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358"},
		{"BBAA99887766554433221105", "000102030405060708090A0B0C0D0E0F", "", "8CF761B6902EF764462AD86498CA6B97"},
		{"BBAA99887766554433221106", "", "000102030405060708090A0B0C0D0E0F", "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D"},
		{"BBAA99887766554433221107", "000102030405060708090A0B0C0D0E0F1011121314151617", "000102030405060708090A0B0C0D0E0F1011121314151617", "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F"},
		{"BBAA99887766554433221108", "000102030405060708090A0B0C0D0E0F1011121314151617", "", "6DC225A071FC1B9F7C69F93B0F1E10DE"},
		{"BBAA99887766554433221109", "", "000102030405060708090A0B0C0D0E0F1011121314151617", "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF"},
		{"BBAA9988776655443322110A", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240"},
		{"BBAA9988776655443322110B", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "", "FE80690BEE8A485D11F32965BC9D2A32"},
		{"BBAA9988776655443322110C", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF"},
		{"BBAA9988776655443322110D", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60"},
		{"BBAA9988776655443322110E", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "", "C5CD9D1850C141E358649994EE701B68"},
		{"BBAA9988776655443322110F", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479"},
	}
	block, _ := aes.NewCipher(key)
	aead, err := newOCB(block, 12, 16)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range vectors {
		n, a, p, c := unhex(t, v.n), unhex(t, v.a), unhex(t, v.p), unhex(t, v.c)
		if got := aead.Seal(nil, n, p, a); !bytes.Equal(got, c) {
			t.Errorf("vector %d: sealed\n %X\nwant\n %X", i, got, c)
		}
		got, err := aead.Open(nil, n, c, a)
		if err != nil || !bytes.Equal(got, p) {
			t.Errorf("vector %d: open = %X, %v", i, got, err)
		}
		for j := range c {
			bad := bytes.Clone(c)
			bad[j] ^= 0x01
			if _, err := aead.Open(nil, n, bad, a); err == nil {
				t.Errorf("vector %d: a flipped bit in byte %d was accepted", i, j)
			}
		}
		if len(a) > 0 {
			if _, err := aead.Open(nil, n, c, a[1:]); err == nil {
				t.Errorf("vector %d: changed associated data was accepted", i)
			}
		}
		// In place, as cipher.AEAD allows.
		buf := bytes.Clone(c)
		if got, err := aead.Open(buf[:0], n, buf, a); err != nil || !bytes.Equal(got, p) {
			t.Errorf("vector %d: in-place open = %X, %v", i, got, err)
		}
	}
}

func TestOCBMatchesRFC7253NinetySixBitTagSample(t *testing.T) {
	block, _ := aes.NewCipher(unhex(t, "0F0E0D0C0B0A09080706050403020100"))
	aead, err := newOCB(block, 12, 12)
	if err != nil {
		t.Fatal(err)
	}
	n := unhex(t, "BBAA9988776655443322110D")
	a := unhex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627")
	want := unhex(t, "1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1A0124B0A55BAE884ED93481529C76B6AD0C515F4D1CDD4FDAC4F02AA")
	if got := aead.Seal(nil, n, a, a); !bytes.Equal(got, want) {
		t.Fatalf("sealed %X, want %X", got, want)
	}
}

// RFC 7253, appendix A: the iterated test over every parameter set, which
// covers many lengths of plaintext and associated data.
func TestOCBMatchesRFC7253IteratedOutputs(t *testing.T) {
	outputs := []struct {
		keyLen, tagLen int
		want           string
	}{
		{16, 16, "67E944D23256C5E0B6C61FA22FDF1EA2"},
		{24, 16, "F673F2C3E7174AAE7BAE986CA9F29E17"},
		{32, 16, "D90EB8E9C977C88B79DD793D7FFA161C"},
		{16, 12, "77A3D8E73589158D25D01209"},
		{24, 12, "05D56EAD2752C86BE6932C5E"},
		{32, 12, "5458359AC23B0CBA9E6330DD"},
		{16, 8, "192C9B7BD90BA06A"},
		{24, 8, "0066BC6E0EF34E24"},
		{32, 8, "7D4EA5D445501CBE"},
	}
	for _, o := range outputs {
		key := make([]byte, o.keyLen)
		key[len(key)-1] = byte(o.tagLen * 8)
		block, _ := aes.NewCipher(key)
		aead, err := newOCB(block, 12, o.tagLen)
		if err != nil {
			t.Fatal(err)
		}
		nonce := func(i int) []byte {
			n := make([]byte, 12)
			n[8], n[9], n[10], n[11] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
			return n
		}
		var c []byte
		for i := 0; i < 128; i++ {
			s := make([]byte, i)
			c = aead.Seal(c, nonce(3*i+1), s, s)
			c = aead.Seal(c, nonce(3*i+2), s, nil)
			c = aead.Seal(c, nonce(3*i+3), nil, s)
		}
		got := aead.Seal(nil, nonce(385), nil, c)
		if want := unhex(t, o.want); !bytes.Equal(got, want) {
			t.Errorf("AES-%d, %d-bit tag: %X, want %X", o.keyLen*8, o.tagLen*8, got, want)
		}
	}
}

// The ten AES-128 test vectors from the EAX paper (Bellare, Rogaway and
// Wagner, 2004), each ciphertext followed by its tag.
func TestEAXMatchesThePublishedVectors(t *testing.T) {
	vectors := []struct{ msg, key, nonce, header, cipher string }{
		{"", "233952DEE4D5ED5F9B9C6D6FF80FF478", "62EC67F9C3A4A407FCB2A8C49031A8B3", "6BFB914FD07EAE6B", "E037830E8389F27B025A2D6527E79D01"},
		{"F7FB", "91945D3F4DCBEE0BF45EF52255F095A4", "BECAF043B0A23D843194BA972C66DEBD", "FA3BFD4806EB53FA", "19DD5C4C9331049D0BDAB0277408F67967E5"},
		{"1A47CB4933", "01F74AD64077F2E704C0F60ADA3DD523", "70C3DB4F0D26368400A10ED05D2BFF5E", "234A3463C1264AC6", "D851D5BAE03A59F238A23E39199DC9266626C40F80"},
		{"481C9E39B1", "D07CF6CBB7F313BDDE66B727AFD3C5E8", "8408DFFF3C1A2B1292DC199E46B7D617", "33CCE2EABFF5A79D", "632A9D131AD4C168A4225D8E1FF755939974A7BEDE"},
		{"40D0C07DA5E4", "35B6D0580005BBC12B0587124557D2C2", "FDB6B06676EEDC5C61D74276E1F8E816", "AEB96EAEBE2970E9", "071DFE16C675CB0677E536F73AFE6A14B74EE49844DD"},
		{"4DE3B35C3FC039245BD1FB7D", "BD8E6E11475E60B268784C38C62FEB22", "6EAC5C93072D8E8513F750935E46DA1B", "D4482D1CA78DCE0F", "835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F"},
		{"8B0A79306C9CE7ED99DAE4F87F8DD61636", "7C77D6E813BED5AC98BAA417477A2E7D", "1A8C98DCD73D38393B2BF1569DEEFC19", "65D2017990D62528", "02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2"},
		{"1BDA122BCE8A8DBAF1877D962B8592DD2D56", "5FFF20CAFAB119CA2FC73549E20F5B0D", "DDE59B97D722156D4D9AFF2BC7559826", "54B9F04E6A09189A", "2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A"},
		{"6CF36720872B8513F6EAB1A8A44438D5EF11", "A4A4782BCFFD3EC5E7EF6D8C34A56123", "B781FCF2F75FA5A8DE97A9CA48E522EC", "899A175897561D7E", "0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700"},
		{"CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7", "8395FCF1E95BEBD697BD010BC766AAC3", "22E7ADD93CFC6393C57EC0B3C17D6B44", "126735FCC320D25A", "CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E"},
	}
	for i, v := range vectors {
		block, _ := aes.NewCipher(unhex(t, v.key))
		aead, err := newEAX(block)
		if err != nil {
			t.Fatal(err)
		}
		m, n, h, c := unhex(t, v.msg), unhex(t, v.nonce), unhex(t, v.header), unhex(t, v.cipher)
		if got := aead.Seal(nil, n, m, h); !bytes.Equal(got, c) {
			t.Errorf("vector %d: sealed %X, want %X", i, got, c)
		}
		if got, err := aead.Open(nil, n, c, h); err != nil || !bytes.Equal(got, m) {
			t.Errorf("vector %d: open = %X, %v", i, got, err)
		}
		for j := range c {
			bad := bytes.Clone(c)
			bad[j] ^= 0x80
			if _, err := aead.Open(nil, n, bad, h); err == nil {
				t.Errorf("vector %d: a flipped bit in byte %d was accepted", i, j)
			}
		}
		if _, err := aead.Open(nil, n, c, h[1:]); err == nil {
			t.Errorf("vector %d: a changed header was accepted", i)
		}
	}
}

// RFC 3394, section 4: every KEK and key data size.
func TestKeyWrapMatchesRFC3394(t *testing.T) {
	vectors := []struct{ kek, data, wrapped string }{
		{"000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
	}
	for i, v := range vectors {
		kek, data, wrapped := unhex(t, v.kek), unhex(t, v.data), unhex(t, v.wrapped)
		got, err := keyWrap(kek, data)
		if err != nil || !bytes.Equal(got, wrapped) {
			t.Errorf("vector %d: wrap = %X, %v", i, got, err)
		}
		back, err := keyUnwrap(kek, wrapped)
		if err != nil || !bytes.Equal(back, data) {
			t.Errorf("vector %d: unwrap = %X, %v", i, back, err)
		}
		bad := bytes.Clone(wrapped)
		bad[len(bad)-1] ^= 1
		if _, err := keyUnwrap(kek, bad); err == nil {
			t.Errorf("vector %d: a changed wrapped key was accepted", i)
		}
	}
	for _, n := range []int{0, 8, 15, 23, 31} {
		if _, err := keyUnwrap(make([]byte, 16), make([]byte, n)); err == nil {
			t.Errorf("unwrapping %d bytes did not fail", n)
		}
	}
}

func TestCFBRoundTripsAndMatchesTheStandardMode(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	iv := bytes.Repeat([]byte{7}, 16)
	msg := bytes.Repeat([]byte("the quick brown fox "), 10)
	// Encrypting in uneven pieces must give the same stream as all at once.
	whole := make([]byte, len(msg))
	newCFB(block, iv, false).XORKeyStream(whole, msg)
	pieces := make([]byte, len(msg))
	enc := newCFB(block, iv, false)
	for off, step := 0, 1; off < len(msg); off, step = off+step, step+3 {
		end := min(off+step, len(msg))
		enc.XORKeyStream(pieces[off:end], msg[off:end])
	}
	if !bytes.Equal(whole, pieces) {
		t.Fatal("piecewise CFB differs from whole-message CFB")
	}
	// The first block is E(IV) xor P, by definition.
	var first [16]byte
	block.Encrypt(first[:], iv)
	for i := range first {
		if whole[i] != first[i]^msg[i] {
			t.Fatal("first CFB block is wrong")
		}
	}
	back := bytes.Clone(whole)
	newCFB(block, iv, true).XORKeyStream(back, back)
	if !bytes.Equal(back, msg) {
		t.Fatal("CFB did not round-trip in place")
	}
}
