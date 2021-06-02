package schnorr

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec"

	"github.com/stretchr/testify/require"
)

func TestSignAndVerify(t *testing.T) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pub, _ := hex.DecodeString(test.pubKey)
			msg, _ := hex.DecodeString(test.msg)
			sig, _ := hex.DecodeString(test.sig)

			var message [32]byte
			copy(message[:], msg)

			var pubkey [32]byte
			copy(pubkey[:], pub)

			if test.privKey != "" {
				aux, _ := hex.DecodeString(test.aux)
				privKey, _ := hex.DecodeString(test.privKey)

				p, P := btcec.PrivKeyFromBytes(Curve, privKey)
				require.Equal(t, pub, pointToBytes(P))

				var auxiliary [32]byte
				copy(auxiliary[:], aux)

				signature, err := Sign(p, message, auxiliary)
				require.NoError(t, err)
				require.Equal(t, signature[:], sig)
			}

			var signature [64]byte
			copy(signature[:], sig)

			res, err := Verify(pubkey, message, signature)
			require.Equal(t, res, test.expectedVerifyRes)
			if test.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTaggedHash(t *testing.T) {
	h := taggedHash("SampleTagName", []byte("Input data"))
	require.Equal(t, "4c55df56134d7f37d3295850659f2e3729128c969b3386ec661feb7dfe29a99c", hex.EncodeToString(h))
}

// tests is a set of test vectors from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
var tests = []struct {
	name              string
	privKey           string
	pubKey            string
	aux               string
	msg               string
	sig               string
	expectedVerifyRes bool
	expectErr         bool
	comment           string
}{
	{
		name:              "0",
		privKey:           "0000000000000000000000000000000000000000000000000000000000000003",
		pubKey:            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		aux:               "0000000000000000000000000000000000000000000000000000000000000000",
		msg:               "0000000000000000000000000000000000000000000000000000000000000000",
		sig:               "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
		expectedVerifyRes: true,
	},
	{
		name:              "1",
		privKey:           "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
		pubKey:            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		aux:               "0000000000000000000000000000000000000000000000000000000000000001",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
		expectedVerifyRes: true,
	},
	{
		name:              "2",
		privKey:           "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
		pubKey:            "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
		aux:               "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
		msg:               "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
		sig:               "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
		expectedVerifyRes: true,
	},
	{
		name:              "3",
		privKey:           "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
		pubKey:            "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
		aux:               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		msg:               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		sig:               "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
		expectedVerifyRes: true,
	},
	{
		name:              "4",
		pubKey:            "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
		msg:               "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
		sig:               "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
		expectedVerifyRes: true,
	},
	{
		name:              "5",
		pubKey:            "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
		expectedVerifyRes: false,
		expectErr:         true,
		comment:           "public key not on the curve",
	},
	{
		name:              "6",
		pubKey:            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
		expectedVerifyRes: false,
		expectErr:         true,
		comment:           "has_even_y(R) is false",
	},
	{
		name:              "7",
		pubKey:            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
		expectedVerifyRes: false,
		expectErr:         true,
		comment:           "negated message",
	},
	{
		name:              "8",
		pubKey:            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
		expectedVerifyRes: false,
		expectErr:         true,
		comment:           "negated s value",
	},
	{
		name:              "9",
		pubKey:            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
		expectedVerifyRes: false,
		expectErr:         true,
		comment:           "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0",
	},
	{
		name:              "10",
		pubKey:            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
		expectedVerifyRes: false,
		expectErr:         true,
		comment:           "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1",
	},
	{
		name:              "11",
		pubKey:            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
		expectedVerifyRes: false,
		expectErr:         true,
		comment:           "sig[0:32] is not an X coordinate on the curve",
	},
	{
		name:              "12",
		pubKey:            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
		expectedVerifyRes: false,
		expectErr:         true,
		comment:           "sig[0:32] is equal to field size",
	},
	{
		name:              "13",
		pubKey:            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
		msg:               "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
		sig:               "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
		expectedVerifyRes: false,
		expectErr:         true,
		comment:           "public key is not a valid X coordinate because it exceeds the field size\n",
	},
}
