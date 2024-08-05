package attest

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/go-tpm-keyfiles/template"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

var (
	ECCSRK_H2_Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
	ECCSAK_H2_Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
)

type Attestation struct {
	Public            *tpm2.TPMTPublic
	Signer            *tpm2.TPMTPublic
	CreateData        []byte
	CreateAttestation []byte
	CreateSignature   []byte
}

type SignedSSHPubkey struct {
	SSHPubkey ssh.PublicKey
	Signature *tpm2.TPMTSignature
}

// All parameters here
type AttestationParameters struct {
	// Not serialized
	Handle      *tpm2.NamedHandle
	Host        string
	User        string
	EK          *tpm2.TPMTPublic
	AK          *Attestation
	TPMBoundKey *Attestation
}

func (a *AttestationParameters) MarshalJSON() ([]byte, error) {
	// Do we need this?
	// "ak_signer":            tpm2.Marshal(a.AK.Signer),
	return json.Marshal(map[string][]byte{
		"ek":                         tpm2.Marshal(a.EK),
		"host":                       []byte(a.Host),
		"user":                       []byte(a.User),
		"ak_public":                  tpm2.Marshal(a.AK.Public),
		"ak_createdata":              a.AK.CreateData,
		"ak_createattestation":       a.AK.CreateAttestation,
		"ak_createsignature":         a.AK.CreateSignature,
		"tpmbound_public":            tpm2.Marshal(a.TPMBoundKey.Public),
		"tpmbound_signer":            tpm2.Marshal(a.TPMBoundKey.Signer),
		"tpmbound_createdata":        a.TPMBoundKey.CreateData,
		"tpmbound_createattestation": a.TPMBoundKey.CreateAttestation,
		"tpmbound_createsignature":   a.TPMBoundKey.CreateSignature,
	})
}

func (a *AttestationParameters) UnmarshalJSON(b []byte) error {
	var obj map[string][]byte
	err := json.Unmarshal(b, &obj)
	if err != nil {
		return err
	}
	ek, err := tpm2.Unmarshal[tpm2.TPMTPublic](obj["ek"])
	if err != nil {
		return err
	}
	a.EK = ek

	a.Host = string(obj["host"])
	a.User = string(obj["user"])

	akpub, err := tpm2.Unmarshal[tpm2.TPMTPublic](obj["ak_public"])
	if err != nil {
		return err
	}
	a.AK = &Attestation{
		Public:            akpub,
		CreateData:        obj["ak_createdata"],
		CreateAttestation: obj["ak_createattestation"],
		CreateSignature:   obj["ak_createsignature"],
	}

	tpmboundpub, err := tpm2.Unmarshal[tpm2.TPMTPublic](obj["tpmbound_public"])
	if err != nil {
		return err
	}

	tpmboundpubsigner, err := tpm2.Unmarshal[tpm2.TPMTPublic](obj["tpmbound_signer"])
	if err != nil {
		return err
	}

	a.TPMBoundKey = &Attestation{
		Public:            tpmboundpub,
		Signer:            tpmboundpubsigner,
		CreateData:        obj["tpmbound_createdata"],
		CreateAttestation: obj["tpmbound_createattestation"],
		CreateSignature:   obj["tpmbound_createsignature"],
	}
	return nil
}

func (a *AttestationParameters) Flush(rwc transport.TPMCloser) {
	keyfile.FlushHandle(rwc, a.Handle.Handle)
}

func (a *AttestationParameters) GetSecret(rwc transport.TPMCloser, ch *EncryptedCredential) ([]byte, error) {
	akHandle, _, err := getAK(rwc)
	if err != nil {
		return nil, err
	}
	defer keyfile.FlushHandle(rwc, akHandle)

	ekHandle, _, err := ReadEKCert(rwc)
	if err != nil {
		return nil, err
	}
	defer keyfile.FlushHandle(rwc, ekHandle.Handle)

	ac, err := tpm2.ActivateCredential{
		ActivateHandle: akHandle,
		KeyHandle: tpm2.AuthHandle{
			Handle: ekHandle.Handle,
			Name:   ekHandle.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, EkPolicy),
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: ch.Credential},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: ch.Secret},
	}.Execute(rwc)
	if err != nil {
		return nil, err
	}
	return ac.CertInfo.Buffer, nil
}

func getAK(rwc transport.TPMCloser) (*tpm2.NamedHandle, *tpm2.CreatePrimaryResponse, error) {
	akRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(ECCSAK_H2_Template),
	}.Execute(rwc)
	if err != nil {
		return nil, nil, nil
	}
	return &tpm2.NamedHandle{
		Handle: akRsp.ObjectHandle,
		Name:   akRsp.Name,
	}, akRsp, nil
}

func NewAttestationParameters(rwc transport.TPMCloser, tpmkey *keyfile.TPMKey, rsp *tpm2.CreateResponse) (*AttestationParameters, error) {
	akHandle, AKrsp, err := getAK(rwc)
	if err != nil {
		return nil, err
	}

	inScheme := tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgECDSA,
		Details: tpm2.NewTPMUSigScheme(
			tpm2.TPMAlgECDSA,
			&tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			},
		),
	}

	ccRsp, err := tpm2.CertifyCreation{
		SignHandle: tpm2.AuthHandle{
			Handle: akHandle.Handle,
			Name:   akHandle.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: akHandle.Handle,
			Name:   akHandle.Name,
		},
		CreationHash:   AKrsp.CreationHash,
		CreationTicket: AKrsp.CreationTicket,
		InScheme:       inScheme,
	}.Execute(rwc)
	if err != nil {
		return nil, err
	}

	sess := keyfile.NewTPMSession(rwc)
	keyhandle, parenthandle, err := keyfile.LoadKey(sess, tpmkey, []byte(nil))
	if err != nil {
		return nil, err
	}

	tpmBoundCCRsp, err := tpm2.CertifyCreation{
		SignHandle: tpm2.AuthHandle{
			Handle: akHandle.Handle,
			Name:   akHandle.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: keyhandle.Handle,
			Name:   keyhandle.Name,
		},
		CreationHash:   rsp.CreationHash,
		CreationTicket: rsp.CreationTicket,
		InScheme:       inScheme,
	}.Execute(rwc)
	if err != nil {
		return nil, err
	}

	// Flush everything now
	keyfile.FlushHandle(rwc, keyhandle)
	keyfile.FlushHandle(rwc, parenthandle)
	keyfile.FlushHandle(rwc, akHandle)

	akpub, err := AKrsp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	keypub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	ekHandle, ek, err := ReadEKCert(rwc)
	if err != nil {
		return nil, err
	}
	keyfile.FlushHandle(rwc, ekHandle)

	return &AttestationParameters{
		EK:     ek,
		Handle: akHandle,
		AK: &Attestation{
			Public:            akpub,
			Signer:            akpub,
			CreateData:        tpm2.Marshal(AKrsp.CreationData),
			CreateAttestation: tpm2.Marshal(ccRsp.CertifyInfo),
			CreateSignature:   tpm2.Marshal(ccRsp.Signature),
		},
		TPMBoundKey: &Attestation{
			Public:            keypub,
			Signer:            akpub,
			CreateData:        tpm2.Marshal(rsp.CreationData),
			CreateAttestation: tpm2.Marshal(tpmBoundCCRsp.CertifyInfo),
			CreateSignature:   tpm2.Marshal(tpmBoundCCRsp.Signature),
		},
	}, nil
}

// ECC coordinates need to maintain a specific size based on the curve, so we pad the front with zeros.
// This is particularly an issue for NIST-P521 coordinates, as they are frequently missing their first byte.
func eccIntToBytes(curve elliptic.Curve, i *big.Int) []byte {
	bytes := i.Bytes()
	curveBytes := (curve.Params().BitSize + 7) / 8
	return append(make([]byte, curveBytes-len(bytes)), bytes...)
}

func ReadEKCert(rwc transport.TPMCloser) (*tpm2.NamedHandle, *tpm2.TPMTPublic, error) {
	// TODO: Figure out EK from nvread
	// rsp, err := tpm2.NVReadPublic{
	// 	NVIndex: tpm2.TPMHandle(0x01C00002),
	// }.Execute(rwc)
	// if err == nil {
	// 	nvcont, err := rsp.NVPublic.Contents()
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	buf := make([]byte, nvcont.DataSize())
	// 	nvrsp, err := tpm2.NVRead{
	// 		AuthHandle: tpm2.TPMHandle(0x01C00002),
	// 		NVIndex:    tpm2.TPMHandle(0x01C00002),
	// 		Size: nvcont.DataSize().
	// 	}.Execute(rwc)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	return nil, nil
	// }

	createRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(rwc)
	if err != nil {
		return nil, nil, err
	}
	tpublic, err := createRsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	return &tpm2.NamedHandle{
		Handle: createRsp.ObjectHandle,
		Name:   createRsp.Name,
	}, tpublic, err
}

func EkPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}

func (aa *Attestation) VerifyCreation(restricted bool) (bool, error) {
	attest2b, err := tpm2.Unmarshal[tpm2.TPM2BAttest](aa.CreateAttestation)
	if err != nil {
		return false, err
	}
	attest, err := attest2b.Contents()
	if err != nil {
		return false, err
	}
	if attest.Type != tpm2.TPMSTAttestCreation {
		return false, fmt.Errorf("doesn't attest for creation")
	}
	h, err := aa.Public.NameAlg.Hash()
	if err != nil {
		return false, err
	}
	hh := h.New()
	// Strip length prefix as we use tpm2.Marshal
	hh.Write(aa.CreateData[2:])
	creation, err := attest.Attested.Creation()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(creation.CreationHash.Buffer, hh.Sum(nil)) {
		return false, fmt.Errorf("incorrect public key")
	}

	if attest.Magic != tpm2.TPMGeneratedValue {
		return false, fmt.Errorf("key not created on tpm")
	}

	if !aa.Public.ObjectAttributes.FixedTPM {
		return false, fmt.Errorf("AK is exportable")
	}

	if !aa.Public.ObjectAttributes.Restricted && restricted {
		return false, fmt.Errorf("key is not limited to attestation")
	}

	if !aa.Public.ObjectAttributes.FixedParent || !aa.Public.ObjectAttributes.SensitiveDataOrigin {
		return false, fmt.Errorf("key is not bound to TPM")
	}

	name, err := tpm2.ObjectName(aa.Public)
	if err != nil {
		return false, err
	}

	if !bytes.Equal(name.Buffer, creation.ObjectName.Buffer) {
		return false, fmt.Errorf("createion attestation is for another key")
	}

	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](aa.CreateSignature)
	if err != nil {
		return false, err
	}

	var signer *tpm2.TPMTPublic
	if aa.Signer == nil {
		signer = aa.Public
	} else {
		signer = aa.Signer
	}

	return VerifySignature(signer, aa.CreateAttestation[2:], sig)
}

func (a *AttestationParameters) Verify() (bool, error) {
	// Caller needs to check if the ssh key matches the tpmbound.public
	ok, err := a.AK.VerifyCreation(true)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	// Verify that the AK we trust is the same signer on the TPMBoundKey
	akpubname, err := tpm2.ObjectName(a.AK.Public)
	if err != nil {
		return false, err
	}
	tpmboundpubname, err := tpm2.ObjectName(a.TPMBoundKey.Signer)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(akpubname.Buffer, tpmboundpubname.Buffer) {
		return false, fmt.Errorf("AK is not the signer of the TPM Bound key")
	}

	// This is most likely not a restricted key
	ok, err = a.TPMBoundKey.VerifyCreation(false)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return true, nil
}

func (a *AttestationParameters) CreateChallenge(secret []byte) (*EncryptedCredential, error) {
	attest2b, err := tpm2.Unmarshal[tpm2.TPM2BAttest](a.AK.CreateAttestation)
	if err != nil {
		return nil, err
	}
	attest, err := attest2b.Contents()
	if err != nil {
		return nil, err
	}

	creat, err := attest.Attested.Creation()
	if err != nil {
		return nil, err
	}

	cred, encSecret, err := credentialWrapping(creat.ObjectName, a.EK, secret)
	if err != nil {
		return nil, err
	}

	return &EncryptedCredential{
		Credential: cred,
		Secret:     encSecret,
	}, nil
}

type EncryptedCredential struct {
	Credential []byte
	Secret     []byte
	OIDC       string
	Nonce      string
}

func createECCSeed(pub *tpm2.TPMTPublic, label string) (seed, encryptedSeed []byte, err error) {
	curve := elliptic.P256()

	// We need access to the values so we don't use ecdh to generate the key
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x.Bytes()),
			Y:     new(big.Int).SetBytes(y.Bytes()),
		},
		D: new(big.Int).SetBytes(priv),
	}
	privKeyECDH, err := privKey.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating ecdh key: %v", err)
	}

	ecc, err := pub.Unique.ECC()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting ECC values from public: %v", err)
	}

	if len(ecc.X.Buffer) == 0 || len(ecc.Y.Buffer) == 0 {
		return nil, nil, fmt.Errorf("public TPM2TPublic does not have a valid ECC public key")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(ecc.X.Buffer),
		Y:     new(big.Int).SetBytes(ecc.Y.Buffer),
	}

	pubkeyECDH, err := pubKey.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting ECDH from produced public key: %v", err)
	}

	z, _ := privKeyECDH.ECDH(pubkeyECDH)
	xBytes := eccIntToBytes(curve, x)
	seed = tpm2.KDFe(
		crypto.SHA256,
		z,
		label,
		xBytes,
		eccIntToBytes(curve, pubKey.X),
		crypto.SHA256.Size()*8)

	encryptedSeed = tpm2.Marshal(tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, len(x.Bytes())))},
		Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, len(y.Bytes())))},
	})

	return seed, encryptedSeed, err
}

func credentialWrapping(aik tpm2.TPM2BName, pub *tpm2.TPMTPublic, secret []byte) ([]byte, []byte, error) {
	var err error
	var seed []byte
	var encryptedSeed []byte

	switch pub.Type {
	case tpm2.TPMAlgECC:
		seed, encryptedSeed, err = createECCSeed(pub, "IDENTITY")
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("only support ECC parents for import wrapping: %v", pub.Type)
	}

	// AES symm encryption key
	symmetricKey := tpm2.KDFa(crypto.SHA256, seed, "STORAGE", aik.Buffer, nil, 128)

	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, err
	}

	cv := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: secret})

	encryptedSecret := make([]byte, len(cv))

	// // The TPM spec requires an all-zero IV.
	iv := make([]byte, len(symmetricKey))
	cipher.NewCFBEncrypter(c, iv).XORKeyStream(encryptedSecret, cv)

	macKey := tpm2.KDFa(
		crypto.SHA256,
		seed,
		"INTEGRITY",
		/*contextU=*/ nil,
		/*contextV=*/ nil,
		crypto.SHA256.Size()*8)

	mac := hmac.New(func() hash.Hash { return crypto.SHA256.New() }, macKey)
	mac.Write(encryptedSecret)
	mac.Write(aik.Buffer)

	hmacSum := mac.Sum(nil)

	idObject := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: hmacSum})
	idObject = append(idObject, encryptedSecret...)

	return idObject, encryptedSeed, err
}

func CreateChallenge(ap *AttestationParameters) (*EncryptedCredential, error) {
	sec := make([]byte, 32)
	io.ReadFull(rand.Reader, sec)
	return ap.CreateChallenge(sec)
}

func CreateSRK(rwc transport.TPMCloser, hier tpm2.TPMHandle, ownerAuth []byte) (*tpm2.AuthHandle, *tpm2.TPMTPublic, *tpm2.CreatePrimaryResponse, error) {
	public := tpm2.New2B(ECCSRK_H2_Template)

	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: hier, Auth: tpm2.PasswordAuth(ownerAuth),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: public,
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err := srk.Execute(rwc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed creating primary key: %v", err)
	}

	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed getting srk public content: %v", err)
	}

	return &tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, rsp, nil
}

func GetECDSAFromTPMTPublic(pub *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	pk, err := template.FromTPMPublicToPubkey(pub)
	if err != nil {
		return nil, fmt.Errorf("not a valid private key")
	}
	switch p := pk.(type) {
	case *ecdsa.PublicKey:
		return p, nil
	default:
		return nil, fmt.Errorf("not a ecdsa key")
	}
}

func VerifySignature(pub *tpm2.TPMTPublic, b []byte, sig *tpm2.TPMTSignature) (bool, error) {
	pk, err := template.FromTPMPublicToPubkey(pub)
	if err != nil {
		return false, fmt.Errorf("not a valid private key")
	}
	switch p := pk.(type) {
	case *ecdsa.PublicKey:
		eccsig, err := sig.Signature.ECDSA()
		if err != nil {
			return false, err
		}
		h, err := eccsig.Hash.Hash()
		if err != nil {
			return false, err
		}
		sh := h.New()
		sh.Write(b)
		return ecdsa.Verify(p, sh.Sum(nil), new(big.Int).SetBytes(eccsig.SignatureR.Buffer), new(big.Int).SetBytes(eccsig.SignatureS.Buffer)), nil
	default:
		// TODO: Implement RSA
		return false, fmt.Errorf("not supported")
	}
}
