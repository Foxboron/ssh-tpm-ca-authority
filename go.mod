module github.com/foxboron/ssh-tpm-ca-authority

go 1.22.4

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240620184055-b891af1cbc88
	github.com/foxboron/ssh-tpm-agent v0.5.0
	github.com/google/go-tpm v0.9.2-0.20240625170440-991b038b62b6
	github.com/google/go-tpm-tools v0.4.4
	golang.org/x/crypto v0.24.0
)

require golang.org/x/sys v0.21.0 // indirect
