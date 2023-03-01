SERVER_DIR := server
CLIENT_DIR := client
CONFIG_DIR := config
CA_DIR := ca

serve:
	go run ${SERVER_DIR}/server.go

get:
	go run ${CLIENT_DIR}/client.go

test:
	go test -coverprofile=/tmp/cover_go.out $$(go list ./... | grep -v /e2e)

gencert:
	cfssl gencert \
		-initca ${CONFIG_DIR}/ca-csr.json \
		| cfssljson -bare ca
	mv *.pem *.csr ${CONFIG_DIR}

genservercert:
	cfssl gencert \
		-ca=ca.pem \
		-ca-key=ca-key.pem \
		-config=${CONFIG_DIR}/ca-config.json \
		-profile=server \
		${CONFIG_DIR}/server-csr.json \
		| cfssljson -bare server
	mv *.pem *.csr ${CONFIG_DIR}

genclientcert:
	cfssl gencert \
		-ca=${CONFIG_DIR}/ca.pem \
		-ca-key=${CONFIG_DIR}/ca-key.pem \
		-config=${CONFIG_DIR}/ca-config.json \
		-profile=client \
		${CONFIG_DIR}/client-csr.json | cfssljson -bare client
	mv *.pem *.csr ${CONFIG_DIR}

.PHONY: client curl
	