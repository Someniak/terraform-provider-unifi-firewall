BINARY=terraform-provider-unifi
VERSION=0.5.0
OS_ARCH=darwin_arm64

default: build

# Build for current platform
build:
	go build -o ${BINARY} ./src

# Install locally for development
install: build
	mkdir -p ~/.terraform.d/plugins/registry.terraform.io/someniak/unifi/${VERSION}/${OS_ARCH}
	mv ${BINARY} ~/.terraform.d/plugins/registry.terraform.io/someniak/unifi/${VERSION}/${OS_ARCH}/

# Release builds for all platforms
release:
	GOOS=darwin GOARCH=arm64 go build -o bin/${VERSION}/darwin_arm64/${BINARY} ./src
	GOOS=darwin GOARCH=amd64 go build -o bin/${VERSION}/darwin_amd64/${BINARY} ./src
	GOOS=linux GOARCH=amd64 go build -o bin/${VERSION}/linux_amd64/${BINARY} ./src
	GOOS=linux GOARCH=arm64 go build -o bin/${VERSION}/linux_arm64/${BINARY} ./src
	GOOS=windows GOARCH=amd64 go build -o bin/${VERSION}/windows_amd64/${BINARY}.exe ./src
	cd bin && tar -czvf unifi-provider-${VERSION}.tar.gz ${VERSION}/

test-init: install
	cd examples && terraform init -upgrade

clean-init: install
	cd examples && rm -rf .terraform .terraform.lock.hcl
	cd examples && terraform init

test-plan:
	cd examples && terraform plan

test-apply:
	cd examples && terraform apply -auto-approve

# Generate documentation
generate:
	go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate -provider-name unifi -provider-dir ./src

clean:
	rm -f ${BINARY}
	rm -rf bin/
	rm -rf examples/.terraform
	rm -f examples/.terraform.lock.hcl
