# Development purposes
start:
	go build -gcflags="all=-N -l" -o /bin/app -mod vendor cmd/authentication/main.go && /go/bin/dlv --listen=:40000 --headless=true --api-version=2 --accept-multiclient exec /bin/app

update-mocks:
	go get github.com/vektra/mockery/v2/.../
	ls -d */  | grep -v svc | grep -v vendor | xargs -n1 -I{} mockery --dir {} --all --inpackage --note "To update this file, run 'make update-mocks'"

.PHONY: start update-mocks
