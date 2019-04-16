module github.com/hortonworks/dp-cli-common/apikeyauth

go 1.12

require (
	github.com/Sirupsen/logrus v1.0.6
	github.com/go-openapi/runtime v0.19.0
	github.com/go-openapi/strfmt v0.18.0
	github.com/hortonworks/dp-cli-common/utils v0.0.0-20181126104958-228e0c1c270f
	golang.org/x/crypto v0.0.0-20190320223903-b7391e95e576
)

replace github.com/hortonworks/dp-cli-common/utils => ../utils
