.PHONY: install clean package ltvalues

DIST_ROOT=dist
KUBE_INSTALL := $(shell command -v kubectl 2> /dev/null)
HELM_INSTALL := $(shell command -v helm 2> /dev/null)

SUB_CHARTS := $(shell ls ./charts)

all: package

check:
ifndef KUBE_INSTALL
    $(error "kubectl is not available please install from https://kubernetes.io/")
endif
ifndef HELM_INSTALL
    $(error "helm is not available please install from https://github.com/kubernetes/helm")
endif

.init:
	helm init
	touch $@

package: check .init
	# Temporary while we wait for changes to be merged upstream
	helm repo add mattermost-mysqlha https://releases.mattermost.com/helm/mysqlha
	mkdir -p dist
	rm -f ./charts/*.tgz
	helm package ./charts/* -d ./charts
	helm dep up mattermost-helm
	helm package mattermost-helm -d $(DIST_ROOT)

clean:
	rm -rf $(DIST_ROOT)
	rm -f ./charts/*.tgz

install: check
	helm install dist/mattermost-helm*.*

ltvalues:
	cp ../platform-private/kubernetes/values_loadtest.yaml ./values.yaml
