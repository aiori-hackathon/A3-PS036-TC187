# LadderLens — PS-036 MTL vs per-record PQC signature benchmark
IMAGE      := ladderlens:latest
DOCKERFILE := docker/Dockerfile
ALG        := SLH-DSA-SHA2-128s-MTL-SHA2-128

.PHONY: build smoke shell clean

## build: create the pinned benchmark image (OpenSSL 3.6.0, liboqs 0.16.0, MTL v1.3.1)
build:
	docker build -f $(DOCKERFILE) -t $(IMAGE) .

## smoke: 1A proof — sign + verify one message with $(ALG) and print measured sizes
smoke:
	docker run --rm -v "$(CURDIR)":/work $(IMAGE) /bin/sh /work/scripts/smoke_test.sh "$(ALG)"

## shell: interactive shell in the image with the repo mounted at /work
shell:
	docker run --rm -it -v "$(CURDIR)":/work $(IMAGE)

clean:
	-docker rmi $(IMAGE)
