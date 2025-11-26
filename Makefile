build:
	docker buildx bake -f build/docker-bake.hcl image-l2geth
.PHONY: build
