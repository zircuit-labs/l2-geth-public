# Build definitions for Zircuit L2geth project

target "image-l2geth" {
    context = "."
    dockerfile = "./build/l2geth.Dockerfile"
    tags = ["l2geth-public:latest"]
}
