ARG base_img=mcr.microsoft.com/devcontainers/base:bookworm

FROM ${base_img} AS builder-install

# Dependencies for C
RUN apt-get update --fix-missing && apt-get -y upgrade && apt-get install -y --no-install-recommends \
    apt-utils \
    curl \
    cmake \
    build-essential \
    gdb \
    make \
    wget \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

RUN echo 'en_US.UTF-8 UTF-8' > /etc/locale.gen && /usr/sbin/locale-gen
RUN echo "alias ll='ls -laGFh'" >> /root/.bashrc

VOLUME ["/workspaces/crappasswd"]
WORKDIR /workspaces/crappasswd

# install clang tools

ARG base_tag=bullseye
ARG llvm_version=16
RUN apt-get update --fix-missing && apt-get -y upgrade && apt-get install -y --no-install-recommends \
    gnupg2 \
    gnupg-agent \
    ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN curl --fail --silent --show-error --location https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN echo "deb http://apt.llvm.org/$base_tag/ llvm-toolchain-$base_tag-$llvm_version main" >> /etc/apt/sources.list.d/llvm.list

RUN apt-get update --fix-missing && apt-get -y upgrade && apt-get install -y --no-install-recommends \
    clang-format-${llvm_version} \
    clang-tidy-${llvm_version} \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/bin/clang-format-${llvm_version} /usr/local/bin/clang-format
RUN ln -s /usr/bin/clang-tidy-${llvm_version} /usr/local/bin/clang-tidy

# Dependencies for the project
RUN apt-get update --fix-missing && apt-get -y upgrade && apt-get install -y --no-install-recommends \
    libldap-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
