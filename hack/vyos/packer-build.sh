#!/bin/bash
# See https://vyos.tnyzeq.icu and https://github.com/dd010101/vyos-jenkins for more information

which docker &> /dev/null

if (( $? )); then
  echo "Docker must be installed (and in your PATH) to use this build script. Exiting."
  exit 1
fi

which packer &> /dev/null

if (( $? )); then
  echo "Packer must be installed (and in your PATH) to use this build script. Exiting."
  exit 1
fi

if [[ -f vyos-build/build/live-image-amd64.hybrid.iso ]]; then
  echo "VyOS ISO file already exists, so not rebuilding"
  echo "If you want to rebuild the ISO, please delete the 'vyos-build/build' directory"
else
  if [[ ! -f /tmp/apt.gpg.key ]]; then
    # Download the custom APT key
    wget https://vyos.tnyzeq.icu/apt/apt.gpg.key -O /tmp/apt.gpg.key
  fi

  if [[ ! -d vyos-build ]]; then
    # Clone the VyOS build repository
    git clone -b equuleus --single-branch https://github.com/dd010101/vyos-build.git

    # Apply the vwifi patch
    # Generate with: pushd ./vyos-build && git add . && git diff --cached > ../vwifi.patch && popd
    pushd vyos-build
    git apply < ../vwifi.patch
    popd
  fi

  # Build the VyOS ISO
  docker run \
    -v $(pwd)/vyos-build:/vyos \
    -v "/tmp/apt.gpg.key:/opt/apt.gpg.key" \
    -w /vyos \
    --privileged \
    -e GOSU_UID=$(id -u) \
    -e GOSU_GID=$(id -g) \
    --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
    --rm \
    --name="vyos-build" \
    vyos/vyos-build:equuleus \
      /bin/bash -c \
        '/vyos/packages/vwifi/build.sh &&
        sudo --preserve-env ./configure \
          --architecture amd64 \
          --build-by "phenix@localhost" \
          --build-type release \
          --debian-elts-mirror http://deb.freexian.com/extended-lts \
          --version "1.3.x" \
          --vyos-mirror "https://vyos.tnyzeq.icu/apt/equuleus" \
          --custom-apt-key /opt/apt.gpg.key \
          --custom-package "vyos-1x-smoketest" \
          --custom-package "libnl-3-dev" \
          --custom-package "libnl-genl-3-dev" \
          && sudo make iso'
fi

# Build the QEMU image
export ISO_IMAGE=vyos-build/build/live-image-amd64.hybrid.iso
export ISO_MD5SUM="$(md5sum ${ISO_IMAGE} | awk '{print $1}')"

packer build packer.json
