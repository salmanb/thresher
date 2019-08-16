#!/bin/bash


IMAGE=""
DOCKER=$(which docker)
OUT="$1"
TAGS="${@:2}"

function print_usage() {
  echo -e "Usage: bash run.sh /output/path tag1 tag2 tag3 ..."
  exit 1
}

if [[ -z ${DOCKER} ]]; then
  echo "Docker is required, but was not found. Please install docker and try again."
  exit 1
fi

if [[ ! -d ${HOME}/.aws ]]; then
  echo "${HOME}/.aws does not exist. Please configure your aws cli and try again."
  exit 1
fi

if [[ -z ${OUT} ]]; then
  echo "Output path is required"
  print_usage
fi

if [[ -z ${TAGS} ]]; then
  echo "Tags are required"
  print_usage
fi


${DOCKER} run -it -v $(realpath ${OUT}):/out -v ${HOME}/.aws:/root/.aws ${IMAGE} /out ${TAGS}
