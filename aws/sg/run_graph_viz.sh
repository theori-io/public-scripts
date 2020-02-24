#!/bin/bash
# check already installed
docker image ls | grep aws-viz
ret=$?
# aws_security_viz -o /ms/sg.json -f /ms/viz.svg --color
if [ $ret -eq 0 ]; then
	docker run -i --rm -t -v $(pwd):/ms --entrypoint /ms/make_graph.sh --name aws-viz aws-viz
	exit
fi

# download repo
cd /tmp
git clone https://github.com/anaynayak/aws-security-viz.git
cd /tmp/aws-security-viz

# build with docker
docker build . -t 'aws-viz'

