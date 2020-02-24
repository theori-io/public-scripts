#!/bin/sh
echo '[svg]'
aws_security_viz -o /ms/sg.json -f /ms/viz.svg --color
echo '[pdf]'
aws_security_viz -o /ms/sg.json -f /ms/viz.pdf --color
echo '[png]'
aws_security_viz -o /ms/sg.json -f /ms/viz.png --color
