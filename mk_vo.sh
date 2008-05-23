#!/bin/bash

dir=`echo $@ | sed -r 's|(.*)/[^/]*|\1|'`
file=`echo $@ | sed -r 's|.*/([^/]+)|\1|'`

#echo > $dir/.gacl_vo
