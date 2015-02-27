#!/bin/bash
bs_user(){
h=`echo -n "$1:$2" | md5sum | awk '{print $1}' | tr '[:lower:]' '[:upper:]'`
echo $1:$h
} 
bs_user $1 $2