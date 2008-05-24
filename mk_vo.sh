#!/bin/bash

#  mk_vo.sh <path>
#
#  Sample script for generating lists of VO members. To be used with
#  the Apache module mod_gacl.
#
#  Copyright 2008 (C) Frederik Orellana, Niels Bohr Institute,
#  University of Copenhagen. All Rights Reserved.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see http://www.gnu.org/licenses/.


# The DocumentRoot of the web server. When recursing upwards looking
# for a .gacl file, this is where we stop. You may want to change this.
DOCUMENT_ROOT="/var/www/html/grid/data"

GACL_FILE=".gacl"
DN_LIST_URL_TAG="dn-list-url"

# First find the directory containing the .gacl file to check.

# The argument supplied to this script must be a path - either of a
# directory or of a file. Here we find the directory (and the file name).

path="$@"

if [ -z $path ]; then
  echo "no path given"
  return -1
fi

if [ -d $path ]; then
  dir=$path
  file=""
else
  dir=`echo $path | sed -r 's|(.*)/[^/]*|\1|'`
  file=`echo $path | sed -r 's|.*/([^/]+)|\1|'`
fi

# Recurse upwards until a .gacl file is found

while [ $PWD != DOCUMENT_ROOT -a $PWD != "/" ]; do
  if [ -e $GACL_FILE ]; then
    echo OK
    break
  fi
  cd ..
done

if [ ! -e $GACL_FILE ]; then
  echo "no $GACL_FILE file found"
  return -2
fi

# Check if the .gacl file contains elements of the form
# <dn-list-url>https://some.url/vo.txt</dn-list-url>.

# Get the list of URLs
gacl_line=`sed -n '1h;2,$H;${g;s/\n//g;p}' .gacl | sed -r 's/>\s+</></g'`
old_line=""
while [ "$gacl_line" != "$old_line" ]; do
  old_line=$gacl_line
  gacl_line=`echo "$old_line" | sed -r 's|(.*)<dn-list-url>(.*)</dn-list-url>(.*)|\2\\t\1\3|'`
done
url_list=`echo "$gacl_line" | sed -r 's|(.*http://\S+)\t[^\t]*|\1|'`

if [ -z "$url_list" ]; then
  echo "no $DN_LIST_URL_TAG tag found"
  return 0
fi

## TODO
# Get the corresponding list of entries
gacl_line=`sed -n '1h;2,$H;${g;s/\n//g;p}' .gacl | sed -r 's/>\s+</></g'`
old_line=""
while [ "$gacl_line" != "$old_line" ]; do
  old_line=$gacl_line
  gacl_line=`echo "$old_line" | sed -r 's|(.*)(<entry>.*)<dn-list-url>.*</dn-list-url>(.*</entry>)(.*)|\2\3\\t\1\4|'`
done
entries_list=`echo "$gacl_line" | sed -r 's|(.+)\t[^\t]*|\1|'`

echo "$url_list" | tr '\t' ' '
echo "$entries_list"

touch $dir/.gacl_vo
