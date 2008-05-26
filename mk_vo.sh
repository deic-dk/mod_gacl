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

#
# Configuration
#

# The DocumentRoot of the web server. When recursing upwards looking
# for a .gacl file, this is where we stop. You may want to change this.
DOCUMENT_ROOT="/var/www/html/grid/data"
GACL_FILE=".gacl"
GACL_VO_FILE=".gacl_vo"
DN_LIST_URL_TAG="dn-list-url"

#
# First find the directory containing the .gacl file to check.
#

# The argument supplied to this script must be a path - either of a
# directory or of a file. Here we find the directory (and the file name).

path="$@"

if [ -z $path ]; then
  echo "no path given"
  exit -1
fi

if [ -d $path ]; then
  dir=$path
  file=""
else
  dir=`echo $path | sed -r 's|(.*)/[^/]*|\1|'`
  file=`echo $path | sed -r 's|.*/([^/]+)|\1|'`
fi

# Recurse upwards until a .gacl file is found.

while [ $PWD != DOCUMENT_ROOT -a $PWD != "/" ]; do
  if [ -e $GACL_FILE ]; then
    echo "Found $GACL_FILE file in $PWD"
    break
  fi
  cd ..
done

if [ ! -e $GACL_FILE ]; then
  echo "no $GACL_FILE file found"
  exit -2
fi

#
# Check if the .gacl file contains elements of the form
# <dn-list-url>https://some.url/vo.txt</dn-list-url>.
# If it does, construct list of URLs.
#

# Get the list of URLs
gacl_line=`sed -n '1h;2,$H;${g;s/\n//g;p}' .gacl | sed -r 's/>\s+</></g'`
old_line=""
url_list=$gacl_line
while [ "$url_list" != "$old_line" ]; do
  old_line=$url_list
  url_list=`echo "$old_line" | sed -r "s|(.*)<$DN_LIST_URL_TAG>(.*)</$DN_LIST_URL_TAG>(.*)|\2\\t\1\3|"`
done
url_list=`echo "$url_list" | sed -r 's|(.*http[s]*://\S+)\t[^\t]*|\1|'`

if [ -z "$url_list" -o "$url_list" == "$gacl_line" ]; then
  echo "no $DN_LIST_URL_TAG tag found"
  exit 0
fi

#
# Construct list of entries in the form
# URL1<allow>...</allow><deny>...</deny>URL2<allow>...</allow><deny>...</deny>...
#

gacl_line=`sed -n '1h;2,$H;${g;s/\n//g;p}' .gacl | sed -r 's/>\s+</></g'`
old_line=""
entries_list=`echo "$gacl_line" | sed 's|<entry>|<entry\t>|gi' | sed 's|</entry>|</entry\t>|gi'`
while [ "$entries_list" != "$old_line" ]; do
  old_line=$entries_list
  entries_list=`echo "$old_line" | sed -r "s|(.*)<entry\t>([^\t]*)<$DN_LIST_URL_TAG>([^\t]*)</$DN_LIST_URL_TAG>([^\t]*)</entry\t>(.*)|\3\2\4\1\5|"`
done
entries_list=`echo "$entries_list" | sed -r 's|(.+)<gacl>.*|\1|i'`https://
#echo "$url_list" | tr '\t' ' '
#echo "$entries_list"

#
# Write the .gacl_vo file.
#

echo "Writing file $GACL_VO_FILE"

echo "<gacl>" > $GACL_VO_FILE
for url in $url_list; do
  url1=`echo $url | sed 's|http[s]*://|\t|g'`
  perms=`echo $entries_list | sed 's|http[s]*://|\t|g'`
  perms=`echo "$perms" | sed -r "s|.*$url1([^\t]+)\t.*|\1|"`
  echo URL: "$url"
  echo PERMS: "$perms"
  curl --insecure $url 2>/dev/null | sed 's/\"//g' | while read name; do
cat >> $GACL_VO_FILE <<EOF
  <entry>
    <person>
      <dn>$name</dn>
    </person>
    $perms
  </entry>
EOF
  done
done
echo "</gacl>" >> $GACL_VO_FILE
