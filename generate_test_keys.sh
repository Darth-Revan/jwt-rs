#!/bin/bash

# MIT License
#
# Copyright (c) 2019 Kevin Kirchner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This helper script generates some test keys for use in jwt-rs unit test.
# Requires openssl.

# POSIX-compliant check for openssl
command -v openssl >/dev/null 2>&1 || {
    echo >&2 "This script requires openssl but it's not installed. Aborting.";
    exit 1;
}

OUTDIR="./testdata"
mkdir -p "$OUTDIR"

echo -ne "Generating RSA key pair..."
openssl genrsa -out "$OUTDIR/rsa_priv.pem" 2048 2>/dev/null
openssl rsa -in "$OUTDIR/rsa_priv.pem" -pubout -outform PEM -out "$OUTDIR/rsa_pub.pem" 2>/dev/null
echo "Done"

echo -ne "Generating second RSA key pair for cross verifications..."
openssl genrsa -out "$OUTDIR/rsa_other_priv.pem" 2048 2>/dev/null
openssl rsa -in "$OUTDIR/rsa_other_priv.pem" -pubout -outform PEM -out "$OUTDIR/rsa_other_pub.pem" 2>/dev/null
echo "Done"

echo -ne "Generating elliptic curve key pair using prime256v1..."
openssl ecparam -name prime256v1 -genkey -noout -out "$OUTDIR/ec_priv.pem" 2>/dev/null
openssl ec -in "$OUTDIR/ec_priv.pem" -pubout -out "$OUTDIR/ec_pub.pem" 2>/dev/null
echo "Done"

echo -ne "Generating seconds elliptic curve key pair using prime256v1..."
openssl ecparam -name prime256v1 -genkey -noout -out "$OUTDIR/ec_other_priv.pem" 2>/dev/null
openssl ec -in "$OUTDIR/ec_other_priv.pem" -pubout -out "$OUTDIR/ec_other_pub.pem" 2>/dev/null
echo "Done"

echo -ne "Generating elliptic curve key pair using secp384r1..."
openssl ecparam -name secp384r1 -genkey -noout -out "$OUTDIR/ec_other_curve_priv.pem" 2>/dev/null
openssl ec -in "$OUTDIR/ec_other_curve_priv.pem" -pubout -out "$OUTDIR/ec_other_curve_pub.pem" 2>/dev/null
echo "Done"

echo -ne "Generating elliptic curve key pair using secp521r1..."
openssl ecparam -name secp521r1 -genkey -noout -out "$OUTDIR/ec_521_priv.pem" 2>/dev/null
openssl ec -in "$OUTDIR/ec_521_priv.pem" -pubout -out "$OUTDIR/ec_521_pub.pem" 2>/dev/null
echo "Done"
