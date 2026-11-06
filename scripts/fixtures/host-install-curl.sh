#!/bin/sh
# The host installer test must not run target ELF or make an Internet request.
# Fake-Magisk's runtime phase replaces this with its explicit curl protocol mock.
printf '%s\n' 'curl unavailable in the offline host installer fixture' >&2
exit 127
