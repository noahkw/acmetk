#!/bin/bash

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout client_cert.key -out fullchain.pem -config san.cnf
