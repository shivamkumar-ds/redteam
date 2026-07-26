#!/bin/bash

python sandbox_setup.py

gunicorn app:app --bind 0.0.0.0:$PORT
